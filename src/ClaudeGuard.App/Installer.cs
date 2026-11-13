using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace ClaudeGuard;

internal sealed class ServiceSetupException(int stage, Exception cause) : IOException(ServiceUpgrade.FailureMessage(stage), cause)
{
    public int Stage { get; } = stage;
    public int ExitCode => (Stage << 16) | (InnerException!.HResult & 65535);
}

internal static class Installer
{
    private static void Admin()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) throw new UnauthorizedAccessException();
    }
    private static int Sc(params string[] args)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var p = Process.Start(info)!;
        var stdout = p.StandardOutput.ReadToEndAsync(); var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(20000)) throw new IOException("SCM timeout");
        Task.WaitAll(stdout, stderr);
        return p.ExitCode;
    }
    private static void Require(params string[] args) { if (Sc(args) != 0) throw new IOException("SCM operation failed"); }
    private static void RejectLinks(string path)
    {
        for (var dir = new DirectoryInfo(path); dir != null; dir = dir.Parent)
            if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse path refused");
    }
    private static void CopyTree(string source, string dest)
    {
        RejectLinks(source); RejectLinks(dest); Directory.CreateDirectory(dest);
        foreach (var file in Directory.GetFiles(source))
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse file refused");
            File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), true);
        }
        foreach (var dir in Directory.GetDirectories(source)) CopyTree(dir, Path.Combine(dest, Path.GetFileName(dir)));
    }
    public static void Install(string owner)
    {
        Admin(); _ = new SecurityIdentifier(owner);
        using var profile = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + owner);
        if (profile?.GetValue("ProfileImagePath") is not string profilePath) throw new IOException("Unknown user");
        try
        {
            using var legacy = new LegacyGuardTask();
            LegacyGuardMigration.Remove(legacy, owner, Environment.ExpandEnvironmentVariables(profilePath));
        }
        catch (Exception error) { throw new ServiceSetupException(9, error); }
        string source = Directory.GetParent(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))!.FullName;
        string serviceSource = Path.Combine(source, "service", "ClaudeGuard.Service.exe");
        using var embeddedService = typeof(Installer).Assembly.GetManifestResourceStream("ClaudeGuard.ServicePayload.exe");
        if (embeddedService == null && !File.Exists(serviceSource)) throw new IOException("Service payload missing");
        if (string.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar),
            Path.Combine(Product.InstallPath, "app"), StringComparison.OrdinalIgnoreCase))
        {
            // Installed files may still be in use. Updates must run from a new downloaded EXE.
            if (Sc("query", Product.ServiceName) == 0)
            {
                using var installed = Registry.LocalMachine.OpenSubKey(Product.RegistryPath);
                if (installed?.GetValue("OwnerSid") is not string existingOwner || existingOwner != owner) throw new IOException("Different service owner");
                Native.AllowOwnerToStartService(owner);
                Require("config", Product.ServiceName, "start=", "demand");
                Sc("start", Product.ServiceName); return;
            }
            throw new IOException("Run the downloaded installer outside the installation folder");
        }
        RejectLinks(Product.InstallPath);
        string backup = Product.InstallPath + ".rollback-" + Guid.NewGuid().ToString("N");
        bool existing = Directory.Exists(Product.InstallPath), created = false;
        using var oldConfig = Registry.LocalMachine.OpenSubKey(Product.RegistryPath);
        if (oldConfig?.GetValue("OwnerSid") is string oldOwner && oldOwner != owner) throw new IOException("Different service owner");
        bool serviceExisted = Sc("query", Product.ServiceName) == 0;
        int stage = 10;
        try
        {
            if (serviceExisted)
            {
                uint pid = Native.ServiceProcessId();
                using var running = CaptureProcess(pid);
                Sc("stop", Product.ServiceName);
                ServiceUpgrade.WaitForExitAsync(Native.ServiceActive, () => running == null || running.HasExited,
                    TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            }
            stage = 11;
            if (existing) Directory.Move(Product.InstallPath, backup);
            stage = 12;
            Directory.CreateDirectory(Product.InstallPath);
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(Product.InstallPath).SetAccessControl(acl);
            if (embeddedService != null)
            {
                string appDir = Path.Combine(Product.InstallPath, "app");
                string serviceDir = Path.Combine(Product.InstallPath, "service");
                Directory.CreateDirectory(appDir); Directory.CreateDirectory(serviceDir);
                File.Copy(Environment.ProcessPath!, Path.Combine(appDir, "ClaudeGuard.exe"), false);
                using var output = new FileStream(Path.Combine(serviceDir, "ClaudeGuard.Service.exe"), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                embeddedService.CopyTo(output);
            }
            else
            {
                CopyTree(Path.Combine(source, "app"), Path.Combine(Product.InstallPath, "app"));
                CopyTree(Path.Combine(source, "service"), Path.Combine(Product.InstallPath, "service"));
            }
            using (var key = Registry.LocalMachine.CreateSubKey(Product.RegistryPath)) key.SetValue("OwnerSid", owner);
            stage = 13;
            string exe = Path.Combine(Product.InstallPath, "service", "ClaudeGuard.Service.exe");
            if (!serviceExisted)
            {
                Require("create", Product.ServiceName, "binPath=", "\"" + exe + "\"", "start=", "demand", "obj=", "LocalSystem", "DisplayName=", "ClaudeGuard 连接守护");
                created = true;
            }
            else Require("config", Product.ServiceName, "binPath=", "\"" + exe + "\"", "start=", "demand", "obj=", "LocalSystem");
            stage = 14;
            Native.AllowOwnerToStartService(owner);
            Require("description", Product.ServiceName, "断网等待重连；不结束 Claude，不启动 Clash Verge。");
            Require("failure", Product.ServiceName, "reset=", "86400", "actions=", "restart/2000/restart/5000/restart/15000");
            Require("failureflag", Product.ServiceName, "1");
            stage = 15;
            Require("start", Product.ServiceName);
            var deadline = DateTime.UtcNow.AddSeconds(12);
            while (Native.ServicePid() == 0 && DateTime.UtcNow < deadline) Thread.Sleep(250);
            if (Native.ServicePid() == 0) throw new IOException("Service failed to start");
            stage = 16;
            CreateShortcut();
            DeploymentCleanup.Prune(Product.InstallPath);
        }
        catch (Exception error)
        {
            try
            {
                uint pid = Native.ServiceProcessId();
                using var running = CaptureProcess(pid);
                Sc("stop", Product.ServiceName);
                ServiceUpgrade.WaitForExitAsync(Native.ServiceActive, () => running == null || running.HasExited,
                    TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
                if (created) Sc("delete", Product.ServiceName);
                if (existing && Directory.Exists(backup))
                {
                    string failed = Product.InstallPath + ".failed-" + Guid.NewGuid().ToString("N");
                    if (Directory.Exists(Product.InstallPath)) Directory.Move(Product.InstallPath, failed);
                    Directory.Move(backup, Product.InstallPath);
                    DeploymentCleanup.TryRemoveBackup(Product.InstallPath, failed);
                }
                // A failed rename leaves the original installation in place too.
                if (serviceExisted) Sc("start", Product.ServiceName);
            }
            catch { /* Preserve the original stage; never remove unknown files. */ }
            throw new ServiceSetupException(stage, error);
        }
    }
    private static Process? CaptureProcess(uint pid)
    {
        if (pid == 0) return null;
        try { var process = Process.GetProcessById((int)pid); _ = process.Handle; return process; }
        catch (ArgumentException) { return null; }
    }
    private static void CreateShortcut()
    {
        dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
        dynamic link = shell.CreateShortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "ClaudeGuard.lnk"));
        link.TargetPath = Path.Combine(Product.InstallPath, "app", "ClaudeGuard.exe");
        link.WorkingDirectory = Path.Combine(Product.InstallPath, "app"); link.Save();
    }
    public static void Uninstall()
    {
        Admin(); Sc("stop", Product.ServiceName);
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (Native.ServicePid() != 0 && DateTime.UtcNow < deadline) Thread.Sleep(250);
        if (Native.ServicePid() != 0) throw new IOException("Service still running");
        int result = Sc("delete", Product.ServiceName); if (result != 0 && result != 1060) throw new IOException();
        Firewall.Remove();
        Registry.LocalMachine.DeleteSubKeyTree(Product.RegistryPath, false);
        string shortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "ClaudeGuard.lnk");
        if (File.Exists(shortcut)) File.Delete(shortcut);
        // Running UI binaries are removed by the user after exit; completed upgrades prune generated backups.
    }
}
