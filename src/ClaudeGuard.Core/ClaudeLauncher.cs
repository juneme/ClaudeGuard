using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;

namespace ClaudeGuard;

public sealed record ClaudeLaunchTarget(string Executable, string AppUserModelId = "")
{
    public bool IsPackaged => AppUserModelId.Length != 0;
}

public static class ClaudeLauncher
{
    // Discovery and activation run as the interactive user, after the service has validated
    // the selected executable and consumed its one-shot permit. No service launches Claude.
    public static ClaudeLaunchTarget Resolve(string executable)
    {
        string selected = Path.GetFullPath(executable);
        using var repository = Registry.CurrentUser.OpenSubKey(
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
        if (repository != null)
            foreach (string name in repository.GetSubKeyNames())
            {
                using var package = repository.OpenSubKey(name);
                if (package?.GetValue("PackageRootFolder") is not string root) continue;
                if (!IsWithin(selected, root))
                {
                    // Match the final path when WindowsApps is a junction onto another drive.
                    string? manifestPath = ClaudeLocator.Resolve(Path.Combine(root, "AppxManifest.xml"));
                    if (manifestPath == null) continue;
                    root = Path.GetDirectoryName(manifestPath)!;
                    if (!IsWithin(selected, root)) continue;
                }
                using var reader = XmlReader.Create(Path.Combine(root, "AppxManifest.xml"), new XmlReaderSettings
                { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
                return FromManifest(selected, root, FamilyName(name), XDocument.Load(reader));
            }
        // A missing registration must not silently fall back to the same direct MSIX launch.
        if (selected.Split(Path.DirectorySeparatorChar).Contains("WindowsApps", StringComparer.OrdinalIgnoreCase))
            throw new IOException("无法确认 Claude 的 MSIX 应用注册，请从开始菜单启动一次后重新检测");
        return new(selected);
    }

    internal static ClaudeLaunchTarget FromManifest(string selected, string root, string family, XDocument manifest)
    {
        if (!IsWithin(selected, root)) throw new IOException("Claude 路径不属于所选应用包");
        foreach (var app in manifest.Root?.Elements().Where(e => e.Name.LocalName == "Applications")
                     .Elements().Where(e => e.Name.LocalName == "Application") ?? [])
        {
            string relative = (string?)app.Attribute("Executable") ?? "";
            string id = (string?)app.Attribute("Id") ?? "";
            if (relative.Length == 0 || id.Length == 0 || id.Contains('!') || Path.IsPathRooted(relative)) continue;
            string candidate = Path.GetFullPath(Path.Combine(root, relative));
            if (IsWithin(candidate, root) && candidate.Equals(selected, StringComparison.OrdinalIgnoreCase))
                return new(selected, family + "!" + id);
        }
        throw new IOException("应用包中没有与已检测 Claude.exe 对应的启动入口");
    }

    private static bool IsWithin(string path, string root) => Path.GetFullPath(path).StartsWith(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static string FamilyName(string fullName)
    {
        uint length = 0;
        int error = PackageFamilyNameFromFullName(fullName, ref length, null);
        if (error != 122 || length is 0 or > 512) throw new Win32Exception(error);
        var value = new StringBuilder((int)length);
        error = PackageFamilyNameFromFullName(fullName, ref length, value);
        if (error != 0) throw new Win32Exception(error);
        return value.ToString();
    }

    // Package activation and ordinary shell execution remain separate. A failed activation never retries
    // by directly executing the package binary, and neither path owns or terminates its process.
    internal static int Start(ClaudeLaunchTarget target, Func<string, int> activate, Func<string, int> shell) =>
        target.IsPackaged ? activate(target.AppUserModelId) : shell(target.Executable);

    public static int Start(ClaudeLaunchTarget target) => Start(target, Activate, path =>
    {
        using var process = Process.Start(new ProcessStartInfo(path)
        { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(path)! });
        return process?.Id ?? 0;
    });

    private static int Activate(string appUserModelId)
    {
        Guid clsid = new("45BA127D-10A8-46EA-8AB7-56EA9078943C");
        Guid iid = typeof(IApplicationActivationManager).GUID;
        // Task.Run may arrive on a thread with no COM apartment. Balance only our own
        // successful initialization; an existing STA can also use the activation manager.
        int initialized = CoInitializeEx(IntPtr.Zero, 0);
        if (initialized < 0 && initialized != unchecked((int)0x80010106)) Marshal.ThrowExceptionForHR(initialized);
        try
        {
            // Let Windows broker the package lifetime independently of the guard window.
            Marshal.ThrowExceptionForHR(CoCreateInstance(ref clsid, IntPtr.Zero, 4, ref iid, out var manager));
            try
            {
                // AO_NONE: debug/no-splash activation flags can cause PLM to terminate an app.
                Marshal.ThrowExceptionForHR(manager.ActivateApplication(appUserModelId, "", 0, out uint pid));
                return checked((int)pid);
            }
            finally { Marshal.ReleaseComObject(manager); }
        }
        finally { if (initialized >= 0) CoUninitialize(); }
    }

    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoInitializeEx(IntPtr reserved, uint concurrency);
    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern void CoUninitialize();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int PackageFamilyNameFromFullName(string fullName, ref uint length, StringBuilder? familyName);

    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid,
        [MarshalAs(UnmanagedType.Interface)] out IApplicationActivationManager manager);

    [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint processId);
        [PreserveSig]
        int ActivateForFile([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId, IntPtr items,
            [MarshalAs(UnmanagedType.LPWStr)] string verb, out uint processId);
        [PreserveSig]
        int ActivateForProtocol([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId, IntPtr items, out uint processId);
    }
}
