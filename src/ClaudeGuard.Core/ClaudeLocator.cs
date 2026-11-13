using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ClaudeGuard;

// Resolve the installed Claude client on this machine. Discovery is mechanism-based and
// portable: the per-user package repository, installer registry entries and conventional
// per-user layouts are probed by executable name only — no package identity, family hash
// or versioned path is hardcoded. A remembered path is never trusted: the service
// re-verifies publisher, signature and reparse points in SetAppPath.
public static class ClaudeLocator
{
    private const string ExeName = "Claude.exe";

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);

    public static string Find()
    {
        try
        {
            foreach (string executable in Candidates())
            {
                string? resolved = Resolve(executable);
                if (resolved != null) return resolved;
            }
            return "";
        }
        catch (IOException) { return ""; }
        catch (UnauthorizedAccessException) { return ""; }
        catch (ArgumentException) { return ""; }
    }

    // The package root may be a protected junction to another volume, inaccessible to
    // directory enumeration. Resolve the opened file instead. The service still rejects
    // reparse points in the final path and verifies the executable signature.
    internal static string? Resolve(string executable)
    {
        try
        {
            using var file = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var resolved = new StringBuilder(32768);
            uint written = GetFinalPathNameByHandle(file.SafeFileHandle, resolved, (uint)resolved.Capacity, 0);
            if (written == 0 || written >= resolved.Capacity) return null;
            string finalPath = resolved.ToString();
            return finalPath.StartsWith(@"\\?\") && !finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)
                ? finalPath[4..]
                : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (ArgumentException) { return null; }
    }

    private static List<string> Candidates()
    {
        var found = new List<string>();
        void Add(string? path)
        {
            if (path is not null && Path.IsPathFullyQualified(path) && !path.StartsWith(@"\\", StringComparison.Ordinal) &&
                Path.GetFileName(path).Equals(ExeName, StringComparison.OrdinalIgnoreCase) &&
                !found.Contains(path, StringComparer.OrdinalIgnoreCase)) found.Add(path);
        }
        void Probe(string dir) { Add(Path.Combine(dir, "app", ExeName)); Add(Path.Combine(dir, ExeName)); }
        void EachDir(string root, Action<string> visit)
        {
            try { foreach (string dir in Directory.GetDirectories(root)) visit(dir); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (ArgumentException) { }
        }

        // 1. Per-user package repository: every package root is a candidate, newest
        //    version first. Works for any MSIX identity without hardcoding one.
        var roots = new List<(string Root, Version Version)>();
        try
        {
            using var repository = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (repository != null)
                foreach (string name in repository.GetSubKeyNames())
                {
                    using var package = repository.OpenSubKey(name);
                    if (package?.GetValue("PackageRootFolder") is string root) roots.Add((root, PackageVersion(name)));
                }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        foreach (var (root, _) in roots.OrderByDescending(r => r.Version)) Probe(root);

        // 2. Installer registry: App Paths and Uninstall entries name the executable or
        //    its folder; anything that is not Claude.exe is discarded by Add.
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (string prefix in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\" })
            {
                try
                {
                    using var key = hive.OpenSubKey(prefix + ExeName);
                    Add(ExeFromIcon(key?.GetValue("") as string ?? ""));
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            foreach (string prefix in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
            {
                try
                {
                    using var uninstall = hive.OpenSubKey(prefix);
                    if (uninstall == null) continue;
                    foreach (string name in uninstall.GetSubKeyNames())
                    {
                        using var entry = uninstall.OpenSubKey(name);
                        if (entry == null) continue;
                        if (entry.GetValue("DisplayIcon") is string icon) Add(ExeFromIcon(icon));
                        if (entry.GetValue("DisplayName") is string display && display.Contains("Claude", StringComparison.OrdinalIgnoreCase) &&
                            entry.GetValue("InstallLocation") is string location) Probe(location);
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        // 3. Conventional per-user layouts, one directory level deep, e.g. Squirrel-style
        //    %LOCALAPPDATA%\<vendor> and %LOCALAPPDATA%\Programs\<app> trees.
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (string root in new[]
        {
            local,
            Path.Combine(local, "Programs"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        })
        {
            if (root.Length == 0) continue;
            Probe(root);
            EachDir(root, Probe);
        }
        return found;
    }

    private static string? ExeFromIcon(string icon)
    {
        string value = Environment.ExpandEnvironmentVariables(icon.Trim().Trim('"'));
        int end = value.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return end < 0 ? null : value[..(end + 4)].Trim('"');
    }

    private static Version PackageVersion(string fullName) =>
        Version.TryParse(fullName.Split('_').ElementAtOrDefault(1), out var version) ? version : new Version(0, 0);
}
