using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ClaudeGuard;

// Resolve the installed package for the current user; never trust a remembered versioned path.
public static class ClaudeLocator
{
    private const string PackageFamily = "Claude_pzs8sxrjxfjjc";
    private const int InsufficientBuffer = 122;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackagesByPackageFamily(string family, ref uint count, IntPtr names, ref uint length, IntPtr buffer);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackagePathByFullName(string fullName, ref uint length, StringBuilder? path);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);

    public static string Find()
    {
        try
        {
            foreach (string package in InstalledPackages().OrderByDescending(PackageVersion))
            {
                uint length = 0;
                if (GetPackagePathByFullName(package, ref length, null) != InsufficientBuffer || length is 0 or > 32768) continue;
                var path = new StringBuilder((int)length);
                if (GetPackagePathByFullName(package, ref length, path) != 0) continue;
                string executable = Path.Combine(path.ToString(), "app", "Claude.exe");
                // The package root may be a protected junction to another volume, inaccessible
                // to directory enumeration. Resolve the opened file instead. The service still
                // rejects reparse points in the final path and verifies the executable signature.
                using var file = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var resolved = new StringBuilder(32768);
                uint written = GetFinalPathNameByHandle(file.SafeFileHandle, resolved, (uint)resolved.Capacity, 0);
                if (written == 0 || written >= resolved.Capacity) continue;
                string finalPath = resolved.ToString();
                if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal) && !finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    return finalPath[4..];
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new[] { Path.Combine(local, "AnthropicClaude", "Claude.exe"), Path.Combine(local, "Programs", "Claude", "Claude.exe") }
            .FirstOrDefault(File.Exists) ?? "";
    }

    private static Version PackageVersion(string fullName) =>
        Version.TryParse(fullName.Split('_').ElementAtOrDefault(1), out var version) ? version : new Version(0, 0);

    private static List<string> InstalledPackages()
    {
        uint count = 0, length = 0;
        if (GetPackagesByPackageFamily(PackageFamily, ref count, IntPtr.Zero, ref length, IntPtr.Zero) != InsufficientBuffer ||
            count is 0 or > 128 || length is 0 or > 32768) return [];
        IntPtr names = Marshal.AllocHGlobal(checked((int)count * IntPtr.Size));
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)length * sizeof(char)));
        try
        {
            if (GetPackagesByPackageFamily(PackageFamily, ref count, names, ref length, buffer) != 0) return [];
            var result = new List<string>();
            for (int i = 0; i < count; i++)
                if (Marshal.PtrToStringUni(Marshal.ReadIntPtr(names, i * IntPtr.Size)) is { Length: > 0 } name) result.Add(name);
            return result;
        }
        finally { Marshal.FreeHGlobal(buffer); Marshal.FreeHGlobal(names); }
    }
}
