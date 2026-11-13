namespace ClaudeGuard;

// Remove only the two single-file binaries produced by this installer. Unknown files and
// links are preserved; they must never turn a backup cleanup into a recursive deletion.
public static class DeploymentCleanup
{
    public static void Prune(string installation)
    {
        try
        {
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(installation));
            string parent = Path.GetDirectoryName(full)!;
            foreach (string candidate in Directory.GetDirectories(parent, Path.GetFileName(full) + ".*"))
                TryRemoveBackup(full, candidate);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    public static bool TryRemoveBackup(string installation, string candidate)
    {
        try
        {
            string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(installation));
            string backup = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
            if (!string.Equals(Path.GetDirectoryName(full), Path.GetDirectoryName(backup), StringComparison.OrdinalIgnoreCase)) return false;
            string suffix = backup.StartsWith(full + ".", StringComparison.OrdinalIgnoreCase) ? backup[full.Length..] : "";
            string id = suffix.StartsWith(".rollback-", StringComparison.Ordinal) ? suffix[10..] :
                suffix.StartsWith(".failed-", StringComparison.Ordinal) ? suffix[8..] : "";
            if (!Guid.TryParseExact(id, "N", out _)) return false;
            for (var dir = new DirectoryInfo(backup); dir != null; dir = dir.Parent)
                if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) return false;
            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { Path.Combine("app", "ClaudeGuard.exe"), Path.Combine("service", "ClaudeGuard.Service.exe") };
            var files = new List<string>();
            var directories = Directory.GetDirectories(backup);
            foreach (string directory in directories)
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0 ||
                    Path.GetFileName(directory) is not ("app" or "service") || Directory.GetDirectories(directory).Length != 0) return false;
                files.AddRange(Directory.GetFiles(directory));
            }
            if (Directory.GetFiles(backup).Length != 0) return false;
            foreach (string file in files)
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0 || !allowed.Contains(Path.GetRelativePath(backup, file))) return false;
            foreach (string file in files) File.Delete(file);
            foreach (string directory in directories) Directory.Delete(directory);
            Directory.Delete(backup);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}
