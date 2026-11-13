using System.Runtime.InteropServices;
using System.Xml;
using System.Xml.Linq;

namespace ClaudeGuard;

public interface ILegacyGuardTask
{
    string? ReadXml();
    void Disable();
    void Stop();
    void Delete();
}

public static class LegacyGuardMigration
{
    public const string TaskName = "ClaudeBodyguard";

    public static void Remove(ILegacyGuardTask task, string ownerSid, string profilePath)
    {
        string? xml = task.ReadXml();
        if (xml == null) return;
        if (!Matches(xml, ownerSid, profilePath))
            throw new IOException("旧守护任务的用户或启动命令不匹配，请检查 ClaudeBodyguard 任务");
        // Disable first: restart-on-failure and logon triggers must not resurrect the killer.
        task.Disable();
        task.Stop();
        task.Delete();
        if (task.ReadXml() != null) throw new IOException("旧守护任务未移除，暂时不能完成升级");
    }

    internal static bool Matches(string xml, string ownerSid, string profilePath)
    {
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
            var doc = XDocument.Load(reader);
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var principals = doc.Root?.Element(ns + "Principals")?.Elements(ns + "Principal").ToArray() ?? [];
            if (principals.Length != 1 || (string?)principals[0].Element(ns + "UserId") != ownerSid) return false;
            var actions = doc.Root?.Element(ns + "Actions")?.Elements().ToArray() ?? [];
            if (actions.Length != 1 || actions[0].Name != ns + "Exec") return false;
            string command = (string?)actions[0].Element(ns + "Command") ?? "";
            string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (!command.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
                !command.Equals(Path.Combine(system, @"WindowsPowerShell\v1.0\powershell.exe"), StringComparison.OrdinalIgnoreCase)) return false;
            string arguments = (string?)actions[0].Element(ns + "Arguments") ?? "";
            var args = SplitArguments(arguments);
            int index = 0;
            while (index < args.Length)
            {
                string flag = args[index++];
                if (flag.Equals("-NoProfile", StringComparison.OrdinalIgnoreCase) || flag.Equals("-NonInteractive", StringComparison.OrdinalIgnoreCase)) continue;
                if (index >= args.Length) return false;
                string value = args[index++];
                if (flag.Equals("-WindowStyle", StringComparison.OrdinalIgnoreCase) && value.Equals("Hidden", StringComparison.OrdinalIgnoreCase)) continue;
                if (flag.Equals("-ExecutionPolicy", StringComparison.OrdinalIgnoreCase) && value.Equals("Bypass", StringComparison.OrdinalIgnoreCase)) continue;
                return flag.Equals("-File", StringComparison.OrdinalIgnoreCase) && index == args.Length &&
                    Path.IsPathFullyQualified(value) && Path.GetFullPath(value).Equals(
                        Path.Combine(Path.GetFullPath(profilePath), ".claude-switcher", "claude-bodyguard.ps1"), StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        catch (XmlException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static string[] SplitArguments(string arguments)
    {
        IntPtr argv = CommandLineToArgvW("powershell.exe " + arguments, out int count);
        if (argv == IntPtr.Zero) throw new IOException("无法解析旧守护命令");
        try
        {
            var args = new string[count - 1];
            for (int i = 1; i < count; i++) args[i - 1] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size))!;
            return args;
        }
        finally { LocalFree(argv); }
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);
}
