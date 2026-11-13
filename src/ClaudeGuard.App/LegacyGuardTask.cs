using System.IO;
using System.Runtime.InteropServices;

namespace ClaudeGuard;

internal sealed class LegacyGuardTask : ILegacyGuardTask, IDisposable
{
    private readonly dynamic scheduler;
    private readonly dynamic folder;
    public LegacyGuardTask()
    {
        scheduler = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        scheduler.Connect();
        folder = scheduler.GetFolder(@"\");
    }
    private dynamic? Find()
    {
        try { return folder.GetTask(LegacyGuardMigration.TaskName); }
        catch (Exception ex) when (ex.HResult == unchecked((int)0x80070002)) { return null; }
    }
    public string? ReadXml()
    {
        dynamic? task = Find();
        try { return task == null ? null : (string)task.Xml; }
        finally { if (task != null) Marshal.ReleaseComObject(task); }
    }
    public void Disable()
    {
        dynamic? task = Find();
        try { if (task != null) { task.Enabled = false; if ((bool)task.Enabled) throw new IOException("旧守护任务仍启用"); } }
        finally { if (task != null) Marshal.ReleaseComObject(task); }
    }
    public void Stop()
    {
        dynamic? task = Find();
        try
        {
            if (task == null) return;
            task.Stop(0);
            var until = DateTime.UtcNow.AddSeconds(10);
            while ((int)task.State == 4 && DateTime.UtcNow < until) Thread.Sleep(100);
            if ((int)task.State == 4) throw new IOException("旧守护任务仍在运行");
        }
        finally { if (task != null) Marshal.ReleaseComObject(task); }
    }
    public void Delete() => folder.DeleteTask(LegacyGuardMigration.TaskName, 0);
    public void Dispose()
    {
        Marshal.ReleaseComObject(folder);
        Marshal.ReleaseComObject(scheduler);
    }
}
