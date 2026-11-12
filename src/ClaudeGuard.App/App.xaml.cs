using System.Windows;
using System.Security.Principal;

namespace ClaudeGuard;

public partial class App : System.Windows.Application
{
    private Mutex? instance;
    private EventWaitHandle? showEvent;
    private CancellationTokenSource? eventLifetime;
    private bool ownsInstance;
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Length == 2 && e.Args[0] == "--prepare-service")
        {
            // Installer blocks on SCM waits. Running it on the dispatcher thread would deadlock on
            // its own async continuations, which is exactly how the upgrade used to hang forever.
            int exit = 0;
            try { Task.Run(() => Installer.Install(e.Args[1])).GetAwaiter().GetResult(); }
            catch (ServiceSetupException error) { exit = error.ExitCode; }
            catch { exit = 1; }
            Shutdown(exit);
            return;
        }
        if (e.Args.Length == 2 && e.Args[0] == "--install-service")
        {
            try { Task.Run(() => Installer.Install(e.Args[1])).GetAwaiter().GetResult(); MessageBox.Show("守护服务已安装。请重新打开 ClaudeGuard。", "ClaudeGuard"); Shutdown(); }
            catch { MessageBox.Show("安装未完成，已尝试恢复旧文件。请检查管理员权限及安装包完整性。", "ClaudeGuard"); Shutdown(1); }
            return;
        }
        if (e.Args.Length == 1 && e.Args[0] == "--uninstall-service")
        {
            try { Installer.Uninstall(); MessageBox.Show("服务与专用防火墙规则已移除。", "ClaudeGuard"); Shutdown(); }
            catch { MessageBox.Show("移除失败，请确认管理员权限。", "ClaudeGuard"); Shutdown(1); }
            return;
        }
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\ClaudeGuard.Show." + sid);
        instance = new Mutex(true, @"Local\ClaudeGuard.Window." + sid, out ownsInstance);
        if (!ownsInstance) { showEvent.Set(); Shutdown(); return; }
        var window = new MainWindow();
        MainWindow = window; window.Show();
        if (showEvent != null)
        {
            eventLifetime = new CancellationTokenSource();
            var signal = showEvent; var stop = eventLifetime.Token.WaitHandle;
            _ = Task.Run(() =>
            {
                while (WaitHandle.WaitAny([signal, stop]) == 0)
                    Dispatcher.BeginInvoke(window.ShowWindow);
            });
        }
    }
    protected override void OnExit(ExitEventArgs e)
    {
        eventLifetime?.Cancel();
        if (ownsInstance) instance?.ReleaseMutex();
        instance?.Dispose();
        // The background waiter is allowed to observe cancellation before handles are disposed.
        base.OnExit(e);
    }
}
