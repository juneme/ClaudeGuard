using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

namespace ClaudeGuard;

internal sealed class GuardService : ServiceBase
{
    private readonly CancellationTokenSource lifetime = new();
    private Task? server;
    private Task? monitor;
    private Coordinator? coordinator;
    private WindowsProbe? probe;
    private volatile bool stopping;
    public GuardService() { ServiceName = Product.ServiceName; CanStop = true; AutoLog = false; }
    protected override void OnStart(string[] args)
    {
        using var config = Registry.LocalMachine.OpenSubKey(Product.RegistryPath);
        string owner = config?.GetValue("OwnerSid") as string ?? throw new InvalidOperationException("Service not configured");
        _ = new SecurityIdentifier(owner);
        probe = new WindowsProbe(owner);
        // Persist only a validated executable path, never approvals, addresses or credentials.
        if (config?.GetValue("AppPath") is string savedPath && File.Exists(savedPath))
        { probe.SetAppPath(savedPath); probe.Quarantine(); }
        coordinator = new Coordinator(probe);
        server = ServeAsync(owner, lifetime.Token);
        monitor = MonitorAsync(lifetime.Token);
        _ = WatchAsync();
    }
    private async Task WatchAsync()
    {
        await Task.WhenAny(server!, monitor!);
        if (!lifetime.IsCancellationRequested && !stopping)
        {
            try { coordinator?.Shutdown(); }
            finally
            {
                // Recover only this service. Even an isolation fault must not bypass SCM
                // recovery or cause any attempt to terminate the protected Claude process.
                Environment.Exit(1);
            }
        }
    }
    private async Task MonitorAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        while (await timer.WaitForNextTickAsync(ct)) await coordinator!.TickAsync(ct);
    }
    private async Task ServeAsync(string owner, CancellationToken ct)
    {
        var security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(owner), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        // Keep the first instance open for service lifetime to prevent pipe-name squatting.
        using var pipe = NamedPipeServerStreamAcl.Create(Product.PipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
        while (!ct.IsCancellationRequested)
        {
            await pipe.WaitForConnectionAsync(ct);
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromSeconds(50));
            try
            {
                if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid)) continue;
                using var client = Process.GetProcessById((int)pid);
                if (Native.Owner(client) != owner || client.SessionId == 0) continue;
                var request = await PipeWire.ReadAsync<Request>(pipe, budget.Token);
                if (request.Secret.Length > 4096) continue;
                Response response;
                bool shutdown = false;
                switch (request.Command)
                {
                    case "status": response = coordinator!.Status; break;
                    case "shutdown":
                        // Stopping must survive an isolation fault: the grant is already revoked,
                        // and refusing to stop only traps the user with a guard that cannot exit.
                        string stopNote = "";
                        try { coordinator!.Shutdown(); }
                        catch (CheckFailed e) { stopNote = "；" + e.Message; }
                        catch (Exception) { stopNote = "；连接隔离状态未能确认"; }
                        stopping = true; shutdown = true;
                        response = new("stopping", "正在停止守护服务" + stopNote, []); break;
                    case "permit": response = await coordinator!.PermitAsync(request.Force, budget.Token); break;
                    case "check": case "repair":
                        response = await coordinator!.CheckAsync(request.Country, request.Command == "repair", budget.Token, () =>
                        {
                            probe!.Secret = request.Secret;
                            probe.SetAppPath(request.AppPath);
                            probe.Quarantine();
                            using var key = Registry.LocalMachine.OpenSubKey(Product.RegistryPath, true);
                            key!.SetValue("AppPath", probe.AppPath);
                        });
                        using (var key = Registry.LocalMachine.OpenSubKey(Product.RegistryPath, true)) key!.SetValue("Monitoring", coordinator.Monitoring ? 1 : 0);
                        break;
                    default: response = new("blocked", "未知请求", []); break;
                }
                try { await PipeWire.WriteAsync(pipe, response with { Protocol = GuardLifecycle.RequiredProtocol }, budget.Token); }
                finally { if (shutdown) _ = Task.Run(Stop); }
                if (shutdown) return;
            }
            catch (CheckFailed e)
            { try { await PipeWire.WriteAsync(pipe, new Response("blocked", e.Message, [new(e.Title, "fail", e.Message)]), budget.Token); } catch { } }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch { /* No raw exception, endpoint, token or user path is written to logs. */ }
            finally { if (pipe.IsConnected) pipe.Disconnect(); }
        }
    }
    protected override void OnStop()
    {
        lifetime.Cancel();
        try { Task.WhenAll(server ?? Task.CompletedTask, monitor ?? Task.CompletedTask).Wait(TimeSpan.FromSeconds(8)); } catch { }
        try { coordinator?.Shutdown(); } catch { }
        probe?.Dispose();
    }
    public static void Main() => Run(new GuardService());
}
