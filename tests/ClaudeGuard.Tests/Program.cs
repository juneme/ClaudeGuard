using ClaudeGuard;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

int passed = 0, failures = 0;
async Task Test(string name, Func<Task> action)
{
    try { await action(); Console.WriteLine("PASS " + name); passed++; }
    catch (Exception error) { Console.WriteLine("FAIL " + name + ": " + error.GetType().Name + " " + error.Message); failures++; }
}
void Assert(bool value, string message = "Assertion failed") { if (!value) throw new Exception(message); }
FwFacts Facts(bool ruleFound = true, bool enabled = true, FwDirection direction = FwDirection.Outbound,
    FwAction action = FwAction.Block, FwProtocol protocol = FwProtocol.Any, FwProfile profiles = FwProfile.All,
    string app = @"C:\Program Files\Claude\Claude.exe", string application = @"C:\Program Files\Claude\Claude.exe",
    string[]? interfaces = null, string[]? expected = null, bool domain = true, bool isPrivate = true, bool isPublic = true) =>
    new(domain, isPrivate, isPublic, ruleFound, enabled, direction, action, protocol, profiles, app, application,
        interfaces ?? ["Ethernet"], expected ?? ["Ethernet"]);
await Test("proxy failure never probes country or mutates environment", async () =>
{
    var probe = new FakeProbe { ProxyFails = true }; var c = new Coordinator(probe);
    var r = await c.CheckAsync("US", true, default);
    Assert(!r.Ready && probe.CountryCalls == 0 && probe.Repairs == 0 && probe.EnvironmentCalls == 0);
});
await Test("wrong exit country cannot repair or launch", async () =>
{
    var probe = new FakeProbe { Country = "JP" }; var c = new Coordinator(probe);
    Assert(!(await c.CheckAsync("US", true, default)).Ready && probe.Repairs == 0);
    Assert(!(await c.PermitAsync(false, default)).Ready);
});
await Test("launch reuses audit and consumes a single grant", async () =>
{
    var p = new FakeProbe(); var c = new Coordinator(p);
    Assert((await c.CheckAsync("US", false, default)).Ready);
    var grant = await c.PermitAsync(false, default);
    Assert(grant.Ready && grant.Ticket.Length > 0 && p.CountryCalls == 1 && p.EnvironmentCalls == 1);
    Assert(!(await c.PermitAsync(false, default)).Ready);
});
await Test("TUN loss disconnects without terminating and reconnects automatically", async () =>
{
    var time = new FakeTime(); var p = new FakeProbe(); var c = new Coordinator(p, time);
    await c.CheckAsync("US", false, default); await c.PermitAsync(false, default);
    p.Fast = false; time.Advance(2); await c.TickAsync(default);
    Assert(c.Status.Phase == "reconnecting" && !c.Status.Ready && p.Quarantined);
    p.Fast = true; time.Advance(6); await c.TickAsync(default);
    Assert(c.Status.Ready && !p.Quarantined && c.Status.LaunchUsed);
});
await Test("wrong country remains disconnected until original country returns", async () =>
{
    var time = new FakeTime(); var p = new FakeProbe(); var c = new Coordinator(p, time);
    await c.CheckAsync("US", false, default); p.Country = "JP"; time.Advance(26); await c.TickAsync(default);
    Assert(!c.Status.Ready && p.Quarantined);
    time.Advance(6); await c.TickAsync(default); Assert(!c.Status.Ready);
    p.Country = "US"; time.Advance(6); await c.TickAsync(default); Assert(c.Status.Ready && !p.Quarantined);
});
await Test("unreachable country never counts as a pass", async () =>
{
    var time = new FakeTime(); var p = new FakeProbe(); var c = new Coordinator(p, time);
    await c.CheckAsync("US", false, default); p.CountryFails = true; time.Advance(26); await c.TickAsync(default);
    Assert(!c.Status.Ready && p.Quarantined);
});
await Test("expired grant blocks launch without network calls", async () =>
{
    var time = new FakeTime(); var p = new FakeProbe(); var c = new Coordinator(p, time);
    await c.CheckAsync("US", false, default); time.Advance(46);
    Assert(!(await c.PermitAsync(false, default)).Ready && p.CountryCalls == 1 && p.Quarantined);
});
await Test("shutdown preserves process and quarantines; restart has no grant", async () =>
{
    var p = new FakeProbe(); var c = new Coordinator(p); await c.CheckAsync("US", false, default);
    c.Shutdown(); Assert(p.Quarantined && !(await new Coordinator(p).PermitAsync(false, default)).Ready);
});
await Test("repair order follows proxy and country, then environment", async () =>
{
    var p = new FakeProbe(); var c = new Coordinator(p); await c.CheckAsync("US", true, default);
    Assert(string.Join(",", p.Events) == "quarantine,proxy,country,repair,environment,resume");
});
await Test("failed repair leaves quarantine active", async () =>
{
    var p = new FakeProbe { RepairFails = true }; var c = new Coordinator(p);
    var result = await c.CheckAsync("US", true, default);
    Assert(!result.Ready && p.Quarantined);
    Assert(result.Message.Contains("连接保护") && result.Checks.Any(x => x.Title == "Clash Verge" && x.State == "ok") &&
        result.Checks.Any(x => x.Title == "出口地区" && x.State == "ok") && result.Checks.Any(x => x.Title == "连接保护" && x.State == "fail"));
});
await Test("a failed protection check is displayed once with its useful detail", async () =>
{
    var p = new FakeProbe { EnvironmentFails = true }; var c = new Coordinator(p);
    var result = await c.CheckAsync("US", false, default);
    Assert(!result.Ready && result.Checks.Count(x => x.Title == "连接保护" && x.State == "fail") == 1);
    Assert(result.Message == "请修复连接保护");
});
await Test("IPC rejects oversized messages", async () =>
{
    using var stream = new MemoryStream(BitConverter.GetBytes(65536));
    try { await PipeWire.ReadAsync<Request>(stream, default); throw new Exception("Accepted oversized request"); } catch (IOException) { }
});
await Test("IPC request roundtrip", async () =>
{
    using var stream = new MemoryStream(); var request = new Request("status");
    await PipeWire.WriteAsync(stream, request, default); stream.Position = 0;
    Assert(await PipeWire.ReadAsync<Request>(stream, default) == request);
});
await Test("unavailable IPC connection times out independently of an audit", async () =>
{
    using var pipe = new NamedPipeClientStream(".", "ClaudeGuard-test-" + Guid.NewGuid().ToString("N"), PipeDirection.InOut, PipeOptions.Asynchronous);
    var timer = Stopwatch.StartNew();
    try { await PipeClient.ConnectAsync(pipe, default, TimeSpan.FromMilliseconds(250)); throw new Exception("Missing pipe connected"); }
    catch (ServiceUnavailableException) { }
    Assert(timer.Elapsed < TimeSpan.FromSeconds(3), "Missing pipe took too long");
});
await Test("country fallback starts concurrently but primary takes precedence", async () =>
{
    var fallbackStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    using var http = new HttpClient(new FakeHttp(async (request, ct) =>
    {
        if (request.RequestUri!.Host == "1.1.1.1") { fallbackStarted.SetResult(); return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("loc=JP\n") }; }
        await fallbackStarted.Task.WaitAsync(ct);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("loc=US\n") };
    }));
    Assert(await CountryLookup.QueryAsync(http, default) == "US");
});
await Test("country fallback is used only when primary fails", async () =>
{
    using var http = new HttpClient(new FakeHttp((request, _) => Task.FromResult(request.RequestUri!.Host == "1.1.1.1"
        ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("loc=TW\n") }
        : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))));
    Assert(await CountryLookup.QueryAsync(http, default) == "TW");
});
await Test("invalid country responses fail closed", async () =>
{
    using var http = new HttpClient(new FakeHttp((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("loc=??\n") })));
    try { await CountryLookup.QueryAsync(http, default); throw new Exception("Invalid country passed"); } catch (CheckFailed) { }
});
await Test("service owner receives only start and query permissions", () =>
{
    var descriptor = new RawSecurityDescriptor("D:(A;;GA;;;SY)(A;;GA;;;BA)");
    const string owner = "S-1-5-21-100-200-300-1001";
    int original = descriptor.DiscretionaryAcl!.Count;
    Assert(Native.AddOwnerStartAccess(descriptor, owner));
    var added = descriptor.DiscretionaryAcl.Cast<GenericAce>().OfType<CommonAce>().Single(ace => ace.SecurityIdentifier == new SecurityIdentifier(owner));
    Assert(added.AccessMask == 0x14 && added.AceQualifier == AceQualifier.AccessAllowed && descriptor.DiscretionaryAcl.Count == original + 1);
    Assert(!Native.AddOwnerStartAccess(descriptor, owner) && descriptor.DiscretionaryAcl.Count == original + 1);
    return Task.CompletedTask;
});
await Test("firewall targets every IP-capable adapter except tunnel and loopback", () =>
{
    FirewallInterface[] adapters = [new("tun", "Tunnel", false, true, true), new("eth", "Ethernet", false, true, true),
        new("wifi", "Wi-Fi", false, true, false), new("filter", "WFP filter", false, false, false), new("loop", "Loopback", true, true, true)];
    Assert(FirewallInterfaces.Select(adapters, "tun").SequenceEqual(new[] { "Ethernet", "Wi-Fi" }));
    return Task.CompletedTask;
});
await Test("firewall COM accepts the interface list on a detached rule", () =>
{
    var candidates = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
        (n.Supports(NetworkInterfaceComponent.IPv4) || n.Supports(NetworkInterfaceComponent.IPv6))).Select(n => n.Name).ToArray();
    bool tested = false;
    foreach (string name in candidates)
    {
        var rule = new FwRule { Name = "ClaudeGuard isolated test object" };
        try
        {
            rule.Interfaces = [name];
            Assert(rule.Interfaces.SequenceEqual(new[] { name }));
            tested = true; break;
        }
        catch (COMException ex) when (ex.HResult == unchecked((int)0x80070490)) { }
    }
    Assert(tested, "No firewall-compatible local adapter was available for the detached COM test");
    return Task.CompletedTask;
});
await Test("protection passes only when the rule covers every physical adapter", () =>
{
    Assert(Firewall.Evaluate(Facts()).Ok);
    return Task.CompletedTask;
});
await Test("missing rule asks for repair instead of a generic failure", () =>
{
    var check = Firewall.Evaluate(Facts(ruleFound: false));
    Assert(check.State == FwRuleState.Missing && check.Detail.Contains("尚未建立"));
    return Task.CompletedTask;
});
await Test("a stale rule names the exact mismatching property", () =>
{
    Assert(Firewall.Evaluate(Facts(action: FwAction.Allow)).Detail.Contains("动作"));
    Assert(Firewall.Evaluate(Facts(protocol: (FwProtocol)6)).Detail.Contains("协议"));
    Assert(Firewall.Evaluate(Facts(interfaces: ["Ethernet", "Wi-Fi"])).Detail.Contains("网卡"));
    Assert(Firewall.Evaluate(Facts(application: @"D:\other\Claude.exe")).Detail.Contains("程序"));
    return Task.CompletedTask;
});
await Test("a disabled firewall profile is reported as a profile problem", () =>
{
    var check = Firewall.Evaluate(Facts(isPublic: false));
    Assert(check.State == FwRuleState.Mismatch && check.Detail.Contains("配置文件"));
    return Task.CompletedTask;
});
await Test("a detached rule round-trips the named firewall values", () =>
{
    var rule = new FwRule
    {
        Direction = FwDirection.Outbound, Action = FwAction.Block, Protocol = FwProtocol.Any,
        Profiles = FwProfile.All, Enabled = true
    };
    Assert(rule.Direction == FwDirection.Outbound && rule.Action == FwAction.Block);
    Assert(rule.Protocol == FwProtocol.Any && rule.Profiles == FwProfile.All && rule.Enabled);
    return Task.CompletedTask;
});
await Test("opening and exiting use the existing guard without setup", async () =>
{
    var guard = new FakeGuardRuntime { Running = true, Active = true };
    guard.Statuses.Enqueue(new Response("idle", "", [], Protocol: GuardLifecycle.RequiredProtocol));
    await GuardLifecycle.EnsureAsync(guard, default);
    await GuardLifecycle.StopAsync(guard, default);
    Assert(string.Join(",", guard.Events) == "status,stop" && !guard.Active);
});
await Test("opening prepares a missing guard automatically", async () =>
{
    var guard = new FakeGuardRuntime();
    guard.Statuses.Enqueue(new Response("idle", "", [], Protocol: GuardLifecycle.RequiredProtocol));
    await GuardLifecycle.EnsureAsync(guard, default);
    Assert(string.Join(",", guard.Events) == "start,prepare,status");
});
await Test("opening upgrades an incompatible guard before use", async () =>
{
    var guard = new FakeGuardRuntime { Running = true, Active = true };
    guard.Statuses.Enqueue(new Response("idle", "", [], Protocol: GuardLifecycle.RequiredProtocol - 1));
    guard.Statuses.Enqueue(new Response("idle", "", [], Protocol: GuardLifecycle.RequiredProtocol));
    await GuardLifecycle.EnsureAsync(guard, default);
    Assert(string.Join(",", guard.Events) == "status,prepare,status");
});
await Test("guard exit does not report success when shutdown is refused", async () =>
{
    var guard = new FakeGuardRuntime { Running = true, Active = true, RefuseStop = true };
    try { await GuardLifecycle.StopAsync(guard, default); throw new Exception("Refused stop passed"); }
    catch (IOException) { }
    Assert(guard.Active);
});
await Test("upgrade waits for process exit after SCM reports stopped", async () =>
{
    bool exited = false;
    var waiting = ServiceUpgrade.WaitForExitAsync(() => false, () => exited, TimeSpan.FromSeconds(2));
    Assert(!waiting.IsCompleted);
    await Task.Delay(150);
    Assert(!waiting.IsCompleted);
    exited = true;
    await waiting;
});
await Test("upgrade refuses replacement when shutdown does not complete", async () =>
{
    try { await ServiceUpgrade.WaitForExitAsync(() => false, () => false, TimeSpan.FromMilliseconds(150)); throw new Exception("Live process accepted"); }
    catch (IOException) { }
});
await Test("upgrade wait completes while the installer dispatcher is blocked", () =>
{
    var original = SynchronizationContext.Current;
    try
    {
        SynchronizationContext.SetSynchronizationContext(new BlockedDispatcher());
        var elapsed = Stopwatch.StartNew();
        var waiting = ServiceUpgrade.WaitForExitAsync(() => false,
            () => elapsed.Elapsed >= TimeSpan.FromMilliseconds(50), TimeSpan.FromSeconds(1));
        Assert(waiting.Wait(TimeSpan.FromSeconds(2)), "Upgrade wait deadlocked on the installer dispatcher");
    }
    finally { SynchronizationContext.SetSynchronizationContext(original); }
    return Task.CompletedTask;
});
await Test("setup diagnostics preserve the stage and Windows error", () =>
{
    string message = ServiceUpgrade.FailureMessage((11 << 16) | 32);
    Assert(message.Contains("备份") && message.Contains("32") && message.Contains("11"));
    return Task.CompletedTask;
});
await Test("real firewall policy can be opened read-only", () =>
{
    var policy = FwPolicy.Open();
    _ = policy.FirewallEnabled(FwProfile.Public);
    return Task.CompletedTask;
});
await Test("unrestricted detached firewall rule has no explicit interfaces", () =>
{
    var rule = new FwRule();
    Assert(rule.Interfaces.Length == 0);
    return Task.CompletedTask;
});
await Test("quarantine failure revokes a previous permit and returns a useful failure", async () =>
{
    var p = new FakeProbe(); var c = new Coordinator(p);
    Assert((await c.CheckAsync("US", false, default)).Ready);
    p.QuarantineFails = true;
    var result = await c.CheckAsync("US", false, default);
    Assert(!result.Ready && !c.Status.Ready && !c.Monitoring);
    Assert(result.Checks.Any(item => item.State == "fail" && item.Title == "连接隔离"));
    Assert(!(await c.PermitAsync(false, default)).Ready);
});
await Test("unexpected quarantine error is reported without escaping the audit", async () =>
{
    var p = new FakeProbe { QuarantineUnexpectedFailure = true }; var c = new Coordinator(p);
    var result = await c.CheckAsync("US", true, default);
    Assert(!result.Ready && !c.Status.Ready && p.CountryCalls == 0 && p.Repairs == 0);
    Assert(result.Checks.Any(item => item.Title == "连接隔离" && item.State == "fail"));
});
await Test("quarantine failure while suspending revokes the permit", async () =>
{
    var p = new FakeProbe(); var c = new Coordinator(p);
    await c.CheckAsync("US", false, default);
    p.Fast = false; p.QuarantineFails = true;
    Assert(!(await c.PermitAsync(false, default)).Ready && !c.Status.Ready);
});
await Test("loopback-only kernel listeners remain discoverable", () =>
{
    var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    try { Assert(Native.LoopbackPorts(Environment.ProcessId).Contains(((IPEndPoint)listener.LocalEndpoint).Port)); }
    finally { listener.Stop(); }
    return Task.CompletedTask;
});
await Test("kernel listeners bound to wildcard are discovered via loopback", () =>
{
    var listener = new System.Net.Sockets.TcpListener(IPAddress.Any, 0);
    listener.Start();
    try
    {
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Assert(Native.LoopbackPorts(Environment.ProcessId).Contains(port));
    }
    finally { listener.Stop(); }
    return Task.CompletedTask;
});


IpRiskReport Report(bool abuse = false, bool proxy = false, string country = "US") =>
    new("192.0.2.1", "US", country, 90, "Clean", 90, null, false, false, proxy, false, false, abuse, true, "Test");
await Test("risk verdict distinguishes pass warning and block", () =>
{
    Assert(Report().Judge("US") == RiskVerdict.Pass);
    Assert(Report(proxy: true).Judge("US") == RiskVerdict.Warn);
    Assert(Report(abuse: true).Judge("US") == RiskVerdict.Block);
    Assert(Report(country: "JP").Judge("US") == RiskVerdict.Block);
    return Task.CompletedTask;
});
await Test("blocked risk needs explicit force and still consumes a single grant", async () =>
{
    var p = new FakeProbe { Risk = Report(abuse: true) }; var c = new Coordinator(p);
    Assert((await c.CheckAsync("US", false, default)).Verdict == RiskVerdict.Block);
    Assert((await c.PermitAsync(false, default)).Ticket.Length == 0);
    Assert((await c.PermitAsync(true, default)).Ticket.Length > 0);
    Assert((await c.PermitAsync(true, default)).Ticket.Length == 0);
});
await Test("force cannot bypass proxy failure or an expired audit", async () =>
{
    var time = new FakeTime(); var p = new FakeProbe { Risk = Report(abuse: true) }; var c = new Coordinator(p, time);
    await c.CheckAsync("US", false, default);
    time.Advance(46);
    Assert((await c.PermitAsync(true, default)).Ticket.Length == 0);
    p.ProxyFails = true;
    await c.CheckAsync("US", false, default);
    Assert((await c.PermitAsync(true, default)).Ticket.Length == 0);
});
await Test("risk lookup failure does not change the hard audit result", async () =>
{
    var p = new FakeProbe { AdvisoryFails = true }; var c = new Coordinator(p);
    var r = await c.CheckAsync("US", false, default);
    Assert(r.Ready && r.Risk == null && r.Verdict == RiskVerdict.Pass);
    Assert((await c.PermitAsync(false, default)).Ticket.Length > 0);
});
await Test("quarantine failure during shutdown invalidates a prior grant", async () =>
{
    var p = new FakeProbe(); var c = new Coordinator(p);
    await c.CheckAsync("US", false, default); p.QuarantineFails = true;
    try { c.Shutdown(); throw new Exception("Shutdown silently accepted failed isolation"); }
    catch (CheckFailed) { }
    Assert(!c.Status.Ready && !c.Monitoring);
    Assert((await c.PermitAsync(true, default)).Ticket.Length == 0);
});

Console.WriteLine($"{passed} isolated tests passed. No proxies, services, accounts or firewall rules were modified.");

if (failures > 0) throw new Exception($"{failures} tests failed.");

sealed class FakeGuardRuntime : IGuardServiceRuntime
{
    public bool Running, Active, RefuseStop;
    public Queue<Response?> Statuses = new();
    public List<string> Events = [];
    public bool IsRunning => Running;
    public bool IsActive => Active;
    public bool TryStart() { Events.Add("start"); return false; }
    public Task<Response?> WaitForStatusAsync(TimeSpan duration, CancellationToken ct) { Events.Add("status"); return Task.FromResult(Statuses.Dequeue()); }
    public Task PrepareAsync(CancellationToken ct) { Events.Add("prepare"); Running = Active = true; return Task.CompletedTask; }
    public Task<Response> RequestStopAsync(CancellationToken ct)
    {
        Events.Add("stop");
        if (RefuseStop) return Task.FromResult(new Response("blocked", "", [], Protocol: GuardLifecycle.RequiredProtocol));
        Running = Active = false;
        return Task.FromResult(new Response("stopping", "", [], Protocol: GuardLifecycle.RequiredProtocol));
    }
}
sealed class FakeHttp(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => handler(request, cancellationToken);
}
sealed class FakeTime : TimeProvider
{
    private DateTimeOffset now = DateTimeOffset.UtcNow;
    public override DateTimeOffset GetUtcNow() => now;
    public void Advance(int seconds) => now = now.AddSeconds(seconds);
}
sealed class FakeProbe : IEnvironmentProbe
{
    public bool ProxyFails, CountryFails, RepairFails, EnvironmentFails, Fast = true, Quarantined, QuarantineFails, QuarantineUnexpectedFailure;
    public IpRiskReport? Risk;
    public bool AdvisoryFails;
    public Task<AdvisoryResult> AdvisoryAsync(string target, CancellationToken ct)
    {
        if (AdvisoryFails) throw new IOException();
        return Task.FromResult(new AdvisoryResult(Risk, []));
    }
    public string Country = "US";
    public int CountryCalls, EnvironmentCalls, Repairs;
    public List<string> Events = [];
    private static readonly ProxySnapshot Proxy = new(1, 1, "fake-tun", 9097, "rule", true, true);
    public Task<ProxySnapshot> ProxyAsync(CancellationToken ct) { Events.Add("proxy"); if (ProxyFails) throw new CheckFailed("proxy", "missing"); return Task.FromResult(Proxy); }
    public Task<string> CountryAsync(CancellationToken ct) { CountryCalls++; Events.Add("country"); if (CountryFails) throw new IOException(); return Task.FromResult(Country); }
    public Task<List<CheckItem>> EnvironmentAsync(ProxySnapshot p, CancellationToken ct) { EnvironmentCalls++; Events.Add("environment"); return Task.FromResult(EnvironmentFails ? new List<CheckItem> { new("连接保护", "fail", "请修复连接保护") } : new List<CheckItem>()); }
    public bool FastMatches(ProxySnapshot p) => Fast;
    public Task RepairAsync(ProxySnapshot p, CancellationToken ct) { Repairs++; Events.Add("repair"); if (RepairFails) throw new IOException(); return Task.CompletedTask; }
    public void Quarantine() { if (QuarantineUnexpectedFailure) throw new InvalidOperationException(); if (QuarantineFails) throw new CheckFailed("连接隔离", "隔离不可用"); Quarantined = true; Events.Add("quarantine"); }
    public void ResumeTraffic() { Quarantined = false; Events.Add("resume"); }
}

sealed class BlockedDispatcher : SynchronizationContext
{
    public override void Post(SendOrPostCallback callback, object? state) { }
}
