using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace ClaudeGuard;

public sealed class WindowsProbe(string owner) : IEnvironmentProbe, IDisposable
{
    private readonly HttpClient http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(3) })
        { Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 262144 };
    public string Secret { private get; set; } = "";
    public string AppPath { get; private set; } = "";

    public void SetAppPath(string path)
    {
        if (path.Length > 1024 || !Path.IsPathFullyQualified(path) || path.StartsWith(@"\\") || !File.Exists(path) ||
            !Path.GetFileName(path).Equals("Claude.exe", StringComparison.OrdinalIgnoreCase))
            throw new CheckFailed("Claude 客户端", "请选择已安装的 Claude.exe");
        string full = Path.GetFullPath(path);
        // Never follow a user-controlled link while performing privileged file operations.
        for (var dir = new FileInfo(full).Directory; dir != null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new CheckFailed("Claude 客户端", "不支持重解析目录，请选择原始安装位置");
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new CheckFailed("Claude 客户端", "不支持重解析文件");
        var version = FileVersionInfo.GetVersionInfo(full);
        if (!(version.CompanyName?.Contains("Anthropic", StringComparison.OrdinalIgnoreCase) ?? false))
            throw new CheckFailed("Claude 客户端", "所选文件不是 Anthropic Claude 客户端");
        if (!Signature.Verify(full)) throw new CheckFailed("Claude 客户端", "Claude 的数字签名验证失败，请使用官方客户端");
        AppPath = full;
    }

    public async Task<ProxySnapshot> ProxyAsync(CancellationToken ct)
    {
        bool verge = false;
        foreach (var p in Process.GetProcessesByName("clash-verge")) using (p)
        { try { verge |= Native.Owner(p) == owner; } catch { } }
        if (!verge) throw new CheckFailed("Clash Verge", "请手动打开 Clash Verge 并连接代理");
        var kernels = Process.GetProcessesByName("verge-mihomo");
        try
        {
            foreach (var p in kernels)
            {
                try
                {
                    var sid = Native.Owner(p);
                    if (sid != owner && sid != "S-1-5-18") continue;
                    foreach (var port in Native.LoopbackPorts(p.Id))
                    {
                        try
                        {
                            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            budget.CancelAfter(TimeSpan.FromSeconds(2));
                            using var request = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/configs");
                            if (Secret.Length != 0) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Secret);
                            using var result = await http.SendAsync(request, budget.Token);
                            if (result.StatusCode == HttpStatusCode.Unauthorized) continue;
                            result.EnsureSuccessStatusCode();
                            using var json = JsonDocument.Parse(await result.Content.ReadAsStringAsync(budget.Token));
                            var root = json.RootElement;
                            var mode = root.GetProperty("mode").GetString() ?? "";
                            if (mode == "direct") throw new CheckFailed("代理模式", "Clash Verge 处于直连模式，请改为规则或全局模式");
                            var tun = root.GetProperty("tun");
                            if (!tun.TryGetProperty("enable", out var enable) || !enable.GetBoolean())
                                throw new CheckFailed("TUN 连接", "请在 Clash Verge 中手动开启 TUN");
                            string device = tun.TryGetProperty("device", out var dev) ? dev.GetString() ?? "" : "";
                            var adapter = ActiveTun(device);
                            if (adapter == null) throw new CheckFailed("TUN 连接", "未发现控制接口对应的活动 TUN 网卡");
                            bool strict = tun.TryGetProperty("strict-route", out var sr) && sr.GetBoolean();
                            bool autoRoute = tun.TryGetProperty("auto-route", out var ar) && ar.GetBoolean();
                            if (!strict || !autoRoute) throw new CheckFailed("TUN 路由", "请在 Clash Verge 中开启 auto-route 和 strict-route，然后重试");
                            return new(p.Id, p.StartTime.ToUniversalTime().Ticks, adapter.Id, port, mode, true, strict);
                        }
                        catch (CheckFailed) { throw; }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                        catch { /* Another loopback listener may be the controller. */ }
                    }
                }
                catch (CheckFailed) { throw; }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { /* Try another listener owned by this exact kernel, never arbitrary ports. */ }
            }
        }
        finally { foreach (var p in kernels) p.Dispose(); }
        throw new CheckFailed("代理控制接口", "无法连接内核控制接口；请检查 Clash Verge，或填写控制接口密钥");
    }

    private static NetworkInterface? ActiveTun(string device) => NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
        n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
        !string.IsNullOrWhiteSpace(device) && (n.Name.Equals(device, StringComparison.OrdinalIgnoreCase) || n.Id.Equals(device, StringComparison.OrdinalIgnoreCase)));

    public Task<string> CountryAsync(CancellationToken ct) => CountryLookup.QueryAsync(http, ct);

    public bool FastMatches(ProxySnapshot proxy)
    {
        try
        {
            using var p = Process.GetProcessById(proxy.Pid);
            return p.ProcessName == "verge-mihomo" && p.StartTime.ToUniversalTime().Ticks == proxy.Started &&
                NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Id == proxy.Adapter && n.OperationalStatus == OperationalStatus.Up) &&
                Firewall.Inspect(AppPath, proxy.Adapter).Ok;
        }
        catch { return false; }
    }

    public Task<List<CheckItem>> EnvironmentAsync(ProxySnapshot proxy, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        // Missing rule, stale rule and unreadable rule each carry their own reason in the detail,
        // instead of collapsing into one generic sentence.
        var protection = Firewall.Inspect(AppPath, proxy.Adapter);
        return Task.FromResult(new List<CheckItem> {
            new("连接保护", protection.Ok ? "ok" : "fail", protection.Detail),
            new("系统环境", "info", "当前时区：" + TimeZoneInfo.Local.Id + " · 保留系统实际设置")
        });
    }
    // Runs only on an explicit audit, never on the 2-second tick: two network round trips are too
    // slow for the monitor budget, and the result never changes whether Claude may start.
    public async Task<AdvisoryResult> AdvisoryAsync(string target, CancellationToken ct)
    {
        try
        {
            var report = await IpRisk.LookupAsync(http, ct);
            return new(report, [report.ToCheckItem(target)]);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (CheckFailed ex) { return new(null, [new("IP 风险", "info", ex.Message + "（不影响启动）")]); }
        catch { return new(null, [new("IP 风险", "info", "暂时无法获取 IP 风险信息（不影响启动）")]); }
    }
    public Task RepairAsync(ProxySnapshot proxy, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Firewall.Apply(AppPath, proxy.Adapter);
        return Task.CompletedTask;
    }
    public void Quarantine() { if (AppPath.Length != 0) Firewall.Quarantine(AppPath, true); }
    public void ResumeTraffic() => Firewall.Quarantine(AppPath, false);
    public void Dispose() => http.Dispose();
}
