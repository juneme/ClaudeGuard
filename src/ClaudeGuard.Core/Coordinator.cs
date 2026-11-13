namespace ClaudeGuard;

// One authority owns grants, network probes and revocation. No approval files are trusted.
public sealed class Coordinator(IEnvironmentProbe probe, TimeProvider? clock = null)
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly SemaphoreSlim gate = new(1, 1);
    private Observation? observation;
    private IpRiskReport? risk;
    private RiskVerdict verdict = RiskVerdict.Pass;
    private DateTimeOffset checkedAt;
    private string target = "";
    private string ticket = "";
    private bool launchConsumed;
    private bool suspended;
    private DateTimeOffset nextRetry;
    private Response state = new("idle", "等待检测：点击「开始检测」确认代理、出口与连接保护", []);
    public Response Status => state with { LaunchUsed = launchConsumed };
    public bool Monitoring => observation != null;

    public async Task<Response> CheckAsync(string country, bool repair, CancellationToken ct, Action? configure = null)
    {
        await gate.WaitAsync(ct);
        try
        {
            var items = new List<CheckItem>();
            string stage = "连接隔离";
            try
            {
                Revoke("正在检查连接");
                stage = "客户端准备";
                configure?.Invoke();
                if (!RegionPolicy.IsTarget(country)) throw new CheckFailed("出口地区", "请选择目标国家或地区");
                target = country;
                stage = "Clash Verge";
                state = new("checking", "确认 Clash Verge 与 TUN", [.. items]);
                var proxy = await probe.ProxyAsync(ct);
                items.Add(new("Clash Verge", "ok", "客户端与代理内核均在运行"));
                items.Add(new("TUN 连接", "ok", "控制接口与活动网卡交叉验证"));
                stage = "出口地区";
                state = new("checking", "确认出口地区", [.. items]);
                var actual = await probe.CountryAsync(ct);
                if (actual != target) throw new CheckFailed("出口地区", "出口与选定地区不一致，请在 Clash Verge 中调整节点");
                items.Add(new("出口地区", "ok", actual + " · 与目标一致"));
                // Repair is intentionally unreachable until proxy and country have passed.
                stage = "连接保护";
                if (repair) await probe.RepairAsync(proxy, ct);
                state = new("checking", "检查连接保护", [.. items]);
                items.AddRange(await probe.EnvironmentAsync(proxy, ct));
                if (items.Any(x => x.State == "fail")) throw new CheckFailed("连接保护", "请修复后重新检查");
                // Risk context is shown next to the audit and decides whether a launch is allowed,
                // but a failing lookup must never fail the audit itself.
                stage = "出口风险";
                state = new("checking", "核对出口风险", [.. items]);
                try
                {
                    var advisory = await probe.AdvisoryAsync(country, ct);
                    risk = advisory.Risk;
                    verdict = risk?.Judge(country) ?? RiskVerdict.Pass;
                    items.AddRange(advisory.Items);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch
                {
                    risk = null; verdict = RiskVerdict.Pass;
                    items.Add(new("IP 风险", "info", "暂时无法获取 IP 风险信息（不影响检测）"));
                }
                observation = new(proxy, actual, TimeZoneInfo.Local.Id);
                checkedAt = time.GetUtcNow(); ticket = Guid.NewGuid().ToString("N"); launchConsumed = false;
                probe.ResumeTraffic(); suspended = false;
                state = new("ready", ReadyMessage(verdict), items, true, "", actual, observation.TimeZone, checkedAt,
                    false, 0, risk, verdict);
            }
            catch (CheckFailed ex)
            {
                var existing = items.LastOrDefault(item => item.Title == ex.Title && item.State == "fail");
                BlockAfterFailure(existing?.Detail ?? ex.Message, ex.Title, items);
            }
            catch (OperationCanceledException)
            {
                const string message = "检查已取消或超时，请重试";
                BlockAfterFailure(message, stage, items);
            }
            catch (Exception ex)
            {
                string message = stage switch
                {
                    "连接隔离" => "无法建立 Claude 连接隔离，请检查 Windows 防火墙服务",
                    "客户端准备" => "准备 Claude 客户端或连接隔离时发生错误",
                    "Clash Verge" => "检查 Clash Verge 连接时发生错误",
                    "出口地区" => "检查出口地区时发生错误",
                    _ => "设置或检查连接保护时发生错误"
                };
                message += $"（错误码 0x{unchecked((uint)ex.HResult):X8}）";
                BlockAfterFailure(message, stage, items);
            }
            return state;
        }
        finally { gate.Release(); }
    }

    private static string ReadyMessage(RiskVerdict value) => value switch
    {
        RiskVerdict.Block => "出口 IP 判定为高风险，已阻止启动；可修复代理后重试，或强制启动",
        RiskVerdict.Warn => "连接已就绪，出口存在提示项，可以启动",
        _ => "连接已就绪，可以启动 Claude"
    };

    public async Task<Response> PermitAsync(bool force, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            // O(1) local validation only. The previous audit is not run a second time.
            if (!Fresh() || observation == null || !probe.FastMatches(observation.Proxy))
            { if (observation != null) Suspend("连接许可暂时失效，Claude 保持断网，等待重连"); else Revoke("请先检测连接"); return state; }
            // A blocked exit needs an explicit override; every other grant still needs a fresh audit.
            if (verdict == RiskVerdict.Block && !force)
                return state with { Message = "出口 IP 判定为高风险，已阻止启动；可选择强制启动" };
            if (launchConsumed) return state with { Ready = false, Message = "本次启动许可已使用，请重新检查后启动" };
            launchConsumed = true;
            return state with { Ticket = ticket };
        }
        catch (Exception)
        {
            BlockAfterFailure("无法确认连接隔离，禁止启动；请检查 Windows 防火墙服务", "连接隔离", []);
            return state;
        }
        finally { gate.Release(); }
    }

    public async Task TickAsync(CancellationToken ct)
    {
        if (!await gate.WaitAsync(0, ct)) return;
        try
        {
            if (observation == null) return;
            if (!suspended && (!Fresh() || !probe.FastMatches(observation.Proxy))) Suspend("代理或网络发生变化，Claude 已断网，正在等待重连");
            if (suspended && time.GetUtcNow() < nextRetry) return;
            if (suspended && !TryQuarantine())
            { nextRetry = time.GetUtcNow().AddSeconds(5); return; }
            if (!suspended && time.GetUtcNow() - checkedAt < TimeSpan.FromSeconds(25)) return;
            try
            {
                using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
                budget.CancelAfter(TimeSpan.FromSeconds(12));
                var current = await probe.ProxyAsync(budget.Token);
                var country = await probe.CountryAsync(budget.Token);
                if (country != target)
                { Suspend("出口地区不一致，Claude 保持断网，等待代理恢复"); return; }
                var checks = await probe.EnvironmentAsync(current, budget.Token);
                if (checks.Any(x => x.State == "fail")) { Suspend("连接保护需要修复，Claude 保持断网"); return; }
                observation = new(current, country, TimeZoneInfo.Local.Id);
                probe.ResumeTraffic(); suspended = false;
                if (!launchConsumed) ticket = Guid.NewGuid().ToString("N");
                checkedAt = time.GetUtcNow();
                state = state with
                {
                    Phase = "ready", Message = ReadyMessage(verdict), Ready = true,
                    Checks = state.Checks.Where(x => x.Title != "连接隔离" && checks.All(c => c.Title != x.Title)).Concat(checks).ToList(),
                    Ticket = "", Country = country, TimeZone = observation.TimeZone, LastChecked = checkedAt
                };
            }
            catch { Suspend("暂时无法确认连接，Claude 已断网，正在等待重连"); }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { Suspend("连接检查发生异常，正在隔离并等待重连"); }
        finally { gate.Release(); }
    }
    private bool Fresh() => state.Ready && time.GetUtcNow() - checkedAt <= TimeSpan.FromSeconds(45);
    private void Revoke(string message)
    {
        // Invalidate the grant even when the firewall COM operation fails.
        observation = null; ticket = ""; launchConsumed = false; risk = null; verdict = RiskVerdict.Pass;
        suspended = false;
        state = new("blocked", message, []);
        probe.Quarantine();
    }
    private void BlockAfterFailure(string message, string stage, List<CheckItem> items)
    {
        try { Revoke(message); }
        catch (Exception ex)
        {
            // The original isolation error already explains this stage. A retry must not add
            // another generic row for the same failure and bury its useful Windows error.
            if (stage != "连接隔离" && !items.Any(x => x.Title == "连接隔离" && x.State == "fail"))
                items.Add(new("连接隔离", "fail", ex is CheckFailed ? ex.Message :
                    $"无法确认连接隔离，禁止启动（错误码 0x{unchecked((uint)ex.HResult):X8}）"));
        }
        if (!items.Any(x => x.Title == stage && x.State == "fail")) items.Add(new(stage, "fail", message));
        state = new("blocked", message, items);
    }
    private void Suspend(string message)
    {
        suspended = true;
        ticket = ""; nextRetry = time.GetUtcNow().AddSeconds(5);
        state = state with { Phase = "reconnecting", Message = message, Ready = false, Ticket = "" };
        TryQuarantine();
    }

    private bool TryQuarantine()
    {
        try { probe.Quarantine(); return true; }
        catch (Exception ex)
        {
            // Revocation is already complete. Report isolation as unconfirmed, never as a
            // successful disconnect, and retry isolation before attempting network recovery.
            string detail = ex is CheckFailed ? ex.Message : $"错误码 0x{unchecked((uint)ex.HResult):X8}";
            var checks = state.Checks.Where(x => x.Title != "连接隔离").ToList();
            checks.Add(new("连接隔离", "fail", detail));
            state = state with { Ready = false, Ticket = "", Checks = checks,
                Message = "启动许可已撤销，但无法确认连接隔离；正在重试，Claude 进程保持运行" };
            return false;
        }
    }
    public void Shutdown() => Revoke("守护服务已停止");
}

public static class RegionPolicy
{
    // Explicit target selection; never infer or claim the user's physical location.
    public static readonly string[] Targets = ["US", "JP", "TW", "SG", "GB", "DE", "FR", "KR", "AU", "CA", "NL"];
    public static bool IsTarget(string value) => Targets.Contains(value, StringComparer.Ordinal);
}
