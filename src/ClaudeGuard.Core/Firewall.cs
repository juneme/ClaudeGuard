using System.Net.NetworkInformation;

namespace ClaudeGuard;

public sealed record FwFacts(bool DomainEnabled, bool PrivateEnabled, bool PublicEnabled, bool RuleFound,
    bool Enabled, FwDirection Direction, FwAction Action, FwProtocol Protocol, FwProfile Profiles,
    string App, string Application, IReadOnlyList<string> Interfaces, IReadOnlyList<string> Expected,
    string InterfaceTypes = "All", string LocalAddresses = "*", string RemoteAddresses = "*", string ServiceName = "");

public static class Firewall
{
    private const string RuleName = "ClaudeGuard - block direct interfaces";
    private const string QuarantineName = "ClaudeGuard - connection quarantine";
    private const string PreviousName = QuarantineName + " - previous";
    private static readonly FwProfile[] Profiles = [FwProfile.Domain, FwProfile.Private, FwProfile.Public];

    private static string[] OtherInterfaces(string adapter) => FirewallInterfaces.Select(
        NetworkInterface.GetAllNetworkInterfaces().Select(n => new FirewallInterface(n.Id, n.Name,
            n.NetworkInterfaceType == NetworkInterfaceType.Loopback,
            n.Supports(NetworkInterfaceComponent.IPv4), n.Supports(NetworkInterfaceComponent.IPv6))), adapter);

    // Pure decision table: no COM, no system state. Every reason the protection is unusable is
    // named, so the window can explain what to fix instead of repeating one generic sentence.
    public static FwRuleCheck Evaluate(FwFacts f) => EvaluateRule(f, false, true);

    internal static FwRuleCheck EvaluateQuarantine(FwFacts f, bool enabled) => EvaluateRule(f, true, enabled);

    private static FwRuleCheck EvaluateRule(FwFacts f, bool quarantine, bool enabled)
    {
        if (!f.DomainEnabled || !f.PrivateEnabled || !f.PublicEnabled)
            return new(FwRuleState.Mismatch, "Windows 防火墙未启用域/专用/公用全部配置文件");
        if (!f.RuleFound) return new(FwRuleState.Missing, quarantine ? "尚未建立 Claude 连接隔离规则" : "尚未建立 Claude 专用出站阻断规则，请点击修复");
        if (!quarantine && f.Expected.Count == 0) return new(FwRuleState.Mismatch, "无法确认需要保护的物理网卡");
        if (f.Enabled != enabled) return new(FwRuleState.Mismatch, enabled ? "Claude 专用规则已存在但被停用" : "Claude 连接隔离规则未能解除");
        if (f.Direction != FwDirection.Outbound) return new(FwRuleState.Mismatch, "Claude 专用规则的方向不是出站");
        if (f.Action != FwAction.Block) return new(FwRuleState.Mismatch, "Claude 专用规则的动作不是阻止");
        if (f.Protocol != FwProtocol.Any) return new(FwRuleState.Mismatch, "Claude 专用规则被限制为单一协议，其他协议仍可直连");
        if (f.Profiles != FwProfile.All) return new(FwRuleState.Mismatch, "Claude 专用规则未覆盖全部网络配置文件");
        if (!string.Equals(f.Application, f.App, StringComparison.OrdinalIgnoreCase))
            return new(FwRuleState.Mismatch, "Claude 专用规则绑定的程序不是当前客户端，请点击修复");
        if (!f.InterfaceTypes.Equals("All", StringComparison.OrdinalIgnoreCase))
            return new(FwRuleState.Mismatch, "Claude 专用规则未覆盖全部网卡类型");
        if (f.LocalAddresses != "*" || f.RemoteAddresses != "*")
            return new(FwRuleState.Mismatch, "Claude 专用规则被限制为部分网络地址");
        if (f.ServiceName.Length != 0)
            return new(FwRuleState.Mismatch, "Claude 专用规则被限制为 Windows 服务流量");
        if (quarantine && f.Interfaces.Count != 0)
            return new(FwRuleState.Mismatch, "Claude 连接隔离规则未覆盖全部网卡");
        if (quarantine) return new(FwRuleState.Ok, enabled ? "Claude 连接已隔离" : "Claude 连接隔离已解除");
        if (f.Interfaces.Count != f.Expected.Count ||
            !f.Interfaces.Order(StringComparer.Ordinal).SequenceEqual(f.Expected, StringComparer.Ordinal))
            return new(FwRuleState.Mismatch, "Claude 专用规则绑定的网卡与当前物理网卡不一致，请点击修复");
        return new(FwRuleState.Ok, "Claude 已阻止从其他网卡直接联网");
    }

    // Read-only. A missing rule is a state; an unreadable rule is a fault with a Windows error code.
    public static FwRuleCheck Inspect(string app, string adapter)
    {
        string[] expected = OtherInterfaces(adapter);
        try
        {
            var policy = FwPolicy.Open();
            var rule = policy.Find(RuleName);
            return Evaluate(ReadFacts(policy, rule, app, expected));
        }
        catch (FwException ex) { return new(FwRuleState.Unreadable, "无法读取防火墙规则（" + ex.CodeText + "）：" + ex.Message); }
        catch (Exception ex)
        {
            return new(FwRuleState.Unreadable, "无法读取防火墙规则（0x" + unchecked((uint)ex.HResult).ToString("X8") + "），请检查 Windows 防火墙服务");
        }
    }

    public static void Apply(string app, string adapter)
    {
        if (string.IsNullOrWhiteSpace(app)) throw new CheckFailed("Claude 客户端", "请先选择 Claude.exe");
        string[] interfaces = OtherInterfaces(adapter);
        if (interfaces.Length == 0) throw new CheckFailed("连接保护", "无法确认需要保护的物理网卡");
        try
        {
            var policy = FwPolicy.Open();
            foreach (var profile in Profiles)
                if (!policy.FirewallEnabled(profile))
                    throw new CheckFailed("Windows 防火墙", "请先在 Windows 安全中心启用所有防火墙配置文件");
            var rule = new FwRule
            {
                Name = RuleName,
                Description = "Only Claude direct-interface egress; managed by ClaudeGuard.",
                ApplicationName = app, Direction = FwDirection.Outbound, Action = FwAction.Block,
                Protocol = FwProtocol.Any, Profiles = FwProfile.All, Interfaces = interfaces,
                InterfaceTypes = "All", LocalAddresses = "*", RemoteAddresses = "*", Enabled = true
            };
            // A persistent quarantine rule remains enabled while the routing rule is replaced.
            policy.Remove(RuleName);
            policy.Add(rule);
        }
        catch (CheckFailed) { throw; }
        catch (FwException ex) { throw new CheckFailed("连接保护", "写入防火墙规则失败（" + ex.CodeText + "）：" + ex.Message); }
        catch (Exception ex) { throw new CheckFailed("连接保护", "写入防火墙规则失败（0x" + unchecked((uint)ex.HResult).ToString("X8") + "）"); }
        var written = Inspect(app, adapter);
        if (!written.Ok) throw new CheckFailed("连接保护", written.Detail + "，保持禁止启动");
    }

    public static void Quarantine(string app, bool enabled) => Quarantine(app, enabled, FwPolicy.Open);

    // The injected policy is an in-memory collection in regression tests, never a real rule store.
    internal static void Quarantine(string app, bool enabled, Func<FwPolicy> openPolicy)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(app)) throw new CheckFailed("Claude 客户端", "请先选择 Claude.exe");
            var policy = openPolicy();
            foreach (var profile in Profiles)
                if (!policy.FirewallEnabled(profile))
                    throw new CheckFailed("连接隔离", "请先在 Windows 安全中心启用所有防火墙配置文件");
            var rule = policy.Find(QuarantineName);
            var current = ReadFacts(policy, rule, app, []);
            var shape = EvaluateQuarantine(current, current.Enabled);
            if (!enabled && !shape.Ok)
                throw new CheckFailed("连接隔离", shape.Detail + "，禁止恢复连接");
            if (rule != null && !shape.Ok)
            {
                // Preserve an old client's rule while establishing a complete rule for this path.
                rule.Name = PreviousName;
                rule = null;
            }
            if (rule is null) policy.Add(NewQuarantineRule(app, QuarantineName));
            else rule.Enabled = enabled;
            // Re-query the policy: reading the detached object passed to Add does not establish
            // that the stored rule exists, applies to this client, or blocks every interface.
            var written = EvaluateQuarantine(ReadFacts(policy, policy.Find(QuarantineName), app, []), enabled);
            if (!written.Ok) throw new CheckFailed("连接隔离", written.Detail + "，无法确认防火墙隔离状态");
        }
        catch (CheckFailed) { throw; }
        catch (FwException ex) { throw new CheckFailed("连接隔离", "无法确认防火墙隔离状态（" + ex.CodeText + "）：" + ex.Message); }
        catch (Exception ex) { throw new CheckFailed("连接隔离", "无法确认防火墙隔离状态（0x" + unchecked((uint)ex.HResult).ToString("X8") + "）"); }
    }

    private static FwRule NewQuarantineRule(string app, string name) => new()
    {
        Name = name, ApplicationName = app, Direction = FwDirection.Outbound, Action = FwAction.Block,
        Protocol = FwProtocol.Any, Profiles = FwProfile.All,
        InterfaceTypes = "All", LocalAddresses = "*", RemoteAddresses = "*", Enabled = true
    };

    private static FwFacts ReadFacts(FwPolicy policy, FwRule? rule, string app, string[] expected) => new(
        policy.FirewallEnabled(FwProfile.Domain), policy.FirewallEnabled(FwProfile.Private),
        policy.FirewallEnabled(FwProfile.Public), rule != null, rule?.Enabled ?? false,
        rule?.Direction ?? FwDirection.Inbound, rule?.Action ?? FwAction.Allow,
        rule?.Protocol ?? FwProtocol.Any, rule?.Profiles ?? 0, app, rule?.ApplicationName ?? "",
        rule?.Interfaces ?? [], expected, rule?.InterfaceTypes ?? "", rule?.LocalAddresses ?? "",
        rule?.RemoteAddresses ?? "", rule?.ServiceName ?? "");

    public static void Remove()
    {
        try
        {
            var policy = FwPolicy.Open();
            foreach (var name in new[] { RuleName, QuarantineName, PreviousName }) policy.Remove(name);
        }
        catch (Exception) { }
    }
}
