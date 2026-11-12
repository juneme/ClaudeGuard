using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ClaudeGuard;

public sealed record FwFacts(bool DomainEnabled, bool PrivateEnabled, bool PublicEnabled, bool RuleFound,
    bool Enabled, FwDirection Direction, FwAction Action, FwProtocol Protocol, FwProfile Profiles,
    string App, string Application, IReadOnlyList<string> Interfaces, IReadOnlyList<string> Expected);

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
    public static FwRuleCheck Evaluate(FwFacts f)
    {
        if (!f.DomainEnabled || !f.PrivateEnabled || !f.PublicEnabled)
            return new(FwRuleState.Mismatch, "Windows 防火墙未启用域/专用/公用全部配置文件");
        if (!f.RuleFound) return new(FwRuleState.Missing, "尚未建立 Claude 专用出站阻断规则，请点击修复");
        if (f.Expected.Count == 0) return new(FwRuleState.Mismatch, "无法确认需要保护的物理网卡");
        if (!f.Enabled) return new(FwRuleState.Mismatch, "Claude 专用规则已存在但被停用");
        if (f.Direction != FwDirection.Outbound) return new(FwRuleState.Mismatch, "Claude 专用规则的方向不是出站");
        if (f.Action != FwAction.Block) return new(FwRuleState.Mismatch, "Claude 专用规则的动作不是阻止");
        if (f.Protocol != FwProtocol.Any) return new(FwRuleState.Mismatch, "Claude 专用规则被限制为单一协议，其他协议仍可直连");
        if (f.Profiles != FwProfile.All) return new(FwRuleState.Mismatch, "Claude 专用规则未覆盖全部网络配置文件");
        if (!string.Equals(f.Application, f.App, StringComparison.OrdinalIgnoreCase))
            return new(FwRuleState.Mismatch, "Claude 专用规则绑定的程序不是当前客户端，请点击修复");
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
            var facts = rule is null
                ? new FwFacts(policy.FirewallEnabled(FwProfile.Domain), policy.FirewallEnabled(FwProfile.Private),
                    policy.FirewallEnabled(FwProfile.Public), false, false, FwDirection.Inbound, FwAction.Allow,
                    FwProtocol.Any, 0, app, "", [], expected)
                : new FwFacts(policy.FirewallEnabled(FwProfile.Domain), policy.FirewallEnabled(FwProfile.Private),
                    policy.FirewallEnabled(FwProfile.Public), true, rule.Enabled, rule.Direction, rule.Action,
                    rule.Protocol, rule.Profiles, app, rule.ApplicationName, rule.Interfaces, expected);
            return Evaluate(facts);
        }
        catch (FwException ex) { return new(FwRuleState.Unreadable, "无法读取防火墙规则（" + ex.CodeText + "）：" + ex.Message); }
        catch (COMException ex)
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
                Protocol = FwProtocol.Any, Profiles = FwProfile.All, Interfaces = interfaces, Enabled = true
            };
            // A persistent quarantine rule remains enabled while the routing rule is replaced.
            policy.Remove(RuleName);
            policy.Add(rule);
        }
        catch (FwException ex) { throw new CheckFailed("连接保护", "写入防火墙规则失败（" + ex.CodeText + "）：" + ex.Message); }
        catch (COMException ex) { throw new CheckFailed("连接保护", "写入防火墙规则失败（0x" + unchecked((uint)ex.HResult).ToString("X8") + "）"); }
        var written = Inspect(app, adapter);
        if (!written.Ok) throw new CheckFailed("连接保护", written.Detail + "，保持禁止启动");
    }

    public static void Quarantine(string app, bool enabled)
    {
        try
        {
            var policy = FwPolicy.Open();
            var rule = policy.Find(QuarantineName);
            if (rule is null) policy.Add(rule = NewQuarantineRule(app, QuarantineName));
            else if (!string.Equals(rule.ApplicationName, app, StringComparison.OrdinalIgnoreCase))
            {
                // Keep the old path blocked too, until the explicit repair replaces its routing rule.
                rule.Name = PreviousName;
                policy.Add(rule = NewQuarantineRule(app, QuarantineName));
            }
            rule.Enabled = enabled;
            if (rule.Enabled != enabled) throw new CheckFailed("连接隔离", "无法确认防火墙隔离状态");
        }
        catch (FwException ex) { throw new CheckFailed("连接隔离", "无法确认防火墙隔离状态（" + ex.CodeText + "）：" + ex.Message); }
        catch (COMException ex) { throw new CheckFailed("连接隔离", "无法确认防火墙隔离状态（0x" + unchecked((uint)ex.HResult).ToString("X8") + "）"); }
    }

    private static FwRule NewQuarantineRule(string app, string name) => new()
    {
        Name = name, ApplicationName = app, Direction = FwDirection.Outbound, Action = FwAction.Block,
        Protocol = FwProtocol.Any, Profiles = FwProfile.All, Enabled = true
    };

    public static void Remove()
    {
        try
        {
            var policy = FwPolicy.Open();
            foreach (var name in new[] { RuleName, QuarantineName, PreviousName }) policy.Remove(name);
        }
        catch (FwException) { }
        catch (COMException) { }
    }
}
