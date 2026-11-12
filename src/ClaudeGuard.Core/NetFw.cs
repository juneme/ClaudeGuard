using System.Runtime.InteropServices;

namespace ClaudeGuard;

// Windows Firewall COM values were previously passed as bare integers (2, 0, 256, int.MaxValue)
// at every call site. They are named here once and checked by the compiler everywhere else.
public enum FwDirection { Inbound = 1, Outbound = 2 }
public enum FwAction { Block = 0, Allow = 1 }
public enum FwProtocol { Any = 256 }
[Flags] public enum FwProfile { Domain = 1, Private = 2, Public = 4, All = 0x7FFFFFFF }

public enum FwRuleState { Ok, Missing, Mismatch, Unreadable }

public sealed record FwRuleCheck(FwRuleState State, string Detail)
{
    public bool Ok => State == FwRuleState.Ok;
}

public sealed class FwException(string message, int code, Exception? inner = null) : Exception(message, inner)
{
    public int Code { get; } = code;
    public string CodeText => "0x" + unchecked((uint)Code).ToString("X8");
}

// The only place that touches HNetCfg COM. Member names appear once each, so a rename or a typo
// fails here at the single boundary instead of silently degrading a check elsewhere.
public sealed class FwRule
{
    private readonly dynamic rule;
    public FwRule() => rule = FwCom.Create("HNetCfg.FWRule");
    internal FwRule(object value) => rule = value;

    public string Name { get => rule.Name; set => rule.Name = value; }
    public string Description { get => rule.Description; set => rule.Description = value; }
    public string ApplicationName { get => rule.ApplicationName; set => rule.ApplicationName = value; }
    public FwDirection Direction { get => (FwDirection)(int)rule.Direction; set => rule.Direction = (int)value; }
    public FwAction Action { get => (FwAction)(int)rule.Action; set => rule.Action = (int)value; }
    public FwProtocol Protocol { get => (FwProtocol)(int)rule.Protocol; set => rule.Protocol = (int)value; }
    public FwProfile Profiles { get => (FwProfile)(int)rule.Profiles; set => rule.Profiles = (int)value; }
    public bool Enabled { get => (bool)rule.Enabled; set => rule.Enabled = value; }
    internal object Inner => (object)rule;

    public string[] Interfaces
    {
        get => rule.Interfaces is Array interfaces ? interfaces.Cast<string>().ToArray() : [];
        // INetFwRule expects SAFEARRAY(VARIANT), not the SAFEARRAY(BSTR) produced by string[].
        set => rule.Interfaces = value.Cast<object>().ToArray();
    }
}

public sealed class FwPolicy
{
    private const int FileNotFound = unchecked((int)0x80070002);
    private const int ElementNotFound = unchecked((int)0x80070490);

    private readonly dynamic policy;
    private FwPolicy(object value) => policy = value;
    public static FwPolicy Open() => new(FwCom.Create("HNetCfg.FwPolicy2"));

    public bool FirewallEnabled(FwProfile profile) => (bool)policy.FirewallEnabled[(int)profile];

    // A missing rule is a normal state, not an interop fault; everything else stays loud.
    public FwRule? Find(string name)
    {
        try { return new FwRule(policy.Rules.Item(name)); }
        catch (COMException ex) when (ex.HResult is FileNotFound or ElementNotFound) { return null; }
    }
    public void Remove(string name)
    {
        try { policy.Rules.Remove(name); }
        catch (COMException ex) when (ex.HResult is FileNotFound or ElementNotFound) { }
    }
    public void Add(FwRule rule) => policy.Rules.Add(rule.Inner);
}

internal static class FwCom
{
    internal static dynamic Create(string progId)
    {
        try
        {
            var type = Type.GetTypeFromProgID(progId)
                ?? throw new FwException("当前系统未注册 " + progId + "，请确认 Windows 防火墙服务可用", unchecked((int)0x80040154));
            return Activator.CreateInstance(type)!;
        }
        catch (COMException ex) { throw new FwException("无法创建防火墙 COM 对象 " + progId, ex.HResult, ex); }
    }
}
