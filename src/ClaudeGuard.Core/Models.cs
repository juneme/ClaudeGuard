namespace ClaudeGuard;

public static class Product
{
    public const string ServiceName = "ClaudeGuard";
    // Versioned on purpose: an older service must never answer as if it were current.
    public const string PipeName = "ClaudeGuard.v3";
    public const string RegistryPath = @"SOFTWARE\ClaudeGuard";
    public static string InstallPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClaudeGuard");
}
public sealed record CheckItem(string Title, string State, string Detail);
public sealed record ProxySnapshot(int Pid, long Started, string Adapter, int Port, string Mode, bool Tun, bool StrictRoute);
public sealed record Observation(ProxySnapshot Proxy, string Country, string TimeZone);
public sealed record Request(string Command, string Country = "", string Secret = "", string AppPath = "", bool Force = false);
public sealed record Response(string Phase, string Message, List<CheckItem> Checks, bool Ready = false,
    string Ticket = "", string Country = "", string TimeZone = "", DateTimeOffset? LastChecked = null,
    bool LaunchUsed = false, int Protocol = 0, IpRiskReport? Risk = null, RiskVerdict Verdict = RiskVerdict.Pass);

public sealed record AdvisoryResult(IpRiskReport? Risk, List<CheckItem> Items);

public interface IEnvironmentProbe
{
    Task<ProxySnapshot> ProxyAsync(CancellationToken ct);
    Task<string> CountryAsync(CancellationToken ct);
    Task<List<CheckItem>> EnvironmentAsync(ProxySnapshot proxy, CancellationToken ct);
    // Advisory: describes the exit. The coordinator decides whether the verdict blocks a launch.
    Task<AdvisoryResult> AdvisoryAsync(string target, CancellationToken ct);
    bool FastMatches(ProxySnapshot proxy);
    Task RepairAsync(ProxySnapshot proxy, CancellationToken ct);
    void Quarantine();
    void ResumeTraffic();
}
public sealed class CheckFailed(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
