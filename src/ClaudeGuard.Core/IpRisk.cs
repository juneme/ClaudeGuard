using System.Text.Json;

namespace ClaudeGuard;

public enum RiskVerdict { Pass, Warn, Block }

// Advisory, never gating on its own: this describes what the Claude edge sees, and the caller
// decides whether the verdict is allowed to block a launch.
public sealed record IpRiskReport(string Ip, string? TraceCountry, string? CountryCode, int? TrustScore,
    string? Verdict, int? Confidence, string? Reasoning, bool Datacenter, bool Vpn, bool Proxy, bool Tor,
    bool Crawler, bool Abuser, bool Residential, string? AsnOrganization)
{
    public bool Mismatch(string target) => CountryCode is { Length: 2 } && !string.Equals(CountryCode, target, StringComparison.OrdinalIgnoreCase);

    // The launch gate. Country mismatch and abuse history are hard stops; a data centre or a
    // proxy label is only a warning, because plenty of legitimate exits look like that.
    public RiskVerdict Judge(string target)
    {
        if (Tor || Abuser || Mismatch(target)) return RiskVerdict.Block;
        if (TrustScore is < 25) return RiskVerdict.Block;
        if (Vpn || Proxy || Crawler || Datacenter || TrustScore is < 50) return RiskVerdict.Warn;
        return RiskVerdict.Pass;
    }

    public CheckItem ToCheckItem(string target)
    {
        var flags = new List<string>();
        if (Datacenter) flags.Add("机房 IP");
        if (Residential && !Datacenter) flags.Add("住宅 IP");
        if (Vpn) flags.Add("VPN");
        if (Proxy) flags.Add("代理");
        if (Tor) flags.Add("Tor");
        if (Crawler) flags.Add("爬虫");
        if (Abuser) flags.Add("有滥用记录");
        if (Mismatch(target)) flags.Add("Claude 侧出口为 " + CountryCode!.ToUpperInvariant());

        var detail = "信任分 " + (TrustScore?.ToString() ?? "未知");
        if (flags.Count > 0) detail += " · " + string.Join(" · ", flags);
        if (Verdict is { Length: > 0 }) detail += " · AI 判定 " + Verdict + (Confidence is { } c ? " " + c + "%" : "");

        // Data centre, VPN, proxy, Tor, abuse history, low trust or a different Claude-side country
        // all raise the chance of verification prompts. The row is a warning; the gate reads Verdict.
        var verdict = Judge(target);
        return new CheckItem("IP 风险", verdict == RiskVerdict.Pass ? "info" : "warn", detail);
    }
}

public static class IpRisk
{
    // The address that reaches Claude, not the address that reaches a generic IP echo service.
    public const string TraceUrl = "https://claude.ai/cdn-cgi/trace";
    public const string LookupPrefix = "https://ip.net.coffee/api/iprisk/";
    public static string LookupUrl(string ip) => LookupPrefix + Uri.EscapeDataString(ip);

    public static async Task<IpRiskReport> LookupAsync(HttpClient http, CancellationToken ct)
    {
        using (var traceBudget = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            traceBudget.CancelAfter(TimeSpan.FromSeconds(4));
            string trace = await http.GetStringAsync(TraceUrl, traceBudget.Token);
            string ip = TraceValue(trace, "ip");
            if (ip.Length == 0) throw new CheckFailed("IP 风险", "无法确认 Claude 侧出口地址");
            using var riskBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            riskBudget.CancelAfter(TimeSpan.FromSeconds(6));
            string json = await http.GetStringAsync(LookupUrl(ip), riskBudget.Token);
            return Parse(ip, TraceValue(trace, "loc"), json);
        }
    }

    public static string TraceValue(string trace, string key)
    {
        foreach (var line in trace.Split('\n'))
        {
            int split = line.IndexOf('=');
            if (split > 0 && line.AsSpan(0, split).SequenceEqual(key)) return line[(split + 1)..].Trim();
        }
        return "";
    }

    public static IpRiskReport Parse(string ip, string? traceCountry, string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new CheckFailed("IP 风险", "风险接口返回了无法识别的内容");

        string? Text(string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        int? Number(string name) => root.TryGetProperty(name, out var value) && value.TryGetInt32(out int parsed) ? parsed : null;
        bool Flag(string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

        string? verdict = null, reasoning = null;
        int? confidence = null;
        if (root.TryGetProperty("ai_verdict", out var ai) && ai.ValueKind == JsonValueKind.Object)
        {
            if (ai.TryGetProperty("label", out var label) && label.ValueKind == JsonValueKind.String) verdict = label.GetString();
            if (ai.TryGetProperty("confidence", out var score) && score.TryGetInt32(out int parsed)) confidence = parsed;
            if (ai.TryGetProperty("reasoning", out var reason) && reason.ValueKind == JsonValueKind.String) reasoning = reason.GetString();
        }

        return new IpRiskReport(ip, traceCountry, Text("countryCode"), Number("trust_score"), verdict, confidence, reasoning,
            Flag("is_datacenter"), Flag("is_vpn"), Flag("is_proxy"), Flag("is_tor"), Flag("is_crawler"),
            Flag("is_abuser"), Flag("isResidential"), Text("asOrganization"));
    }
}
