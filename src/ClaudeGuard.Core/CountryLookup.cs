using System.Net.Http;

namespace ClaudeGuard;

public static class CountryLookup
{
    private const string Primary = "https://www.cloudflare.com/cdn-cgi/trace";
    private const string Fallback = "https://1.1.1.1/cdn-cgi/trace";

    public static async Task<string> QueryAsync(HttpClient http, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        // Start both requests together, but retain the original primary-first preference.
        Task<string?> primary = ReadAsync(http, Primary, budget.Token);
        Task<string?> fallback = ReadAsync(http, Fallback, budget.Token);
        try
        {
            string? country = await primary;
            if (country == null) country = await fallback;
            ct.ThrowIfCancellationRequested();
            return country ?? throw new CheckFailed("出口地区", "暂时无法确认出口地区，请检查代理连接后重试");
        }
        finally { budget.Cancel(); }
    }

    private static async Task<string?> ReadAsync(HttpClient http, string url, CancellationToken ct)
    {
        try
        {
            string text = await http.GetStringAsync(url, ct);
            string? country = text.Split('\n').FirstOrDefault(x => x.StartsWith("loc=", StringComparison.Ordinal))?[4..].Trim();
            return country is { Length: 2 } && country.All(char.IsAsciiLetterUpper) ? country : null;
        }
        catch (HttpRequestException) { return null; }
        catch (OperationCanceledException) { return null; }
        catch (IOException) { return null; }
    }
}
