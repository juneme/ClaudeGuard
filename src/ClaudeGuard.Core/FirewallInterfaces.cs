namespace ClaudeGuard;

public sealed record FirewallInterface(string Id, string Name, bool IsLoopback, bool SupportsIpv4, bool SupportsIpv6);

public static class FirewallInterfaces
{
    // Every IP-capable adapter except the tunnel itself and loopback: traffic may only leave
    // through the proxy tunnel, so the physical paths are the ones that must be blocked.
    public static string[] Select(IEnumerable<FirewallInterface> interfaces, string tunnelId) => interfaces
        .Where(n => n.Id != tunnelId && !n.IsLoopback && (n.SupportsIpv4 || n.SupportsIpv6))
        .Select(n => n.Name).Order(StringComparer.Ordinal).ToArray();
}
