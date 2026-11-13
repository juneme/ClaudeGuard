namespace ClaudeGuard;

// The UI owns the lifetime; the service remains the sole authority for connection protection.
public interface IGuardServiceRuntime
{
    bool IsRunning { get; }
    bool IsActive { get; }
    bool TryStart();
    Task<Response?> WaitForStatusAsync(TimeSpan duration, CancellationToken ct);
    Task PrepareAsync(CancellationToken ct);
    Task<Response> RequestStopAsync(CancellationToken ct);
}

public static class GuardLifecycle
{
    // Bumped whenever the wire contract or service behaviour changes. Anything older is replaced
    // before use; the app never runs against a service it does not recognise.
    // v7 retries unconfirmed isolation before recovery, and keeps probe faults inside the
    // monitor. Older service behaviour must be replaced together with the new launcher UI.
    // v8 requires installer migration of the legacy scheduled process-killing guard.
    public const int RequiredProtocol = 8;

    // Connects, and replaces a missing or outdated service in place. The installer stops the old
    // service first, so there are never two guards running at once.
    public static async Task<Response> EnsureAsync(IGuardServiceRuntime runtime, CancellationToken ct)
    {
        bool present = runtime.IsRunning || runtime.TryStart();
        var status = present ? await runtime.WaitForStatusAsync(TimeSpan.FromSeconds(4), ct) : null;
        if (status != null && status.Protocol >= RequiredProtocol) return status;
        await runtime.PrepareAsync(ct);
        status = await runtime.WaitForStatusAsync(TimeSpan.FromSeconds(10), ct);
        if (status is null || status.Protocol < RequiredProtocol) throw new IOException("守护服务更新后仍无法连接，请重试");
        return status;
    }

    // Forces a reinstall even when the running service looks compatible.
    public static async Task<Response> InstallAsync(IGuardServiceRuntime runtime, CancellationToken ct)
    {
        await runtime.PrepareAsync(ct);
        var status = await runtime.WaitForStatusAsync(TimeSpan.FromSeconds(10), ct);
        if (status is null || status.Protocol < RequiredProtocol) throw new IOException("安装后仍无法连接守护服务，请重试");
        return status;
    }

    public static async Task StopAsync(IGuardServiceRuntime runtime, CancellationToken ct)
    {
        if (runtime.IsRunning)
        {
            var response = await runtime.RequestStopAsync(ct);
            if (response.Protocol < RequiredProtocol || response.Phase != "stopping") throw new IOException("Service refused to stop");
        }
        var until = DateTime.UtcNow.AddSeconds(10);
        while (runtime.IsActive && DateTime.UtcNow < until) await Task.Delay(200, ct);
        if (runtime.IsActive) throw new IOException("Service did not stop");
    }
}
