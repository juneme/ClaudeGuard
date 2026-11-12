namespace ClaudeGuard;

public static class ServiceUpgrade
{
    public static async Task WaitForExitAsync(Func<bool> serviceActive, Func<bool> processExited, TimeSpan timeout, CancellationToken ct = default)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (serviceActive() || !processExited())
        {
            if (DateTime.UtcNow >= deadline) throw new IOException("Service shutdown timed out");
            // Installer.Install calls this from WPF startup with GetAwaiter().GetResult().
            // Never capture its dispatcher, which is blocked until this wait completes.
            await Task.Delay(100, ct).ConfigureAwait(false);
        }
    }
    public static string FailureMessage(int code)
    {
        int stage = code > 65535 ? code >> 16 : code;
        string detail = stage switch
    {
        10 => "旧守护尚未完全退出，暂时无法更新",
        11 => "无法备份旧程序目录，可能有文件仍被占用",
        12 => "无法写入新守护文件，请检查磁盘空间和目录权限",
        13 => "无法更新 Windows 服务注册信息",
        14 => "无法配置守护的启动权限",
        15 => "新守护未能启动，请检查 Windows 服务记录",
        16 => "无法创建程序快捷方式",
        _ => "守护准备失败，请检查程序完整性或管理员权限"
        };
        return code > 65535 ? detail + $"（Windows 错误码 {code & 65535}，步骤 {stage}）" : detail;
    }
}
