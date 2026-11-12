using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace ClaudeGuard;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer poll = new() { Interval = TimeSpan.FromSeconds(3) };
    private readonly CancellationTokenSource lifetime = new();
    private readonly IGuardServiceRuntime service;
    private readonly System.Windows.Forms.NotifyIcon? tray;
    private bool busy, polling, startingService, quitting, initializing = true, autoRepairTried;
    private int displayEpoch;
    private string checkedPath = "", checkedCountry = "";
    private Response? latest;
    private readonly string settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClaudeGuard", "ui.json");
    private sealed record Preferences(string AppPath, string Country);
    public MainWindow()
    {
        InitializeComponent();
        service = new GuardServiceRuntime();
        CountryBox.ItemsSource = RegionPolicy.Targets;
        CountryBox.SelectedItem = "US";
        try
        {
            var settings = JsonSerializer.Deserialize<Preferences>(File.ReadAllText(settingsPath));
            if (settings != null && RegionPolicy.IsTarget(settings.Country)) CountryBox.SelectedItem = settings.Country;
        }
        catch { }
        ClaudePath.Text = ClaudeLocator.Find();
        ControllerSecret.Password = FindControllerSecret();
        tray = new System.Windows.Forms.NotifyIcon { Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? System.Drawing.SystemIcons.Shield, Text = "ClaudeGuard · 连接守护", Visible = true };
        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("打开窗口", null, (_, _) => Dispatcher.Invoke(ShowWindow));
        menu.Items.Add("退出程序并停止守护", null, async (_, _) => await Dispatcher.InvokeAsync(QuitAsync).Task.Unwrap());
        tray.ContextMenuStrip = menu; tray.DoubleClick += (_, _) => Dispatcher.Invoke(ShowWindow);
        poll.Tick += async (_, _) => await PollAsync();
        Loaded += async (_, _) => { poll.Start(); await StartServiceAsync(); };
        ShowPage(false);
        initializing = false;
    }
    private async Task PollAsync()
    {
        if (busy || polling || startingService || quitting) return;
        polling = true;
        int epoch = displayEpoch;
        try
        {
            var response = await PipeClient.SendAsync(new("status"), lifetime.Token);
            if (busy || quitting || epoch != displayEpoch) return;
            if (response.Protocol < GuardLifecycle.RequiredProtocol) { ShowOffline("守护版本需要更新，请重试启动守护。"); return; }
            if (checkedPath.Length == 0 && response.Ready) response = response with { Ready = false, Message = "窗口已重新打开，请先检测本次启动条件" };
            Display(response); ServiceLabel.Text = "●  守护服务运行中";
        }
        catch { if (!busy && !quitting && epoch == displayEpoch) ShowOffline(); }
        finally { polling = false; }
    }
    private void ShowOffline(string message = "守护未能启动，请检查 Windows 管理员授权后重试。")
    {
        Display(new("offline", message, []));
        ServiceLabel.Text = "○  守护服务未连接";
    }
    private async Task StartServiceAsync(bool install = false)
    {
        if (startingService || busy || quitting) return;
        startingService = true; displayEpoch++; SetBusy(true);
        Display(new("starting", install ? "正在安装后台守护，Windows 会请求管理员授权。" : "正在连接后台守护（旧版本会就地替换）…", []));
        ServiceLabel.Text = "◌  正在启动守护";
        // Elevation can be invisible (prompt behind the window) or never answered. Bound it so the
        // window can never sit disabled forever waiting on a process that will not exit.
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        attempt.CancelAfter(TimeSpan.FromMinutes(2));
        try
        {
            var work = install ? GuardLifecycle.InstallAsync(service, attempt.Token) : GuardLifecycle.EnsureAsync(service, attempt.Token);
            // The replace step needs one Windows consent prompt; say so instead of looking frozen.
            if (await Task.WhenAny(work, Task.Delay(TimeSpan.FromSeconds(7), lifetime.Token)) != work)
                StatusDetail.Text = "正在等待管理员授权以替换旧版守护…如果没有看到授权窗口，请查看任务栏。";
            var status = await work;
            if (checkedPath.Length == 0 && status.Ready) status = status with { Ready = false, Message = "请先检测本次启动条件" };
            Display(status); ServiceLabel.Text = "●  守护服务运行中";
            ServiceSetupButton.Content = "重试启动守护";
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223) { ShowOffline("Windows 管理员授权已取消，点击重试后允许授权即可。"); ServiceSetupButton.Content = "重试启动守护"; }
        catch (Win32Exception error) { ShowOffline($"Windows 无法启动守护准备程序（错误码 {error.NativeErrorCode}）"); ServiceSetupButton.Content = "重试启动守护"; }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (OperationCanceledException) { ShowOffline("准备守护超时：管理员授权可能没有确认。点击「重试启动守护」再来一次。"); ServiceSetupButton.Content = "重试启动守护"; }
        catch (IOException error) { ShowOffline(error.Message); ServiceSetupButton.Content = "重试启动守护"; }
        catch { ShowOffline("守护未能启动，请检查管理员授权或程序安装状态后重试。"); ServiceSetupButton.Content = "重试启动守护"; }
        finally { startingService = false; SetBusy(false); }
    }
    private static async Task<Response?> WaitForServiceAsync(TimeSpan duration, CancellationToken ct)
    {
        var until = DateTime.UtcNow + duration;
        while (DateTime.UtcNow < until)
        {
            ct.ThrowIfCancellationRequested();
            try { return await PipeClient.SendAsync(new("status"), ct); }
            catch (ServiceUnavailableException) { }
            catch (IOException) { }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            await Task.Delay(250, ct);
        }
        return null;
    }
    private sealed class GuardServiceRuntime : IGuardServiceRuntime
    {
        public bool IsRunning => Native.ServicePid() != 0;
        public bool IsActive => Native.ServiceActive();
        public bool TryStart() => Native.TryStartService();
        public Task<Response?> WaitForStatusAsync(TimeSpan duration, CancellationToken ct) => WaitForServiceAsync(duration, ct);
        public async Task PrepareAsync(CancellationToken ct)
        {
            var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            info.ArgumentList.Add("--prepare-service"); info.ArgumentList.Add(WindowsIdentity.GetCurrent().User!.Value);
            using var process = Process.Start(info) ?? throw new IOException("Service setup did not start");
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromSeconds(45));
            try { await process.WaitForExitAsync(budget.Token); }
            catch (OperationCanceledException)
            {
                try { process.Kill(); } catch { }
                throw new IOException("替换守护服务超时：管理员授权未确认或被拒绝，请点击「重试启动守护」再试");
            }
            if (process.ExitCode != 0) throw new IOException(ServiceUpgrade.FailureMessage(process.ExitCode));
        }
        public Task<Response> RequestStopAsync(CancellationToken ct) => PipeClient.SendAsync(new("shutdown"), ct);
    }
    private async Task CheckAsync(bool repair)
    {
        if (busy || startingService) return;
        displayEpoch++;
        ClaudePath.Text = ClaudeLocator.Find();
        if (ClaudePath.Text.Length == 0)
        {
            checkedPath = ""; SettingsPanel.IsExpanded = true;
            Display(new("blocked", "没有找到 Claude 桌面客户端，请先安装后重新检测。", [new("Claude 客户端", "fail", "未找到默认安装位置")]));
            return;
        }
        busy = true; SetBusy(true);
        try
        {
            checkedPath = ClaudePath.Text; checkedCountry = CountryBox.SelectedItem as string ?? "";
            Display(new("checking", repair ? "先确认代理与出口，再修复连接保护…" : "正在确认代理、出口与连接保护…", []));
            var response = await PipeClient.SendAsync(new(repair ? "repair" : "check", checkedCountry, ControllerSecret.Password, checkedPath), lifetime.Token);
            if (response.Protocol < GuardLifecycle.RequiredProtocol) { ShowOffline("守护版本需要更新，请重试启动守护。"); return; }
            Display(response);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(settingsPath)!);
                File.WriteAllText(settingsPath, JsonSerializer.Serialize(new Preferences(checkedPath, checkedCountry)));
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        catch (ServiceUnavailableException) { ShowOffline(); }
        catch { Display(new("blocked", "检查未完成，请确认服务已安装、Clash Verge 已连接后重试", [])); }
        finally { busy = false; SetBusy(false); }
    }
    private void SetBusy(bool value)
    {
        CheckButton.IsEnabled = RepairButton.IsEnabled = CountryBox.IsEnabled = !value;
        ControllerSecret.IsEnabled = !value;
        RiskCheckButton.IsEnabled = !value;
        ForceButton.IsEnabled = !value;
        LaunchButton.IsEnabled = !value && CanLaunch(latest);
    }
    private static bool CanLaunch(Response? response) =>
        response is { Ready: true, LaunchUsed: false } && response.Verdict != RiskVerdict.Block;
    private void Display(Response response)
    {
        latest = response;
        bool blockedByRisk = response.Phase == "ready" && response.Verdict == RiskVerdict.Block;
        StatusTitle.Text = blockedByRisk ? "出口有风险。" : response.Phase switch { "ready" => "一切就绪。", "starting" => "正在启动守护…", "checking" => "正在确认连接…", "reconnecting" => "暂时断网，等待重连", "offline" => "守护未启动", "blocked" => "需要一点处理", _ => "准备好，再出发" };
        StatusDetail.Text = response.Message;
        ServiceSetupButton.Visibility = response.Phase == "offline" ? Visibility.Visible : Visibility.Collapsed;
        StatusSymbol.Text = blockedByRisk ? "!" : response.Ready ? "✓" : response.Phase == "checking" ? "◌" : "◈";
        ApplyStatusTone(blockedByRisk || response.Phase is "blocked" or "reconnecting", response.Ready && !blockedByRisk);
        LastChecked.Text = response.LastChecked is { } stamp ? "服务最近确认于 " + stamp.ToLocalTime().ToString("HH:mm:ss") + " · 后台持续守护" : "等待本次检测";
        var checks = response.Checks.Count > 0 ? response.Checks : [new CheckItem("Clash Verge", "idle", "等待确认客户端与 TUN"), new("出口地区", "idle", "代理就绪后检测"), new("连接保护", "idle", "出口一致后检查")];
        ChecksList.ItemsSource = checks.Select(c => new { c.Title, c.Detail, Symbol = c.State == "ok" ? "✓" : c.State == "fail" ? "!" : c.State == "warn" ? "▲" : "·", Color = Tone(c.State) }).ToArray();
        LaunchHint.Text = response.Ready
            ? response.LaunchUsed ? "再次启动前请重新检测"
            : response.Verdict == RiskVerdict.Block ? "出口风险过高，需强制启动"
            : response.Verdict == RiskVerdict.Warn ? "出口有提示项，可以启动"
            : "连接已确认，可以启动"
            : response.Phase switch
            {
                "starting" => "正在准备守护",
                "checking" => "检测完成后可启动",
                "offline" => "守护启动后可进行检测",
                _ when response.Checks.Any(c => c.Title == "连接保护" && c.State == "fail") => "请先修复连接保护",
                _ => "检测通过后可启动"
            };
        LaunchButton.IsEnabled = CanLaunch(response) && !busy;
        RenderRisk(response);
        // A repairable failure repairs itself once; the user can still retry by hand afterwards.
        if (!busy && !startingService && !autoRepairTried && response.Phase == "blocked"
            && response.Checks.Any(c => c.Title == "连接保护" && c.State == "fail"))
        {
            autoRepairTried = true;
            StatusDetail.Text = response.Message + "（已自动开始修复…）";
            _ = Dispatcher.InvokeAsync(async () => { await Task.Delay(700); if (!busy && !startingService) await CheckAsync(true); });
        }
    }
    private static string Tone(string state) => state switch
    {
        "ok" => "#67825A",
        "fail" => "#B56B54",
        "warn" => "#B07A2E",
        _ => "#A4A79F"
    };
    private static Brush Brush(string hex) => (Brush)new BrushConverter().ConvertFromString(hex)!;
    private void ApplyStatusTone(bool attention, bool ready)
    {
        var (surface, border, badge, ink) = attention ? ("#FBF0E3", "#EFDFC8", "#F6E2C8", "#A9741F")
            : ready ? ("#EDF1EA", "#E1E7DC", "#DCE6D6", "#5A7654")
            : ("#F1F1EE", "#E6E6E2", "#E7E7E2", "#7B7D76");
        StatusCard.Background = Brush(surface); StatusCard.BorderBrush = Brush(border);
        StatusBadge.Background = Brush(badge); StatusSymbol.Foreground = Brush(ink);
    }
    private sealed record RiskRow(string Title, string Actual, string Expected, string Verdict, string Color);
    private void RenderRisk(Response response)
    {
        string target = response.Country is { Length: 2 } ? response.Country : checkedCountry;
        RiskTarget.Text = "目标地区 " + (target.Length == 2 ? target : "—");
        ForceButton.Visibility = response.Ready && response.Verdict == RiskVerdict.Block && !response.LaunchUsed ? Visibility.Visible : Visibility.Collapsed;
        var risk = response.Risk;
        if (risk is null)
        {
            RiskSymbol.Text = "◈";
            RiskTitle.Text = response.Phase == "checking" ? "正在核对出口风险…" : "尚未取得出口数据";
            RiskDetail.Text = response.Phase == "checking"
                ? "正在向 claude.ai 与 ip.net.coffee 查询当前出口。"
                : "完成一次检测后，这里会显示 Claude 侧出口的信任分与属性判定。";
            RiskIp.Text = "—"; RiskGeo.Text = "—";
            RiskCard.Background = Brush("#F1F1EE"); RiskCard.BorderBrush = Brush("#E6E6E2");
            RiskBadge.Background = Brush("#E7E7E2"); RiskSymbol.Foreground = Brush("#7B7D76");
            RiskRows.ItemsSource = null;
            return;
        }
        var verdict = risk.Judge(target);
        var (title, detail, surface, border, badge, ink) = verdict switch
        {
            RiskVerdict.Block => ("出口不适合启动。",
                "该出口被标记为高风险，启动后更容易触发 Claude 的验证或限制。建议更换节点后重新检测。",
                "#FBE9E4", "#F0D6CC", "#F5DACF", "#A24A32"),
            RiskVerdict.Warn => ("出口有提示项。",
                "可以启动，但该出口的属性可能让 Claude 更容易要求验证。",
                "#FBF0E3", "#EFDFC8", "#F6E2C8", "#A9741F"),
            _ => ("出口干净。",
                "出口属性与目标地区一致，没有发现代理或滥用标记。",
                "#EDF1EA", "#E1E7DC", "#DCE6D6", "#5A7654")
        };
        RiskTitle.Text = title; RiskDetail.Text = detail;
        RiskCard.Background = Brush(surface); RiskCard.BorderBrush = Brush(border);
        RiskBadge.Background = Brush(badge); RiskSymbol.Foreground = Brush(ink);
        RiskSymbol.Text = verdict == RiskVerdict.Pass ? "✓" : "!";
        RiskIp.Text = risk.Ip;
        RiskGeo.Text = string.Join(" · ", new[] { risk.CountryCode?.ToUpperInvariant(), risk.AsnOrganization }.Where(x => !string.IsNullOrWhiteSpace(x)));
        bool countryOk = !risk.Mismatch(target);
        var marks = new List<string>();
        if (risk.Vpn) marks.Add("VPN");
        if (risk.Proxy) marks.Add("代理");
        if (risk.Tor) marks.Add("Tor");
        if (risk.Crawler) marks.Add("爬虫");
        RiskRows.ItemsSource = new List<RiskRow>
        {
            new("出口国家", risk.CountryCode?.ToUpperInvariant() ?? "未知", target is { Length: 2 } t ? t : "—", countryOk ? "一致" : "不一致", countryOk ? "#67825A" : "#B56B54"),
            new("信任分", risk.TrustScore?.ToString() ?? "未知", "≥ 50", risk.TrustScore is < 25 ? "高危" : risk.TrustScore is < 50 ? "偏低" : risk.TrustScore is null ? "未知" : "良好",
                risk.TrustScore is < 25 ? "#B56B54" : risk.TrustScore is < 50 ? "#B07A2E" : risk.TrustScore is null ? "#A4A79F" : "#67825A"),
            new("IP 属性", risk.Datacenter ? "机房" : risk.Residential ? "住宅" : "未知", "住宅优先", risk.Datacenter ? "注意" : risk.Residential ? "通过" : "未知", risk.Datacenter ? "#B07A2E" : risk.Residential ? "#67825A" : "#A4A79F"),
            new("代理标记", marks.Count > 0 ? string.Join(" / ", marks) : "无", "无", marks.Count > 0 ? "注意" : "通过", marks.Count > 0 ? "#B07A2E" : "#67825A"),
            new("滥用记录", risk.Abuser ? "有" : "无", "无", risk.Abuser ? "阻止" : "通过", risk.Abuser ? "#B56B54" : "#67825A"),
            new("AI 判定", risk.Verdict is { Length: > 0 } label ? label + (risk.Confidence is { } c ? $" {c}%" : "") : "无数据", "—",
                risk.Verdict is "Clean" or "" or null ? "通过" : "注意",
                risk.Verdict is "Clean" or "" or null ? "#67825A" : "#B07A2E"),
            new("运营商", risk.AsnOrganization ?? "未知", "—", "—", "#A4A79F")
        };
    }
    private async void LaunchClick(object sender, RoutedEventArgs e) => await LaunchAsync(false);
    private async void ForceClick(object sender, RoutedEventArgs e) => await LaunchAsync(true);
    private async Task LaunchAsync(bool force)
    {
        if (busy || latest?.Ready != true) return;
        if (force && MessageBox.Show(
            "该出口 IP 已被判定为高风险，强制启动可能触发 Claude 的验证或限制。\n\n仍然继续吗？",
            "强制启动", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        busy = true; SetBusy(true);
        try
        {
            if (checkedPath != ClaudePath.Text || checkedPath != ClaudeLocator.Find() || checkedCountry != (CountryBox.SelectedItem as string)) throw new IOException();
            var grant = await PipeClient.SendAsync(new("permit", Force: force), lifetime.Token);
            if (grant.Protocol < GuardLifecycle.RequiredProtocol) { ShowOffline("守护版本需要更新，请重试启动守护。"); return; }
            if (!grant.Ready || grant.Ticket.Length == 0) { Display(grant); return; }
            Process.Start(new ProcessStartInfo(checkedPath) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(checkedPath)! });
            Display(grant with { LaunchUsed = true, Message = force ? "已强制启动 Claude，后台继续守护连接" : "Claude 已启动，后台正在持续守护连接", Ticket = "" });
        }
        catch { Display(new("blocked", "启动未完成，请重新检测后重试", [])); }
        finally { busy = false; SetBusy(false); }
    }
    private void ShowOverview(object sender, RoutedEventArgs e) => ShowPage(false);
    private void ShowRisk(object sender, RoutedEventArgs e) => ShowPage(true);
    private void ShowPage(bool risk)
    {
        RiskPage.Visibility = risk ? Visibility.Visible : Visibility.Collapsed;
        OverviewPage.Visibility = risk ? Visibility.Collapsed : Visibility.Visible;
        OverviewBg.Background = risk ? Brushes.Transparent : Brush("#DFE4DE");
        RiskBg.Background = risk ? Brush("#DFE4DE") : Brushes.Transparent;
        OverviewText.Foreground = Brush(risk ? "#6F746C" : "#3F5C49");
        RiskText.Foreground = Brush(risk ? "#3F5C49" : "#6F746C");
        OverviewText.FontWeight = risk ? FontWeights.Normal : FontWeights.SemiBold;
        RiskText.FontWeight = risk ? FontWeights.SemiBold : FontWeights.Normal;
        OverviewDot.Text = risk ? "○" : "◉";
        RiskDot.Text = risk ? "◉" : "○";
        NavHint.Text = risk ? "出口数据 · 对比 · 判定" : "检测 · 修复 · 启动";
    }
    private async void CheckClick(object sender, RoutedEventArgs e) { autoRepairTried = false; await CheckAsync(false); }
    private async void RepairClick(object sender, RoutedEventArgs e) { autoRepairTried = false; await CheckAsync(true); }
    private void InputsChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) => InvalidateInputs();
    private void SecretChanged(object sender, RoutedEventArgs e) => InvalidateInputs();
    private void InvalidateInputs() { if (!initializing && !busy) { displayEpoch++; checkedPath = ""; Display(new("idle", "设置已变化，请重新检测", [])); } }
    private async void RetryService(object sender, RoutedEventArgs e)
    {
        await StartServiceAsync(true);
    }
    private static string FindControllerSecret()
    {
        // Read only the explicitly named controller scalar. Never copy or log the profile.
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "io.github.clash-verge-rev.clash-verge-rev");
        foreach (string name in new[] { "clash-verge.yaml", "config.yaml" })
        {
            try
            {
                string file = Path.Combine(root, name);
                if (new FileInfo(file).Length > 4 * 1024 * 1024) continue;
                var line = File.ReadLines(file).FirstOrDefault(l => l.StartsWith("secret:", StringComparison.Ordinal));
                if (line != null) return line[7..].Trim().Trim('\'', '"');
            }
            catch { }
        }
        return "";
    }
    private void DragTitle(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2 && e.GetPosition(this).Y <= 70) MaximizeClick(sender, e);
        else if (e.ClickCount == 1 && e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
    private void MinimizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void MaximizeClick(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void CloseClick(object sender, RoutedEventArgs e) => Hide();
    internal void ShowWindow() { Show(); WindowState = WindowState.Normal; Activate(); }
    private async Task QuitAsync()
    {
        if (quitting) return;
        if (startingService) { ShowWindow(); StatusDetail.Text = "守护正在启动，请完成管理员授权后再退出。"; return; }
        if (busy) { ShowWindow(); StatusDetail.Text = "检测尚未结束，请稍后再退出。"; return; }
        quitting = true; poll.Stop();
        try
        {
            await GuardLifecycle.StopAsync(service, lifetime.Token);
            lifetime.Cancel(); tray?.Dispose(); System.Windows.Application.Current.Shutdown();
        }
        catch
        {
            quitting = false; poll.Start(); ShowWindow();
            Display(new("blocked", "暂时无法停止守护，程序仍在运行。请稍后从托盘重新退出。", []));
        }
    }
    protected override void OnClosing(CancelEventArgs e) { if (!quitting) { e.Cancel = true; Hide(); } base.OnClosing(e); }
}
