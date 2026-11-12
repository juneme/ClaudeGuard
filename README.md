# ClaudeGuard 3.0.1

Windows 10/11 x64 上的 Claude 桌面连接守护。统一的 C# / .NET 10 源码：WPF 界面、核心库、Windows 服务和回归测试。

## 使用

运行 `ClaudeGuard-3.0.1-win-x64.exe`，无需预装 .NET。可从 [GitHub Releases](https://github.com/juneme/ClaudeGuard/releases/latest) 下载安装包，或按下文自行构建；源码仓库不包含 EXE。先自行连接 Clash Verge，并开启 TUN、auto-route 和 strict-route；打开程序选择目标地区，点击「开始检测」，检查通过后启动 Claude。

首次打开会请求管理员授权，将内嵌服务安装到 `Program Files\ClaudeGuard`。连接保护未建立时会尝试一次自动修复，也可手动点击「修复连接」。关闭窗口会隐藏到托盘；托盘退出会停止守护，并让受保护的 Claude 保持隔离。再次打开并检测通过后恢复。

## 保留的功能

- 检测 Clash Verge、TUN、出口地区和 Claude 专用防火墙规则。
- 45 秒一次性启动许可，服务持续巡检；异常时隔离联网并保留 Claude 进程，条件恢复后重新检查。
- 「出口与风险」页面展示 Claude 侧出口与 IP 风险；高风险默认阻止启动，显式确认可覆盖风险项，不能绕过代理、出口和连接保护检查。
- 自动发现官方 Claude 客户端、托盘驻留、服务安装与升级。

风险查询会将 Claude 侧出口 IP 发送给第三方 `ip.net.coffee`。查询失败只显示提示；程序不修改代理配置、系统时区或区域格式。守护采用轮询，无法保证异常发生瞬间即切断既有连接。

## 构建与测试

开发需要 .NET 10 SDK 和 Python 3；自包含发布需还原 Windows 运行时包。

```powershell
dotnet run --project tests/ClaudeGuard.Tests -c Release
python scripts/build.py
python scripts/gen-sums.py --check
```

构建脚本先发布服务，再将服务 exe 嵌入界面程序，输出 `build/ClaudeGuard-3.0.1-win-x64.exe`。可用 `--dotnet <路径>` 指定 SDK、`--source <目录>` 指定离线 NuGet 源、`--output-root <目录>` 指定产物目录。源码修改后运行 `python scripts/gen-sums.py` 更新清单。

## 目录

```text
src/ClaudeGuard.App       界面、托盘与安装入口
src/ClaudeGuard.Core      协议、检查协调器、防火墙与风险判定
src/ClaudeGuard.Service   后台探测与守护
tests/ClaudeGuard.Tests   隔离回归测试
scripts/                 构建与源码校验
```

## 项目范围与验证边界

本项目专注 Windows 连接守护，不包含旧版账号快照切换功能。回归测试用于验证协调器、授权、风险判定、防火墙封装和服务升级等逻辑；通过编译和隔离测试不代表已完成真实安装、真实流量拦截或 Claude 启动端到端验收。

卸载服务：以管理员身份运行 `ClaudeGuard-3.0.1-win-x64.exe --uninstall-service`，移除服务及专用规则，保留安装目录文件。

## 在其他电脑维护

安装 Git、.NET 10 SDK 和 Python 3 后，克隆本仓库：

```powershell
git clone https://github.com/juneme/ClaudeGuard.git
cd ClaudeGuard
dotnet run --project tests/ClaudeGuard.Tests -c Release
python scripts/build.py
```

只需使用程序时，从 [Releases](https://github.com/juneme/ClaudeGuard/releases/latest) 下载 `ClaudeGuard-3.0.1-win-x64.exe` 即可。源码仓库保留测试、构建脚本和许可证；编译缓存、本机状态及凭据由 `.gitignore` 排除。仓库为私有，在其他电脑需要登录有权限的 GitHub 账号。

修改源码后先运行测试和构建，再执行 `python scripts/gen-sums.py` 更新源码校验清单，然后提交和推送。安装包单独上传到 GitHub Releases。

## 许可与来源

AGPL-3.0-only，完整条款见 LICENSE。基于 [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)，保留原作者与贡献者署名。
