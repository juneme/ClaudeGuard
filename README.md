# ClaudeGuard 3.0.3

Windows 10/11 x64 上的 Claude 桌面连接守护。统一的 C# / .NET 10 源码：WPF 界面、核心库和 Windows 服务。

## 使用

运行 `ClaudeGuard-win-x64.exe`，无需预装 .NET。可从 [GitHub Releases](https://github.com/juneme/ClaudeGuard/releases/latest) 下载安装包，或按下文自行构建；源码仓库不包含 EXE。先自行连接 Clash Verge，并开启 TUN、auto-route 和 strict-route；打开程序选择目标地区，点击「开始检测」，检查通过后启动 Claude。

升级会先核对当前用户的旧版 `ClaudeBodyguard` 计划任务，停用、停止并移除后再安装新服务；新旧守护不能同时运行。该迁移仅匹配当前用户配置目录中的 `claude-bodyguard.ps1`，不修改账号数据或其他任务。

首次打开会请求管理员授权，将内嵌服务安装到 `Program Files\ClaudeGuard`。连接保护未建立时会尝试一次自动修复，也可手动点击「修复连接」。关闭窗口会隐藏到托盘；托盘退出会停止守护，并让受保护的 Claude 保持隔离。再次打开并检测通过后恢复。

## 保留的功能

- 检测 Clash Verge、TUN、出口地区和 Claude 专用防火墙规则。
- 45 秒一次性启动许可，服务持续巡检；异常时隔离联网并保留 Claude 进程，条件恢复后重新检查。
- 「出口与风险」页面展示 Claude 侧出口与 IP 风险；高风险默认阻止启动，显式确认可覆盖风险项，不能绕过代理、出口和连接保护检查。
- 自动发现官方 Claude 客户端、托盘驻留、服务安装与升级。
- Microsoft Store/MSIX 客户端按已校验路径匹配包清单，再通过 Windows AUMID 正式激活；普通安装版通过 Shell 启动。不直接运行 MSIX 包内 EXE，不结束或自动重启 Claude。启动后 30 秒内退出会显示退出码。

风险查询会将 Claude 侧出口 IP 发送给第三方 `ip.net.coffee`。查询失败只显示提示；程序不修改代理配置、系统时区或区域格式。守护采用轮询，无法保证异常发生瞬间即切断既有连接。

## 构建

开发需要 .NET 10 SDK 和 Python 3；自包含发布需还原 Windows 运行时包。

```powershell
python scripts/build.py
python scripts/gen-sums.py --check
```

防火墙查询的 `0x80070002` 也可能只是指定规则尚不存在，不能据此判断 Windows 防火墙服务已停止。当前守护协议为 v8，包含规则缺失处理、完整隔离校验与隔离失败重试；新构建会要求替换旧版守护，避免新界面继续连接仍含旧错误的后台。仅重新编译界面或重复启动已安装的旧快捷方式不会更新服务；应从安装目录以外运行新生成的完整 EXE，并完成 Windows 管理员授权。

构建脚本先发布服务，再将服务 exe 嵌入界面程序，只输出 `build/ClaudeGuard-win-x64.exe` 与对应的 SHA256 文件。重复构建成功后替换这两个文件；失败时保留原安装包，临时发布目录自动删除，不生成 ZIP、展开包或历史备份。安装升级成功后会清理仅含程序生成文件的回滚目录；升级失败时先恢复旧程序，再清理失败版本。包含额外文件或重解析点的目录会保留。可用 `--dotnet <路径>` 指定 SDK、`--source <目录>` 指定离线 NuGet 源、`--output-root <目录>` 指定产物目录。源码修改后运行 `python scripts/gen-sums.py` 更新清单。

## 目录

```text
src/ClaudeGuard.App       界面、托盘与安装入口
src/ClaudeGuard.Core      协议、检查协调器、防火墙与风险判定
src/ClaudeGuard.Service   后台探测与守护
scripts/                 构建与源码校验
```

## 项目范围与验证边界

本项目专注 Windows 连接守护，不包含旧版账号快照切换功能。发布前应在 Windows 上验证安装与升级、连接检测、Claude 启动及隔离恢复；通过编译不代表已完成这些真机验收。

卸载服务：以管理员身份运行 `ClaudeGuard-win-x64.exe --uninstall-service`，移除服务及专用规则，保留安装目录文件。

## 在其他电脑维护

安装 Git、.NET 10 SDK 和 Python 3 后，克隆本仓库：

```powershell
git clone https://github.com/juneme/ClaudeGuard.git
cd ClaudeGuard
python scripts/build.py
```

只需使用程序时，从 [Releases](https://github.com/juneme/ClaudeGuard/releases/latest) 下载 `ClaudeGuard-win-x64.exe` 即可。源码仓库保留程序源码、构建脚本和许可证；编译缓存、本机状态及凭据由 `.gitignore` 排除。仓库为公开仓库，可以直接克隆源码。

修改源码后先构建并验证适用的功能，再执行 `python scripts/gen-sums.py` 更新源码校验清单，然后提交和推送。安装包单独上传到 GitHub Releases。

## 许可与来源

AGPL-3.0-only，完整条款见 LICENSE。基于 [YOURSJEYO/claude-switcher](https://github.com/YOURSJEYO/claude-switcher)，保留原作者与贡献者署名。
