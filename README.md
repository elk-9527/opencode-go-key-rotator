# Key Router

Key Router 把一组 **Base URL + API Key** 安全地批量写入多个 Windows 本地 AI 工具。工作流固定为：自动发现 → 预览 → 加密备份 → 写入 → 重新读取验证；任何一步失败都会尝试恢复原配置。

![Key Router 界面](docs/key-router-ui.png)

## 支持的工具

| 工具 | 写入位置 | 重要说明 |
|---|---|---|
| Hermes | `.env`、`config.yaml` | Windows 默认目录为 `%LOCALAPPDATA%\hermes`，支持 `HERMES_HOME` |
| Continue | `~/.continue/config.yaml` | 多模型时必须明确选择；`${{ secrets.NAME }}` 会保留引用并更新同目录 `.env` |
| dsh | `settings.yaml`、`.credentials.yaml` | 支持 `DSH_HOME`、手动选配置及提供商选择 |
| VS Code 自定义端点 | `chatLanguageModels.json`、SecretStorage | 密钥写入 Windows 加密的 VS Code SecretStorage |
| OpenCode for Copilot | `opencodego` / `opencodezen` 设置、SecretStorage | 扩展启用 BYOK 托管时不会直接覆盖 |
| DeepSeek for Copilot | `deepseek-copilot.baseUrl`、SecretStorage | 按扩展真实配置标识写入 |
| Xiaomi MiMo for Copilot | `mimo-copilot.baseUrl`、SecretStorage | 按扩展真实配置标识写入 |
| Claude Code | `~/.claude/settings.json` | 支持 `CLAUDE_CONFIG_DIR` |
| Pi | `~/.pi/agent/models.json` | 支持 `PI_CODING_AGENT_DIR`；不会覆盖 `auth.json`、环境变量或命令取密 |

## 使用方法

直接运行 `Key-Router.exe`：

1. 填写 Base URL 和 API Key；
2. 检查自动发现结果，并完成 Continue、dsh、OpenCode 或多套 VS Code 的必要选择；
3. 勾选目标并生成预览；
4. 核对将修改的文件和字段后再应用。

未安装的受支持工具会显示“安装”按钮。程序只接受内置白名单中的官方工具或 VS Code 扩展；安装位置必须在确认窗口中选择，下载、安装和安装后验证均绑定到该位置。

发布目录同时提供版本化文件和 `.sha256` 校验文件；v0.6.0 可用 `certutil -hashfile Key-Router-v0.6.0.exe SHA256` 核对完整性。当前本地构建未使用商业代码签名证书，Windows 可能显示未知发布者提示。

选择任何 VS Code 目标前请完全退出 VS Code。写入或安装期间，退出按钮会被禁用；即使强行关闭窗口，程序也会等待当前操作安全结束。

## 凭据优先级保护

Key Router 只修改当前工具真正会使用、且可安全轮换的凭据源：

- Continue 的标准 secrets 引用会被保留，只更新对应 `.env` 值；未知模板表达式会被拒绝；
- dsh 的进程环境变量优先于凭据文件，检测到覆盖时不会进行无效写入；
- Pi 的 `auth.json`、提供商环境变量、`!command` 和 `$ENV_VAR` 引用优先于 `models.json`，检测到这些来源时会显示“凭据托管”并停止覆盖；
- OpenCode for Copilot 的 BYOK 状态由扩展管理，Key Router 不与其争夺凭据所有权。

## 备份与恢复

- 每次正式应用前都会创建唯一备份目录；
- 备份内容和可信清单使用 Windows DPAPI 加密，只能由创建它的 Windows 用户解密；
- VS Code 的 SQLite WAL 数据库通过在线快照备份；
- 写入后会重新检测全部目标，验证失败即自动回滚；
- 如果自动回滚未完全成功，错误信息会给出备份目录和恢复命令。

手动恢复：

```powershell
.\Key-Router.exe --restore-backup "C:\Users\你的用户名\AppData\Local\Key Router\backups\具体备份目录"
```

恢复功能只接受 Key Router 备份根目录内的具体备份，并会先验证受保护清单和全部备份文件。

## 自动发现

- Hermes：`HERMES_HOME`、Windows 官方默认目录、PATH、开始菜单及安装记录；
- dsh：手动位置、`DSH_HOME`、默认目录、PATH、注册表、开始菜单及安装记录；
- VS Code：PATH、App Paths、常用目录和开始菜单；同时识别快捷方式中的 `--user-data-dir` 与 `--extensions-dir`；
- VS Code 扩展：核对扩展目录名和 `package.json` 的发布者、名称、版本，并忽略 `.obsolete` 残留；
- Claude Code：`CLAUDE_CONFIG_DIR`、官方位置、PATH 及安装记录；
- Pi：`PI_CODING_AGENT_DIR`、默认目录、PATH 及安装记录。

自动发现不会递归扫描整个磁盘，也不会执行名称不匹配的快捷方式目标。

## 安全边界

- 本地页面仅监听 `127.0.0.1`，校验 Host、Origin、启动访问令牌和会话令牌；
- 预览和安装确认均为短时、一次性、与请求内容绑定的令牌；
- 页面、接口和日志只显示脱敏密钥；
- Base URL 的远程地址必须使用 HTTPS，HTTP 只允许本机回环地址；
- 安装器固定官方来源；可解析到版本或提交时会锁定并校验，Claude Code 则跟随官方最新版渠道；同时阻止 ZIP 越界、符号链接、设备名、重复路径和解压资源滥用；
- Pi、dsh 与 Hermes 使用可回滚安装目录；dsh 自带独立 Node.js，不修改系统 Node 版本。

Key Router 只负责配置地址和凭据，不转换协议。相同 Base URL 必须同时兼容目标工具实际使用的 OpenAI、Anthropic 或其他协议。

## 从源码运行

```powershell
python -m pip install -r requirements.txt
python web_app.py
```

脱敏演示：

```powershell
python web_app.py --demo
```

## 命令行

省略 `--key` 时会在终端中隐藏输入：

```powershell
python rotate_keys.py --detect
python rotate_keys.py --url https://api.example.com/v1 --targets hermes,claude,pi
python rotate_keys.py --url https://api.example.com/v1 --targets hermes,claude,pi --apply
```

自动化可通过标准输入传入，避免把密钥写进命令历史：

```powershell
Get-Content .\key.txt -Raw | python rotate_keys.py --key-stdin --url https://api.example.com/v1 --targets hermes,claude,pi --apply
```

兼容参数 `--key` 仍可使用，但它会把密钥留在命令历史中。

## 测试与打包

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
python web_app.py --smoke-test
node --check ui\app.js
ruff check rotate_keys.py web_app.py agent_installers.py tests
bandit -c pyproject.toml -r rotate_keys.py web_app.py agent_installers.py
python -m pip install -r requirements-build.txt
pyinstaller key-rotator.spec --clean
python tests\package_e2e.py dist\Key-Router.exe
```

项目还包含 `tests/ui_browser_qa.js`，用于验证打包界面的主题、安装确认、预览、响应式布局、控制台和退出流程。

## 兼容性

- Windows 10 / 11；
- Python 3.10+（仅源码运行需要）；
- macOS 与 Linux 暂不支持。

## License

[MIT](LICENSE)
