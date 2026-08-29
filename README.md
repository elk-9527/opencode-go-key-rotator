# Key Router

把一组 **Base URL + API Key** 批量写入多个本地 AI 工具。先预览，后备份，再应用。

![Key Router 界面](docs/key-router-ui.png)

## 支持的工具

| 工具 | 写入位置 |
|---|---|
| Hermes | `.env` 与 `config.yaml` |
| Continue | `~/.continue/config.yaml` |
| dsh | `~/.dsh/settings.yaml` 与 `.credentials.yaml` |
| VS Code | Custom Endpoint 与 SecretStorage |
| Claude Code | `~/.claude/settings.json` |
| Pi | `~/.pi/agent/models.json` |

## 使用

直接运行 `Key-Router.exe`，然后：

1. 填写 Base URL 和 API Key；
2. 勾选目标工具；
3. 生成预览；
4. 确认后批量应用。

VS Code 被选中时，请先完全退出 VS Code。界面支持日间、夜间和跟随系统主题。

## 安全设计

- 默认只预览，不直接写入；
- 每次应用前自动备份；
- 写入失败自动恢复；
- 页面和日志不显示完整 Key；
- 只监听 `127.0.0.1`，并使用会话令牌与一次性预览令牌；
- VS Code 的 API Key 写入 Windows 加密的 SecretStorage。

## 从源码运行

```powershell
pip install -r requirements.txt
python web_app.py
```

脱敏演示模式：

```powershell
python web_app.py --demo
```

## 命令行

```powershell
python rotate_keys.py --detect
python rotate_keys.py --url https://api.example.com/v1 --key YOUR_KEY --targets hermes,claude,pi
python rotate_keys.py --url https://api.example.com/v1 --key YOUR_KEY --targets hermes,claude,pi --apply
```

## 测试与打包

```powershell
python -m unittest discover -s tests -v
python web_app.py --smoke-test
node --check ui\app.js
pip install -r requirements-build.txt
pyinstaller key-rotator.spec --clean
```

单文件产物：`dist/Key-Router.exe`。

## 兼容性

- Windows 10 / 11；
- Python 3.10+（仅源码运行需要）；
- macOS 与 Linux 暂不支持。

## License

MIT
