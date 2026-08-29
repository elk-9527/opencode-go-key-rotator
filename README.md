# OpenCode Go Key Rotator

一键轮换 **OpenCode Go** 订阅 API key —— 自动替换你所有 agent 里的配置，换新账号不再挨个手动改。

> 痛点：OpenCode Go 首月有优惠（$5），之后恢复 $10/月。想一直享受优惠就得不断买新账号 → key 频繁变动 → Hermes / Continue / dsh / VS Code 四处配置散落各地，手改容易漏。

## 支持的 agent

| Agent | 配置文件 | 存储方式 |
|---|---|---|
| **Hermes** | `E:\Program Files\Hermes\.env` → `OPENCODE_GO_API_KEY=` | 明文 |
| **Continue** (VS Code 插件) | `~/.continue/config.yaml` → `models[].apiKey` | 明文 |
| **dsh** (DeepSeek Harness) | `~/.dsh/.credentials.yaml` → `refs.DEEPSEEK_API_KEY:` | 明文 |
| **VS Code** (opencode-copilot-chat / BYOK 模型) | `state.vscdb` (SecretStorage) + `chatLanguageModels.json` | DPAPI + AES-GCM 加密 |
| (可选) **opencode CLI** | `~/.local/share/opencode/auth.json` | 删除旧 key 条目 |

非目标：DeepSeek 官方 key、小米 MiMo key 等其他凭据**不会被碰**（只替换 == 旧 key 的条目）。

## 用法

```bash
pip install cryptography

python rotate_keys.py --detect                 # 查看各位置当前 key 状态
python rotate_keys.py sk-新key                 # 预览（dry-run，不写文件）
python rotate_keys.py sk-新key --apply         # 执行（自动备份全部文件）
python rotate_keys.py sk-新key --apply --delete-opencode-auth   # 顺带删除 opencode CLI 旧 key
```

⚠️ **执行前必须完全退出 VS Code**（`state.vscdb` 被占用时写入会失败/损坏），脚本也会检测并拒绝。

自定义安装路径：设置环境变量 `RK_PATHS_JSON` 可覆盖任意路径（JSON 对象，键名见脚本 `_paths()`）。

## 原理：VS Code 加密部分怎么解

VS Code 用 Chromium 的 os_crypt 体系：

1. **AES 主密钥**：随机 256-bit key，用 Windows DPAPI 加密后存 `%APPDATA%\Code\Local State` 的 `os_crypt.encrypted_key`（值头带 `DPAPI` 前缀，base64）
2. **每条 secret**：`"v10"` 头 + AES-256-GCM（12B nonce + 密文 + 16B tag），以 `{"type":"Buffer","data":[...]}` JSON 存进 `state.vscdb` 的 `ItemTable`（键 `secret://chat.lm.secret.<id>` 或 `secret://{"extensionId":...}`）

本脚本用 `CryptUnprotectData` 解出 AES 主密钥 → 解密旧 key → 用同一算法加密新 key 写回，全程离线、不启动 VS Code。

另外 opencode-copilot-chat 扩展会把 key 的**指纹**（`前8位-后8位`）嵌进 profile、模型 ID、聊天记录等多种条目，脚本会一并替换为新指纹。

## 安全设计

- 默认 **dry-run 预览**，`--apply` 才真写
- 每次 apply 自动备份全部文件到 `backups/<时间戳>/`（含旧 key，可回滚）
- 全程**不打印完整 key**（只显示 `前8...后4`）
- 替换前检测 VS Code 是否运行
- 修改 `state.vscdb` 用事务，失败即回滚

## 测试

`test_env/` 可放副本文件；脚本支持 `RK_PATHS_JSON` 指向副本做全链路演练（已在隔离副本验证：明文替换 + secret 重加密 + 指纹替换 + 备份回滚全部通过）。

## 兼容性

- Windows 10/11（依赖 DPAPI，macOS/Linux 暂不支持）
- 实测 VS Code 1.134 (Electron 42)、opencode-copilot-chat 0.7.0
- Python 3.10+

## License

MIT