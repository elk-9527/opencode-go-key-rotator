## Key Router v0.4.1

稳定性与兼容性更新：

- 修复 VS Code WAL 数据库备份与失败回滚，备份包含所有已提交数据；
- 写入前验证 Windows SecretStorage 确实可解密、可写；
- 忽略 VS Code `.obsolete` 中已卸载的扩展残留，支持快捷方式 `--extensions-dir`；
- 移除 Hermes 的本机盘符硬编码，支持官方 `~/.hermes`、`HERMES_HOME`、PATH 与快捷方式；
- 支持 `CLAUDE_CONFIG_DIR`，修正 Claude Code 新配置默认使用 `ANTHROPIC_API_KEY`；
- Pi 只更新已存在的模型提供商，并保留 JSONC 注释；
- 加强 URL、端口、Host、Origin、请求大小和一次性预览令牌校验；
- 修复 dsh 切换配置后把“已配置”错误显示成“可写入”的问题；
- 配置详情显示自动发现的实际绝对路径。

验证：17 项自动化测试、9 个目标打包 EXE 隔离写入、真实 DSH/VS Code 只读发现、三主题与窄窗口浏览器回归均通过。
