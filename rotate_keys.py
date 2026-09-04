"""Key Router 核心：把一组 Base URL + API Key 安全写入多个 AI 工具。

默认只预览；正式写入前备份全部目标文件。每个适配器只修改明确字段，
不全盘搜索或替换疑似密钥的字符串。日志与返回值均不包含完整密钥。
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import getpass
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import agent_installers

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class RotationError(RuntimeError):
    """可安全展示给界面的错误。"""


def _console_log(message: str = "") -> None:
    """在非 UTF-8 Windows 控制台或重定向输出中也不会因中文崩溃。"""
    stream = sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    safe_message = str(message).encode(encoding, errors="backslashreplace").decode(encoding)
    print(safe_message, file=stream)


def _configure_console_streams() -> None:
    """CLI 优先输出 UTF-8；不支持 reconfigure 的嵌入式流保持原样。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError, ValueError):
            continue


class ProcessFileLock:
    """跨进程独占锁，防止两个 Key Router 同时修改同一组配置。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            handle.close()
            return False
        self.handle = handle
        return True

    def release(self):
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def _configuration_lock() -> ProcessFileLock:
    return ProcessFileLock(Path(APP_SETTINGS).with_name("key-router-config.lock"))


def _paths() -> dict[str, str]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    localappdata = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
    # Hermes 的用户配置目录与程序安装目录是两回事。Windows 原生版
    # 默认使用 %LOCALAPPDATA%\hermes；HERMES_HOME 只在用户显式覆盖时生效。
    hermes_default = localappdata / "hermes" if os.name == "nt" else home / ".hermes"
    hermes_home = Path(os.environ.get("HERMES_HOME") or hermes_default)
    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home / ".claude")
    pi_home = Path(os.environ.get("PI_CODING_AGENT_DIR") or home / ".pi" / "agent").expanduser()
    app_home = localappdata / "Key Router"
    paths = {
        "HERMES_ENV": str(hermes_home / ".env"),
        "HERMES_CONFIG": str(hermes_home / "config.yaml"),
        "CONTINUE_CONFIG": str(home / ".continue" / "config.yaml"),
        "DSH_SETTINGS": str(home / ".dsh" / "settings.yaml"),
        "DSH_CREDENTIALS": str(home / ".dsh" / ".credentials.yaml"),
        "VSCODE_STATE_DB": str(appdata / "Code" / "User" / "globalStorage" / "state.vscdb"),
        "VSCODE_LOCAL_STATE": str(appdata / "Code" / "Local State"),
        "VSCODE_USER_SETTINGS": str(appdata / "Code" / "User" / "settings.json"),
        "VSCODE_EXTENSIONS_DIR": str(Path(os.environ.get("VSCODE_EXTENSIONS") or home / ".vscode" / "extensions")),
        "CHAT_LM_JSON": str(appdata / "Code" / "User" / "chatLanguageModels.json"),
        "CLAUDE_SETTINGS": str(claude_home / "settings.json"),
        "PI_SETTINGS": str(pi_home / "settings.json"),
        "PI_MODELS": str(pi_home / "models.json"),
        "PI_AUTH": str(pi_home / "auth.json"),
        "BACKUP_DIR": str(app_home / "backups"),
        "APP_SETTINGS": str(app_home / "settings.json"),
    }
    override = os.environ.get("RK_PATHS_JSON")
    if override:
        paths.update({key: str(value) for key, value in json.loads(override).items()})
    return paths


def _apply_paths(paths: dict[str, str]) -> None:
    global HERMES_ENV, HERMES_CONFIG, CONTINUE_CONFIG
    global DSH_SETTINGS, DSH_CREDENTIALS
    global VSCODE_STATE_DB, VSCODE_LOCAL_STATE, VSCODE_USER_SETTINGS
    global VSCODE_EXTENSIONS_DIR, CHAT_LM_JSON
    global CLAUDE_SETTINGS, PI_SETTINGS, PI_MODELS, PI_AUTH, BACKUP_DIR, APP_SETTINGS
    HERMES_ENV = paths["HERMES_ENV"]
    HERMES_CONFIG = paths["HERMES_CONFIG"]
    CONTINUE_CONFIG = paths["CONTINUE_CONFIG"]
    DSH_SETTINGS = paths["DSH_SETTINGS"]
    DSH_CREDENTIALS = paths["DSH_CREDENTIALS"]
    VSCODE_STATE_DB = paths["VSCODE_STATE_DB"]
    VSCODE_LOCAL_STATE = paths["VSCODE_LOCAL_STATE"]
    VSCODE_USER_SETTINGS = paths["VSCODE_USER_SETTINGS"]
    VSCODE_EXTENSIONS_DIR = paths["VSCODE_EXTENSIONS_DIR"]
    CHAT_LM_JSON = paths["CHAT_LM_JSON"]
    CLAUDE_SETTINGS = paths["CLAUDE_SETTINGS"]
    PI_SETTINGS = paths["PI_SETTINGS"]
    PI_MODELS = paths["PI_MODELS"]
    PI_AUTH = paths["PI_AUTH"]
    BACKUP_DIR = paths["BACKUP_DIR"]
    APP_SETTINGS = paths["APP_SETTINGS"]


PATHS = _paths()
_apply_paths(PATHS)


def refresh_runtime_paths() -> None:
    """安装器更新环境变量后，重新解析当前进程使用的配置路径。"""
    global PATHS
    PATHS = _paths()
    _apply_paths(PATHS)


TARGET_ORDER = (
    "hermes",
    "continue",
    "dsh",
    "vscode",
    "opencode_copilot",
    "deepseek_copilot",
    "mimo_copilot",
    "claude",
    "pi",
)
TARGET_META = {
    "hermes": ("Hermes", "config.yaml + .env"),
    "continue": ("Continue", "~/.continue/config.yaml"),
    "dsh": ("dsh", "~/.dsh/settings.yaml"),
    "vscode": ("VS Code 自定义端点", "Custom Endpoint + SecretStorage"),
    "opencode_copilot": ("OpenCode for Copilot", "VS Code 扩展设置 + SecretStorage"),
    "deepseek_copilot": ("DeepSeek for Copilot", "VS Code 扩展设置 + SecretStorage"),
    "mimo_copilot": ("Xiaomi MiMo for Copilot", "VS Code 扩展设置 + SecretStorage"),
    "claude": ("Claude Code", "~/.claude/settings.json"),
    "pi": ("Pi", "~/.pi/agent/models.json"),
}

EXTENSION_META = {
    "continue": {
        "id": "continue.continue",
        "name": "Continue - open-source AI code agent",
        "publisher": "Continue",
    },
    "opencode_copilot": {
        "id": "ltmoerdani.opencode-copilot-chat",
        "name": "OpenCode for Copilot Chat — BYOK 30+ AI Models",
        "publisher": "ltmoerdani",
    },
    "deepseek_copilot": {
        "id": "vizards.deepseek-v4-for-copilot",
        "name": "DeepSeek V4 for Copilot Chat",
        "publisher": "Vizards",
    },
    "mimo_copilot": {
        "id": "sdmapvstool.xiaomimimo-for-copilot",
        "name": "Xiaomi MiMo for Copilot Chat",
        "publisher": "sdmapvstool",
    },
}

VSCODE_PLUGIN_CONFIG = {
    "opencode_copilot": ("opencodego.apiBaseUrl", "opencodego.apiKey"),
    "deepseek_copilot": ("deepseek-copilot.baseUrl", "deepseek-copilot.apiKey"),
    "mimo_copilot": ("mimo-copilot.baseUrl", "mimo-copilot.apiKey"),
}
OPENCODE_VENDORS = {
    "opencodego": ("OpenCode Go", "opencodego.apiBaseUrl", "opencodego.apiKey"),
    "opencodezen": ("OpenCode Zen", "opencodezen.apiBaseUrl", "opencodezen.apiKey"),
}
VSCODE_TARGETS = {"vscode", *VSCODE_PLUGIN_CONFIG}
VSCODE_DISCOVERY_TARGETS = {"continue", *VSCODE_TARGETS}

VSCODE_SECRET_ID = "chat.lm.secret.key-router-api-key"  # nosec B105
VSCODE_SECRET_KEY = f"secret://{VSCODE_SECRET_ID}"
VSCODE_SECRET_REF = "${input:" + VSCODE_SECRET_ID + "}"
BACKUP_MAGIC = b"KEY-ROUTER-DPAPI-V1\0"
BACKUP_MANIFEST = "manifest.dpapi"
CONTINUE_SECRET_PATTERN = re.compile(r"^\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")
PI_PROVIDER_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "ant-ling": "ANT_LING_API_KEY",
    "azure-openai-responses": "AZURE_OPENAI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "nvidia": "NVIDIA_API_KEY",
    "google": "GEMINI_API_KEY",
    "amazon-bedrock": "AWS_BEARER_TOKEN_BEDROCK",
    "mistral": "MISTRAL_API_KEY",
    "groq": "GROQ_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
    "cloudflare-ai-gateway": "CLOUDFLARE_API_KEY",
    "cloudflare-workers-ai": "CLOUDFLARE_API_KEY",
    "xai": "XAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "vercel-ai-gateway": "AI_GATEWAY_API_KEY",
    "zai": "ZAI_API_KEY",
    "zai-coding-cn": "ZAI_CODING_CN_API_KEY",
    "opencode": "OPENCODE_API_KEY",
    "opencode-go": "OPENCODE_API_KEY",
    "radius": "RADIUS_API_KEY",
    "huggingface": "HF_TOKEN",
    "fireworks": "FIREWORKS_API_KEY",
    "together": "TOGETHER_API_KEY",
    "baseten": "BASETEN_API_KEY",
    "kimi-coding": "KIMI_API_KEY",
    "minimax": "MINIMAX_API_KEY",
    "minimax-cn": "MINIMAX_CN_API_KEY",
    "qwen-token-plan": "QWEN_TOKEN_PLAN_API_KEY",
    "qwen-token-plan-individual": "QWEN_TOKEN_PLAN_API_KEY",
    "qwen-token-plan-cn": "QWEN_TOKEN_PLAN_CN_API_KEY",
    "xiaomi": "XIAOMI_API_KEY",
    "xiaomi-token-plan-cn": "XIAOMI_TOKEN_PLAN_CN_API_KEY",
    "xiaomi-token-plan-ams": "XIAOMI_TOKEN_PLAN_AMS_API_KEY",
    "xiaomi-token-plan-sgp": "XIAOMI_TOKEN_PLAN_SGP_API_KEY",
}


@dataclass
class TargetState:
    id: str
    title: str
    location: str
    state: str
    badge: str
    detail: str
    selectable: bool
    current_url: str | None = None
    current_key: str | None = None
    note: str = ""
    discovery: list[dict] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    providers: list[dict] = field(default_factory=list)
    selected_provider: str = ""
    selected_profile: str = ""
    extension: dict | None = None

    def public(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "location": self.location,
            "state": self.state,
            "badge": self.badge,
            "detail": self.detail,
            "selectable": self.selectable,
            "note": self.note,
            "discovery": self.discovery,
            "candidates": self.candidates,
            "providers": self.providers,
            "selectedProvider": self.selected_provider,
            "selectedProfile": self.selected_profile,
            "extension": self.extension,
        }


@dataclass
class Change:
    target_id: str
    path: str
    summary: str
    after_text: str | None = None
    action: Callable[[], None] | None = None

    def apply(self):
        if self.action:
            self.action()
        elif self.after_text is not None:
            _atomic_write_text(self.path, self.after_text)


@dataclass
class TargetPlan:
    target: TargetState
    changes: list[Change] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _dedupe_discovery(items: list[dict]) -> list[dict]:
    seen = set()
    output = []
    for item in items:
        raw = str(item.get("path") or "").strip().strip('"')
        if not raw:
            continue
        key = os.path.normcase(os.path.normpath(raw))
        if key in seen:
            continue
        seen.add(key)
        output.append({**item, "path": raw})
    return output


@lru_cache(maxsize=16)
def _shortcut_targets(name_pattern: str) -> list[dict]:
    """从开始菜单快捷方式取得真实目标；不会扫描磁盘。"""
    if os.name != "nt":
        return []
    script = r"""
$roots = @(
  [Environment]::GetFolderPath('StartMenu'),
  [Environment]::GetFolderPath('CommonStartMenu')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
$shell = New-Object -ComObject WScript.Shell
$rows = foreach ($root in $roots) {
  Get-ChildItem -LiteralPath $root -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue |
    Where-Object { $_.BaseName -match $env:KEY_ROUTER_SHORTCUT_PATTERN } |
    ForEach-Object {
      $shortcut = $shell.CreateShortcut($_.FullName)
      if ($shortcut.TargetPath) {
        [pscustomobject]@{
          path = $shortcut.TargetPath
          shortcut = $_.FullName
          arguments = $shortcut.Arguments
          workingDirectory = $shortcut.WorkingDirectory
        }
      }
    }
}
@($rows) | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["KEY_ROUTER_SHORTCUT_PATTERN"] = name_pattern
    powershell = str(
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=6,
            env=environment,
            creationflags=_creation_flags(),
        )
        if result.returncode or not result.stdout.strip():
            return []
        payload = json.loads(result.stdout)
        rows = payload if isinstance(payload, list) else [payload]
        return [
            {
                "path": row.get("path", ""),
                "source": "开始菜单快捷方式",
                "detail": row.get("shortcut", ""),
                "arguments": row.get("arguments", ""),
                "workingDirectory": row.get("workingDirectory", ""),
            }
            for row in rows
            if isinstance(row, dict)
        ]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def _registry_app_paths(executable_name: str) -> list[dict]:
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []
    output = []
    subkey = rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{executable_name}"
    for hive, label in ((winreg.HKEY_CURRENT_USER, "用户注册表"), (winreg.HKEY_LOCAL_MACHINE, "系统注册表")):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _kind = winreg.QueryValueEx(key, None)
                output.append({"path": str(value), "source": label})
        except OSError:
            continue
    return output


def _registry_uninstall_matches(pattern: str) -> list[dict]:
    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []
    output = []
    roots = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in roots:
        try:
            with winreg.OpenKey(hive, path) as root:
                for index in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, index)) as key:
                            name = str(winreg.QueryValueEx(key, "DisplayName")[0])
                            if not re.search(pattern, name, re.I):
                                continue
                            values = {}
                            for field_name in ("InstallLocation", "DisplayIcon"):
                                try:
                                    values[field_name] = str(winreg.QueryValueEx(key, field_name)[0])
                                except OSError:
                                    pass
                            raw = values.get("InstallLocation") or values.get("DisplayIcon") or ""
                            raw = raw.split(",", 1)[0].strip().strip('"')
                            if raw:
                                output.append({"path": raw, "source": "卸载注册表", "detail": name})
                    except OSError:
                        continue
        except OSError:
            continue
    return output


def _command_discovery(commands: tuple[str, ...], label: str = "PATH 命令") -> list[dict]:
    items = []
    for command in commands:
        located = shutil.which(command)
        if located:
            items.append({"path": located, "source": label})
    return _dedupe_discovery(items)


def discover_hermes_installations() -> list[dict]:
    items = _command_discovery(("hermes", "hermes.cmd", "hermes.exe"))
    items.extend(agent_installers.managed_discovery(APP_SETTINGS, "hermes"))
    items.extend(_shortcut_targets(r"^Hermes(?: Agent| Desktop)?$"))
    return _dedupe_discovery(items)


def discover_claude_installations() -> list[dict]:
    items = _command_discovery(("claude", "claude.cmd", "claude.exe"))
    native = Path.home() / ".local" / "bin" / "claude.exe"
    if native.is_file():
        items.append({"path": str(native), "source": "Claude 官方位置"})
    items.extend(agent_installers.managed_discovery(APP_SETTINGS, "claude"))
    return _dedupe_discovery(items)


def discover_pi_installations() -> list[dict]:
    items = _command_discovery(("pi", "pi.cmd", "pi.exe"))
    items.extend(agent_installers.managed_discovery(APP_SETTINGS, "pi"))
    return _dedupe_discovery(items)


def discover_dsh_installations() -> list[dict]:
    items: list[dict] = []
    for command in ("dsh", "dsh.cmd", "dsh.exe"):
        located = shutil.which(command)
        if located:
            items.append({"path": located, "source": "PATH 命令"})
    for environment_name in ("DSH_EXE", "DSH_INSTALL_DIR"):
        raw = os.environ.get(environment_name)
        if raw:
            items.append({"path": raw, "source": f"环境变量 {environment_name}"})
    local = Path(os.environ.get("LOCALAPPDATA") or "")
    program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
    for candidate in (
        local / "Programs" / "DSH Desktop" / "DSH Desktop.exe",
        program_files / "DSH Desktop" / "DSH Desktop.exe",
    ):
        if candidate.is_file():
            items.append({"path": str(candidate), "source": "常用安装目录"})
    items.extend(_registry_app_paths("DSH Desktop.exe"))
    items.extend(_registry_uninstall_matches(r"\bDSH\b|DeepSeek Harness"))
    items.extend(_shortcut_targets(r"(^|\s)DSH( Desktop)?($|\s)|DeepSeek Harness"))
    items.extend(agent_installers.managed_discovery(APP_SETTINGS, "dsh"))
    return _dedupe_discovery(items)


def _dsh_provider_rows(settings_text: str) -> list[dict]:
    current = _yaml_get(settings_text, ("agent-default-model", "provider")) or ""
    rows = []
    for provider_id in _yaml_child_keys(settings_text, ("llm-pi-ai", "providers")):
        prefix = ("llm-pi-ai", "providers", provider_id)
        env_name = _yaml_get(settings_text, prefix + ("apiKeyEnv",)) or ""
        valid_env_name = bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name))
        environment_override = bool(valid_env_name and os.environ.get(env_name))
        blocked_reason = ""
        if not valid_env_name:
            blocked_reason = "apiKeyEnv 不是有效的环境变量名"
        elif environment_override:
            blocked_reason = f"进程环境变量 {env_name} 优先于凭据文件，请先清除或更新该变量"
        rows.append(
            {
                "id": provider_id,
                "name": _yaml_get(settings_text, prefix + ("displayName",)) or provider_id,
                "baseUrl": _yaml_get(settings_text, prefix + ("baseURL",)) or "",
                "apiKeyEnv": env_name,
                "current": provider_id == current,
                "writable": valid_env_name and not environment_override,
                "environmentOverride": environment_override,
                "blockedReason": blocked_reason,
            }
        )
    return rows


def discover_dsh_configs(extra_path: str | None = None) -> list[dict]:
    candidates: list[dict] = []
    requested = []
    if extra_path:
        manual = Path(extra_path).expanduser()
        if manual.name.lower() == "settings.yaml":
            requested.append((manual, "手动选择"))
    dsh_home = os.environ.get("DSH_HOME")
    if dsh_home:
        requested.append((Path(dsh_home).expanduser() / "settings.yaml", "环境变量 DSH_HOME"))
    requested.append((Path(DSH_SETTINGS), "默认用户配置"))
    standard = Path.home() / ".dsh" / "settings.yaml"
    requested.append((standard, "标准用户目录"))
    for path, source in requested:
        if not path.is_file():
            continue
        try:
            text = _read_text(str(path))
            providers = _dsh_provider_rows(text)
        except OSError:
            continue
        candidates.append(
            {
                "path": str(path),
                "credentialsPath": str(path.parent / ".credentials.yaml"),
                "source": source,
                "providers": providers,
                "currentProvider": next((row["id"] for row in providers if row["current"]), ""),
            }
        )
    return _dedupe_discovery(candidates)


def discover_vscode_installations() -> list[dict]:
    items: list[dict] = []
    for command in ("code", "code.cmd", "Code.exe"):
        located = shutil.which(command)
        if located:
            items.append({"path": located, "source": "PATH 命令"})
    local = Path(os.environ.get("LOCALAPPDATA") or "")
    program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
    program_files_x86 = Path(os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)")
    for candidate in (
        local / "Programs" / "Microsoft VS Code" / "Code.exe",
        program_files / "Microsoft VS Code" / "Code.exe",
        program_files_x86 / "Microsoft VS Code" / "Code.exe",
    ):
        if candidate.is_file():
            items.append({"path": str(candidate), "source": "常用安装目录"})
    items.extend(_registry_app_paths("Code.exe"))
    items.extend(_shortcut_targets(r"Visual Studio Code|^VS Code$"))
    normalized = []
    for item in _dedupe_discovery(items):
        path = Path(item["path"])
        if not path.is_file() or path.name.lower() not in {"code", "code.cmd", "code.exe"}:
            continue
        executable = path
        cli = path
        if path.name.lower() in {"code", "code.cmd"}:
            possible = path.parent.parent / "Code.exe"
            if possible.is_file():
                executable = possible
        else:
            possible = path.parent / "bin" / "code.cmd"
            if possible.is_file():
                cli = possible
        normalized.append({**item, "path": str(executable), "cli": str(cli)})
    return _dedupe_discovery(normalized)


def _shortcut_option_path(item: dict, option_name: str) -> str:
    arguments = str(item.get("arguments") or "")
    match = re.search(
        rf"(?:^|\s)--{re.escape(option_name)}(?:\s*=\s*|\s+)(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
        arguments,
        re.I,
    )
    if not match:
        return ""
    raw = next((part for part in match.groups() if part is not None), "")
    expanded = os.path.expandvars(raw.strip())
    candidate = Path(expanded).expanduser()
    if not candidate.is_absolute() and item.get("workingDirectory"):
        candidate = Path(str(item["workingDirectory"])) / candidate
    return os.path.normpath(str(candidate))


def _vscode_instance_cli_args(item: dict) -> list[str]:
    """只继承会改变 VS Code 数据位置的快捷方式参数。"""
    output = []
    for option_name in ("user-data-dir", "extensions-dir"):
        value = _shortcut_option_path(item, option_name)
        if value:
            output.append(f"--{option_name}={value}")
    return output


def _vscode_profile_paths(user_data_dir: str | Path | None = None) -> dict[str, str]:
    if user_data_dir:
        root = Path(user_data_dir)
        default_root = Path(VSCODE_USER_SETTINGS).parent.parent
        if os.path.normcase(os.path.normpath(str(root))) == os.path.normcase(os.path.normpath(str(default_root))):
            return {
                "stateDb": VSCODE_STATE_DB,
                "localState": VSCODE_LOCAL_STATE,
                "settings": VSCODE_USER_SETTINGS,
                "chatModels": CHAT_LM_JSON,
            }
        return {
            "stateDb": str(root / "User" / "globalStorage" / "state.vscdb"),
            "localState": str(root / "Local State"),
            "settings": str(root / "User" / "settings.json"),
            "chatModels": str(root / "User" / "chatLanguageModels.json"),
        }
    return {
        "stateDb": VSCODE_STATE_DB,
        "localState": VSCODE_LOCAL_STATE,
        "settings": VSCODE_USER_SETTINGS,
        "chatModels": CHAT_LM_JSON,
    }


def discover_vscode_profiles(instances: list[dict] | None = None) -> list[dict]:
    instances = instances if instances is not None else discover_vscode_installations()
    default_root = Path(VSCODE_USER_SETTINGS).parent.parent
    rows = [{"id": str(default_root), "path": str(default_root), "source": "VS Code 标准用户数据"}]
    for item in instances:
        custom = _shortcut_option_path(item, "user-data-dir")
        if custom:
            rows.append(
                {
                    "id": custom,
                    "path": custom,
                    "source": f"{item.get('source') or 'VS Code 快捷方式'} · 自定义用户数据",
                }
            )
    return _dedupe_discovery(rows)


def _select_vscode_profile(instances: list[dict], options: dict) -> tuple[list[dict], dict | None]:
    profiles = discover_vscode_profiles(instances)
    requested = str(options.get("userDataDir") or "")
    selected = next(
        (row for row in profiles if requested and os.path.normcase(row["path"]) == os.path.normcase(requested)),
        None,
    )
    if selected is None and len(profiles) == 1:
        selected = profiles[0]
    return profiles, selected


def discover_vscode_extension_dirs(instances: list[dict] | None = None) -> list[Path]:
    roots = [Path(VSCODE_EXTENSIONS_DIR)]
    for item in instances if instances is not None else discover_vscode_installations():
        custom = _shortcut_option_path(item, "extensions-dir")
        if custom:
            roots.append(Path(custom))
    seen = set()
    output = []
    for root in roots:
        key = os.path.normcase(os.path.normpath(str(root)))
        if key not in seen:
            seen.add(key)
            output.append(root)
    return output


def _obsolete_extension_directories(root: Path) -> set[str]:
    path = root / ".obsolete"
    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(payload, dict):
        return set()
    return {os.path.normcase(str(name)) for name, obsolete in payload.items() if obsolete}


def _installed_vscode_extensions_in_roots(roots: list[Path]) -> dict[str, str]:
    installed: dict[str, str] = {}
    for root in roots:
        if not root.is_dir():
            continue
        obsolete = _obsolete_extension_directories(root)
        try:
            directories = list(root.iterdir())
        except OSError:
            continue
        for directory in directories:
            if not directory.is_dir():
                continue
            if os.path.normcase(directory.name) in obsolete:
                continue
            lower = directory.name.lower()
            for metadata in EXTENSION_META.values():
                extension_id = metadata["id"].lower()
                if lower != extension_id and not lower.startswith(extension_id + "-"):
                    continue
                try:
                    package = json.loads((directory / "package.json").read_text(encoding="utf-8-sig"))
                except (OSError, json.JSONDecodeError):
                    continue
                expected_publisher, expected_name = extension_id.split(".", 1)
                actual_id = f"{package.get('publisher', '')}.{package.get('name', '')}".lower()
                version = str(package.get("version") or "").strip()
                if actual_id != f"{expected_publisher}.{expected_name}" or not re.fullmatch(
                    r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}", version
                ):
                    continue
                previous = installed.get(extension_id, "")
                previous_numbers = tuple(int(part) for part in re.findall(r"\d+", previous))
                version_numbers = tuple(int(part) for part in re.findall(r"\d+", version))
                if not previous or version_numbers >= previous_numbers:
                    installed[extension_id] = version
    return installed


def installed_vscode_extensions(
    instances: list[dict] | None = None,
    *,
    query_cli: bool = False,
) -> dict[str, str]:
    vscode = instances if instances is not None else discover_vscode_installations()
    installed = _installed_vscode_extensions_in_roots(discover_vscode_extension_dirs(vscode))
    if query_cli and vscode:
        instance = vscode[0]
        executable = instance.get("cli") or instance["path"]
        try:
            result = subprocess.run(
                [executable, *_vscode_instance_cli_args(instance), "--list-extensions", "--show-versions"],
                capture_output=True,
                text=True,
                timeout=12,
                creationflags=_creation_flags(),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    extension_id, _separator, version = line.strip().partition("@")
                    if extension_id:
                        installed[extension_id.lower()] = version or "已安装"
        except (OSError, subprocess.SubprocessError):
            pass
    return installed


def extension_public(
    target_id: str,
    installed: dict[str, str] | None = None,
    vscode_instances: list[dict] | None = None,
) -> dict | None:
    metadata = EXTENSION_META.get(target_id)
    if not metadata:
        return None
    versions = installed if installed is not None else installed_vscode_extensions()
    version = versions.get(metadata["id"].lower(), "")
    vscode = vscode_instances if vscode_instances is not None else discover_vscode_installations()
    return {
        **metadata,
        "installed": bool(version),
        "version": version,
        "installable": bool(vscode),
    }


def install_vscode_extension(extension_id: str, extension_dir: str | None = None) -> dict:
    """仅安装白名单中的 VS Code 扩展；调用前应由界面取得用户确认。"""
    allowed = {metadata["id"].lower(): metadata for metadata in EXTENSION_META.values()}
    metadata = allowed.get(extension_id.lower())
    if not metadata:
        raise RotationError("该扩展不在 Key Router 的安装白名单中")
    instances = discover_vscode_installations()
    if not instances:
        raise RotationError("没有找到 VS Code，无法安装扩展")
    roots = discover_vscode_extension_dirs(instances)
    requested_root = Path(extension_dir or roots[0])
    if not requested_root.is_absolute():
        raise RotationError("VS Code 扩展目录必须是完整路径")
    requested_root = requested_root.resolve()
    allowed_roots = {
        os.path.normcase(os.path.normpath(str(root.resolve()))): root
        for root in roots
    }
    requested_key = os.path.normcase(os.path.normpath(str(requested_root)))
    if requested_key not in allowed_roots:
        raise RotationError("VS Code 扩展目录已变化，请重新确认安装位置")
    instance = next(
        (
            item
            for item in instances
            if os.path.normcase(os.path.normpath(_shortcut_option_path(item, "extensions-dir"))) == requested_key
        ),
        instances[0],
    )
    executable = instance.get("cli") or instance["path"]
    instance_args = [arg for arg in _vscode_instance_cli_args(instance) if not arg.startswith("--extensions-dir=")]
    instance_args.append(f"--extensions-dir={requested_root}")
    try:
        result = subprocess.run(
            [executable, *instance_args, "--install-extension", metadata["id"], "--force"],
            capture_output=True,
            text=True,
            timeout=180,
            creationflags=_creation_flags(),
        )
    except subprocess.TimeoutExpired as exc:
        raise RotationError("扩展安装超时，请检查网络或 VS Code 代理设置") from exc
    except OSError as exc:
        raise RotationError("无法启动 VS Code 扩展安装程序") from exc
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode != 0:
        short = output.splitlines()[-1] if output else f"退出码 {result.returncode}"
        raise RotationError(f"扩展安装失败：{short[:300]}")
    versions = _installed_vscode_extensions_in_roots([requested_root])
    version = versions.get(metadata["id"].lower(), "")
    if not version:
        raise RotationError("VS Code 报告安装完成，但重新检测时没有找到该扩展")
    return {
        "id": metadata["id"],
        "name": metadata["name"],
        "publisher": metadata["publisher"],
        "version": version,
    }


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def dpapi_encrypt(blob: bytes) -> bytes:
    source_buffer = ctypes.create_string_buffer(blob)
    source = DATA_BLOB(len(blob), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_byte)))
    output = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(output))
    if not ok:
        raise OSError("无法使用 Windows 账户保护备份")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def dpapi_decrypt(blob: bytes) -> bytes:
    source = DATA_BLOB(len(blob), ctypes.cast(ctypes.create_string_buffer(blob), ctypes.POINTER(ctypes.c_byte)))
    output = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(output))
    if not ok:
        raise OSError("无法解密 VS Code 本机密钥")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def get_vscode_aes_key(local_state_path: str | None = None) -> bytes:
    with open(local_state_path or VSCODE_LOCAL_STATE, encoding="utf-8") as file:
        local_state = json.load(file)
    encrypted = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    if not encrypted.startswith(b"DPAPI"):
        raise RotationError("VS Code Local State 不是受支持的 DPAPI 格式")
    raw = dpapi_decrypt(encrypted[5:])
    return raw if len(raw) == 32 else base64.b64decode(raw)


def vscode_secret_decrypt(value: bytes, aes_key: bytes) -> str:
    if not value.startswith(b"v10"):
        raise RotationError("VS Code SecretStorage 格式不受支持")
    blob = value[3:]
    return AESGCM(aes_key).decrypt(blob[:12], blob[12:], None).decode("utf-8")


def vscode_secret_encrypt(value: str, aes_key: bytes) -> bytes:
    nonce = os.urandom(12)
    return b"v10" + nonce + AESGCM(aes_key).encrypt(nonce, value.encode("utf-8"), None)


def mask(value: str | None) -> str:
    if not value:
        return "未设置"
    if len(value) <= 12:
        return f"{'•' * len(value)} ({len(value)})"
    return f"••••…{value[-4:]} ({len(value)})"


def validate_key(value: str) -> str:
    if not isinstance(value, str):
        raise RotationError("API Key 格式不正确")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise RotationError("API Key 不能包含空格、换行或控制字符")
    key = value.strip()
    if not 4 <= len(key) <= 2048:
        raise RotationError("API Key 长度应为 4–2048 个字符")
    return key


def validate_base_url(value: str) -> str:
    if not isinstance(value, str):
        raise RotationError("Base URL 格式不正确")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise RotationError("Base URL 不能包含空格、换行或控制字符")
    if "\\" in value:
        raise RotationError("Base URL 不能包含反斜杠")
    raw = value.strip()
    if not raw or len(raw) > 2048:
        raise RotationError("Base URL 不能为空或过长")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise RotationError("Base URL 格式不正确") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RotationError("Base URL 必须是完整的 http:// 或 https:// 地址")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RotationError("Base URL 端口无效") from exc
    if port is not None and not 1 <= port <= 65535:
        raise RotationError("Base URL 端口无效")
    if parsed.netloc.endswith(":"):
        raise RotationError("Base URL 端口不能为空")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RotationError("Base URL 不能包含账号、密码、查询参数或锚点")
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "http" and parsed.hostname.lower() not in local_hosts:
        raise RotationError("远程地址必须使用 HTTPS；HTTP 仅允许本机地址")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8-sig", errors="strict", newline="") as file:
        return file.read()


def _atomic_write_text(path: str, text: str):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = target.stat().st_mode if target.exists() else None
    handle, temp_path = tempfile.mkstemp(prefix=f".{target.name}.key-router-", dir=target.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        if mode is not None:
            os.chmod(temp_path, mode)
        os.replace(temp_path, target)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _atomic_write_bytes(path: str, data: bytes):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = target.stat().st_mode if target.exists() else None
    handle, temp_path = tempfile.mkstemp(prefix=f".{target.name}.key-router-", dir=target.parent)
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if mode is not None:
            os.chmod(temp_path, mode)
        os.replace(temp_path, target)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _json_dump(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def _load_json(path: str, default):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, encoding="utf-8-sig") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RotationError(f"配置文件无法解析：{Path(path).name}") from exc


def _strip_jsonc(text: str) -> str:
    output = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
        elif char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            index += 2
            while index + 1 < len(text) and text[index : index + 2] != "*/":
                index += 1
            index += 2
        else:
            output.append(char)
            index += 1
    # 删除尾随逗号时再次识别字符串，避免把字符串中的 `, }` 当成语法。
    source = "".join(output)
    cleaned = []
    index = 0
    in_string = False
    escaped = False
    while index < len(source):
        char = source[index]
        if in_string:
            cleaned.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            cleaned.append(char)
            index += 1
            continue
        if char == ",":
            lookahead = index + 1
            while lookahead < len(source) and source[lookahead].isspace():
                lookahead += 1
            if lookahead < len(source) and source[lookahead] in "}]":
                index += 1
                continue
        cleaned.append(char)
        index += 1
    return "".join(cleaned)


def _load_jsonc(path: str, default):
    if not os.path.isfile(path):
        return default
    try:
        return json.loads(_strip_jsonc(_read_text(path)))
    except (OSError, json.JSONDecodeError) as exc:
        raise RotationError(f"配置文件无法解析：{Path(path).name}") from exc


def _jsonc_set_top_level(text: str, key: str, value: str) -> str:
    """只更新 VS Code settings.json 的一个顶层字符串字段，并保留其余文本。"""
    source = text if text.strip() else "{}\n"
    parsed = json.loads(_strip_jsonc(source))
    if not isinstance(parsed, dict):
        raise RotationError("VS Code settings.json 顶层必须是对象")
    encoded_value = json.dumps(value, ensure_ascii=False)
    tokens = _jsonc_tokens(source)
    if not tokens or tokens[0][0] != "{":
        raise RotationError("VS Code settings.json 顶层必须是对象")
    span = _jsonc_property_span(tokens, 0, key)
    if span:
        start = tokens[span[0]][2]
        end = tokens[span[1] - 1][3]
        return source[:start] + encoded_value + source[end:]
    encoded_key = json.dumps(key, ensure_ascii=False)
    open_index = source.find("{")
    if open_index < 0:
        raise RotationError("VS Code settings.json 缺少开始括号")
    newline = "\r\n" if "\r\n" in source else "\n"
    rest = source[open_index + 1 :]
    if rest.startswith("\r\n"):
        rest = rest[2:]
    elif rest.startswith("\n"):
        rest = rest[1:]
    comma = "," if parsed else ""
    insertion = f"{newline}  {encoded_key}: {encoded_value}{comma}{newline}"
    return source[: open_index + 1] + insertion + rest


def _jsonc_tokens(text: str) -> list[tuple[str, str | None, int, int]]:
    """返回忽略空白与注释的轻量 JSONC 词元，用于精确替换既有字段。"""
    tokens = []
    index = 0
    punctuation = "{}[]:,"
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            closing = text.find("*/", index + 2)
            index = len(text) if closing < 0 else closing + 2
            continue
        if char == '"':
            start = index
            index += 1
            escaped = False
            while index < len(text):
                current = text[index]
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            raw = text[start:index]
            tokens.append(("string", json.loads(raw), start, index))
            continue
        if char in punctuation:
            tokens.append((char, None, index, index + 1))
            index += 1
            continue
        start = index
        while index < len(text) and not text[index].isspace() and text[index] not in punctuation:
            if text.startswith("//", index) or text.startswith("/*", index):
                break
            index += 1
        tokens.append(("literal", text[start:index], start, index))
    return tokens


def _jsonc_value_end(tokens: list[tuple[str, str | None, int, int]], start: int) -> int:
    if start >= len(tokens):
        raise RotationError("JSONC 字段缺少值")
    opening = tokens[start][0]
    if opening not in {"{", "["}:
        return start + 1
    stack = [opening]
    matching = {"}": "{", "]": "["}
    for index in range(start + 1, len(tokens)):
        kind = tokens[index][0]
        if kind in {"{", "["}:
            stack.append(kind)
        elif kind in matching:
            if not stack or stack[-1] != matching[kind]:
                raise RotationError("JSONC 括号结构无效")
            stack.pop()
            if not stack:
                return index + 1
    raise RotationError("JSONC 括号未闭合")


def _jsonc_property_span(
    tokens: list[tuple[str, str | None, int, int]],
    object_index: int,
    key: str,
) -> tuple[int, int] | None:
    if tokens[object_index][0] != "{":
        return None
    object_end = _jsonc_value_end(tokens, object_index)
    index = object_index + 1
    found = None
    while index < object_end - 1:
        if tokens[index][0] == "string" and index + 2 < object_end and tokens[index + 1][0] == ":":
            value_index = index + 2
            value_end = _jsonc_value_end(tokens, value_index)
            if tokens[index][1] == key:
                # JSON 的重复键以最后一个为准；替换最后一处才会实际生效。
                found = (value_index, value_end)
            index = value_end
        else:
            index += 1
    return found


def _jsonc_replace_nested_strings(
    text: str,
    object_path: tuple[str, ...],
    updates: dict[str, str],
) -> str | None:
    """只替换既有嵌套字段；字段缺失时返回 None，由调用方安全降级。"""
    tokens = _jsonc_tokens(text)
    if not tokens or tokens[0][0] != "{":
        return None
    object_index = 0
    for part in object_path:
        span = _jsonc_property_span(tokens, object_index, part)
        if not span or tokens[span[0]][0] != "{":
            return None
        object_index = span[0]
    replacements = []
    for key, value in updates.items():
        span = _jsonc_property_span(tokens, object_index, key)
        if not span:
            return None
        start = tokens[span[0]][2]
        end = tokens[span[1] - 1][3]
        replacements.append((start, end, json.dumps(value, ensure_ascii=False)))
    output = text
    for start, end, replacement in sorted(replacements, reverse=True):
        output = output[:start] + replacement + output[end:]
    return output


def _yaml_split_comment(value: str) -> tuple[str, str]:
    quote = ""
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = ""
        elif quote == "'":
            if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 1
            elif character == "'":
                quote = ""
        elif character in {'"', "'"}:
            quote = character
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip(), value[index:].rstrip()
        index += 1
    return value.rstrip(), ""


def _unquote_yaml(value: str | None) -> str | None:
    if value is None:
        return None
    value, _comment = _yaml_split_comment(value.strip())
    if not value or value in {"null", "~"}:
        return None
    if value[:1] == value[-1:] and value[:1] in {'"', "'"}:
        if value[0] == '"':
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass
        return value[1:-1].replace("''", "'")
    return value


def _yaml_entries(text: str):
    stack: list[tuple[int, str]] = []
    for index, line in enumerate(text.splitlines(keepends=True)):
        match = re.match(r"^( *)([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*?))?\s*(?:\r?\n)?$", line)
        if not match:
            continue
        indent = len(match.group(1))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key = match.group(2)
        path = tuple(item[1] for item in stack) + (key,)
        raw = match.group(3) or ""
        yield index, indent, path, raw
        if not raw.strip() or raw.lstrip().startswith("#"):
            stack.append((indent, key))


def _yaml_get(text: str, path: tuple[str, ...]) -> str | None:
    found = None
    for _index, _indent, current, raw in _yaml_entries(text):
        if current == path:
            # YAML 解析器通常以最后一个重复键为准；读取与写入保持一致。
            found = _unquote_yaml(raw)
    return found


def _yaml_child_keys(text: str, path: tuple[str, ...]) -> list[str]:
    keys = []
    for _index, _indent, current, _raw in _yaml_entries(text):
        if len(current) == len(path) + 1 and current[:-1] == path:
            keys.append(current[-1])
    return keys


def _yaml_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _yaml_set(text: str, path: tuple[str, ...], value: str) -> str:
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    entries = list(_yaml_entries(text))
    for index, indent, current, _raw in reversed(entries):
        if current == path:
            _scalar, inline_comment = _yaml_split_comment(_raw)
            suffix = f" {inline_comment}" if inline_comment else ""
            lines[index] = f"{' ' * indent}{path[-1]}: {_yaml_quote(value)}{suffix}{newline}"
            return "".join(lines)
    parent = path[:-1]
    parent_entry = next((entry for entry in reversed(entries) if entry[2] == parent), None)
    if parent_entry:
        parent_index, parent_indent, _current, parent_raw = parent_entry
        if parent_raw.strip() and not parent_raw.lstrip().startswith("#"):
            inline_comment = re.search(r"(?:^|\s)(#.*)$", parent_raw)
            comment = f" {inline_comment.group(1)}" if inline_comment else ""
            lines[parent_index] = f"{' ' * parent_indent}{parent[-1]}:{comment}{newline}"
        insert_at = len(lines)
        for index in range(parent_index + 1, len(lines)):
            stripped = lines[index].strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(lines[index]) - len(lines[index].lstrip(" "))
            if indent <= parent_indent:
                insert_at = index
                break
        lines.insert(insert_at, f"{' ' * (parent_indent + 2)}{path[-1]}: {_yaml_quote(value)}{newline}")
        return "".join(lines)
    if len(path) == 1:
        prefix = "" if not text or text.endswith(("\n", "\r")) else newline
        return text + prefix + f"{path[0]}: {_yaml_quote(value)}{newline}"
    if len(path) == 2:
        prefix = "" if not text or text.endswith(("\n", "\r")) else newline
        return text + prefix + f"{path[0]}:{newline}  {path[1]}: {_yaml_quote(value)}{newline}"
    raise RotationError(f"配置缺少字段：{'.'.join(parent)}")


def _env_get(text: str, name: str) -> str | None:
    pattern = re.compile(rf"^[ \t]*(?:export[ \t]+)?{re.escape(name)}[ \t]*=[ \t]*(.*?)[ \t]*$", re.M)
    found = None
    for match in pattern.finditer(text):
        raw, _comment = _yaml_split_comment(match.group(1).strip())
        if raw[:1] == raw[-1:] and raw[:1] in {'"', "'"}:
            if raw[0] == '"':
                try:
                    found = json.loads(raw)
                    continue
                except json.JSONDecodeError:
                    pass
            found = raw[1:-1].replace("''", "'")
        else:
            found = raw
    return found


def _env_set(text: str, name: str, value: str) -> str:
    newline = "\r\n" if "\r\n" in text else "\n"
    pattern = re.compile(rf"^([ \t]*(?:export[ \t]+)?){re.escape(name)}[ \t]*=[ \t]*([^\r\n]*)", re.M)
    if pattern.search(text):
        def replace(match: re.Match) -> str:
            _current, comment = _yaml_split_comment(match.group(2))
            suffix = f" {comment}" if comment else ""
            return f"{match.group(1)}{name}={value}{suffix}"

        # dotenv 通常以最后一个重复定义为准；全部更新可避免旧值继续生效。
        return pattern.sub(replace, text)
    prefix = "" if not text or text.endswith(("\n", "\r")) else newline
    return text + prefix + f"{name}={value}" + newline


def _continue_blocks(text: str) -> list[tuple[str, int, int, int, int]]:
    lines = text.splitlines(keepends=True)
    models_index = next(
        (index for index, line in enumerate(lines) if re.match(r"^\s*models:\s*(?:#.*)?$", line.rstrip("\r\n"))),
        None,
    )
    if models_index is None:
        return []
    models_indent = len(lines[models_index]) - len(lines[models_index].lstrip(" "))
    candidates = []
    item_indent = None
    for index in range(models_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= models_indent:
            break
        if re.match(r"^\s*-\s+", line) and item_indent is None:
            item_indent = indent
        if re.match(r"^\s*-\s+", line) and indent == item_indent:
            candidates.append((index, indent))
    if not candidates:
        return []
    blocks = []
    for position, (start, item_indent) in enumerate(candidates):
        end = candidates[position + 1][0] if position + 1 < len(candidates) else len(lines)
        for index in range(start + 1, end):
            if not lines[index].strip() or lines[index].lstrip().startswith("#"):
                continue
            indent = len(lines[index]) - len(lines[index].lstrip(" "))
            if indent <= models_indent:
                end = index
                break
        body = "".join(lines[start:end])
        score = int(bool(re.search(r"^\s*apiBase:\s*", body, re.M))) + int(
            bool(re.search(r"^\s*apiKey:\s*", body, re.M))
        )
        blocks.append((str(position), score, start, end, item_indent))
    return blocks


def _continue_block(text: str, model_index: str | None = None):
    blocks = _continue_blocks(text)
    if model_index is not None:
        return next((item for item in blocks if item[0] == str(model_index)), None)
    if len(blocks) == 1:
        return blocks[0]
    return None


def _continue_models(text: str) -> list[dict]:
    lines = text.splitlines(keepends=True)
    rows = []
    for model_index, _score, start, end, item_indent in _continue_blocks(text):
        body = "".join(lines[start:end])

        def get(field_name, body=body, item_indent=item_indent):
            matches = list(
                re.finditer(
                    rf"^(?:{' ' * item_indent}-\s*|{' ' * (item_indent + 2)}){field_name}:\s*(.*?)\s*$",
                    body,
                    re.M,
                )
            )
            match = matches[-1] if matches else None
            return _unquote_yaml(match.group(1)) if match else None

        name = get("name") or get("model") or f"模型 {int(model_index) + 1}"
        api_key = get("apiKey") or ""
        secret_match = CONTINUE_SECRET_PATTERN.fullmatch(api_key)
        templated = "${{" in api_key
        rows.append(
            {
                "id": model_index,
                "name": name,
                "provider": get("provider") or "",
                "model": get("model") or "",
                "baseUrl": get("apiBase") or "",
                "writable": not templated or secret_match is not None,
                "secretName": secret_match.group(1) if secret_match else "",
                "blockedReason": "apiKey 使用了无法安全轮换的模板表达式" if templated and not secret_match else "",
            }
        )
    return rows


def _continue_values(text: str, model_index: str | None = None) -> tuple[str | None, str | None]:
    block = _continue_block(text, model_index)
    if not block:
        return None, None
    _model_index, _score, start, end, item_indent = block
    body = "".join(text.splitlines(keepends=True)[start:end])

    def get(field_name):
        matches = list(re.finditer(rf"^{' ' * (item_indent + 2)}{field_name}:\s*(.*?)\s*$", body, re.M))
        match = matches[-1] if matches else None
        return _unquote_yaml(match.group(1)) if match else None

    return get("apiBase"), get("apiKey")


def _continue_set(text: str, base_url: str, api_key: str | None, model_index: str | None = None) -> str:
    block = _continue_block(text, model_index)
    if not block:
        raise RotationError("Continue 没有可更新的 models 配置")
    _model_index, _score, start, end, item_indent = block
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    field_indent = item_indent + 2
    fields = [("apiBase", base_url)]
    if api_key is not None:
        fields.append(("apiKey", api_key))
    for field_name, value in fields:
        found = None
        for index in range(start, end):
            if re.match(rf"^{' ' * field_indent}{field_name}:\s*", lines[index]):
                found = index
        # 重复字段以最后一个为准，与读取行为一致。
        inline_comment = ""
        if found is not None:
            raw = lines[found].split(":", 1)[1].rstrip("\r\n")
            _scalar, inline_comment = _yaml_split_comment(raw)
        suffix = f" {inline_comment}" if inline_comment else ""
        new_line = f"{' ' * field_indent}{field_name}: {_yaml_quote(value)}{suffix}{newline}"
        if found is not None:
            lines[found] = new_line
        else:
            lines.insert(end, new_line)
            end += 1
    return "".join(lines)


def _sqlite_readonly_uri(path: str | Path) -> str:
    return Path(path).resolve().as_uri() + "?mode=ro"


def _vscode_read_secret_named(
    secret_id: str,
    state_db_path: str | None = None,
    local_state_path: str | None = None,
) -> str | None:
    state_db_path = state_db_path or VSCODE_STATE_DB
    local_state_path = local_state_path or VSCODE_LOCAL_STATE
    if not os.path.isfile(state_db_path) or not os.path.isfile(local_state_path):
        return None
    try:
        aes_key = get_vscode_aes_key(local_state_path)
        db = sqlite3.connect(_sqlite_readonly_uri(state_db_path), uri=True)
        try:
            row = db.execute("SELECT value FROM ItemTable WHERE key=?", (f"secret://{secret_id}",)).fetchone()
        finally:
            db.close()
        if not row:
            return None
        payload = json.loads(row[0])
        return vscode_secret_decrypt(bytes(payload["data"]), aes_key)
    except (OSError, RotationError, sqlite3.Error, KeyError, TypeError, json.JSONDecodeError):
        # 新版 VS Code 或沙箱环境可能暂时无法解密；检测仍可继续，写入时再给出明确错误。
        return None


def _vscode_read_secret(state_db_path: str | None = None, local_state_path: str | None = None) -> str | None:
    return _vscode_read_secret_named(VSCODE_SECRET_ID, state_db_path, local_state_path)


def _vscode_extension_state(extension_id: str, state_db_path: str | None = None) -> dict:
    state_db_path = state_db_path or VSCODE_STATE_DB
    if not os.path.isfile(state_db_path):
        return {}
    try:
        db = sqlite3.connect(_sqlite_readonly_uri(state_db_path), uri=True)
        try:
            row = db.execute("SELECT value FROM ItemTable WHERE key=?", (extension_id,)).fetchone()
        finally:
            db.close()
        payload = json.loads(row[0]) if row and isinstance(row[0], str) else {}
        return payload if isinstance(payload, dict) else {}
    except (OSError, sqlite3.Error, TypeError, json.JSONDecodeError):
        return {}


def vscode_secret_storage_status(
    state_db_path: str | None = None,
    local_state_path: str | None = None,
) -> tuple[bool, str]:
    state_db_path = state_db_path or VSCODE_STATE_DB
    local_state_path = local_state_path or VSCODE_LOCAL_STATE
    if not os.path.isfile(state_db_path) or not os.path.isfile(local_state_path):
        return False, "没有找到 VS Code SecretStorage"
    try:
        get_vscode_aes_key(local_state_path)
        db = sqlite3.connect(_sqlite_readonly_uri(state_db_path), uri=True)
        try:
            table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ItemTable'").fetchone()
            if not table:
                return False, "VS Code SecretStorage 数据表不存在"
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return False, "VS Code SecretStorage 数据库检查失败"
        finally:
            db.close()
    except (OSError, RotationError, sqlite3.Error, KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False, "当前无法安全访问 VS Code SecretStorage"
    if not os.access(state_db_path, os.W_OK):
        return False, "VS Code SecretStorage 当前不可写"
    return True, ""


def _vscode_write_secret_named(
    secret_id: str,
    api_key: str,
    state_db_path: str | None = None,
    local_state_path: str | None = None,
):
    state_db_path = state_db_path or VSCODE_STATE_DB
    local_state_path = local_state_path or VSCODE_LOCAL_STATE
    aes_key = get_vscode_aes_key(local_state_path)
    payload = json.dumps({"type": "Buffer", "data": list(vscode_secret_encrypt(api_key, aes_key))})
    db = sqlite3.connect(state_db_path)
    try:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)", (f"secret://{secret_id}", payload))
        db.commit()
        checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint and checkpoint[0]:
            raise RotationError("VS Code SecretStorage 仍被其他进程占用")
    finally:
        db.close()


def _vscode_write_secret(
    api_key: str,
    state_db_path: str | None = None,
    local_state_path: str | None = None,
):
    _vscode_write_secret_named(VSCODE_SECRET_ID, api_key, state_db_path, local_state_path)


def vscode_running() -> bool:
    if os.environ.get("RK_SKIP_VSCODE_CHECK") == "1":
        return False
    try:
        import subprocess

        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Code.exe", "/NH"],
            capture_output=True,
            text=True,
            timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "Code.exe" in result.stdout
    except Exception:
        return False


def _detail(current_url: str | None, current_key: str | None, fallback: str) -> str:
    if current_url and current_key:
        return f"{current_url} · {mask(current_key)}"
    if current_url:
        return f"{current_url} · Key 未设置"
    if current_key:
        return f"地址未设置 · {mask(current_key)}"
    return fallback


def _pi_has_environment_reference(value: str) -> bool:
    """识别 Pi 配置值里的未转义环境变量表达式。"""
    index = 0
    while index < len(value):
        if value[index] != "$":
            index += 1
            continue
        if index + 1 < len(value) and value[index + 1] in {"$", "!"}:
            index += 2
            continue
        if index + 1 < len(value) and (
            value[index + 1] == "{" or value[index + 1].isalpha() or value[index + 1] == "_"
        ):
            return True
        index += 1
    return False


def _pi_credential_status(provider_name: str, provider: dict) -> tuple[bool, str | None, str]:
    """按 Pi 的实际优先级判断 models.json 是否是可安全轮换的凭据源。"""
    auth = _load_json(PI_AUTH, {})
    if not isinstance(auth, dict):
        raise RotationError("Pi auth.json 顶层必须是对象")
    if provider_name in auth:
        return False, None, "Pi auth.json 中已有此提供商凭据，请在 Pi 内使用 /login 或 /logout 管理"

    environment_name = PI_PROVIDER_ENV.get(provider_name)
    if environment_name and os.environ.get(environment_name):
        return False, None, f"进程环境变量 {environment_name} 优先于 models.json，请先清除或更新该变量"

    key = provider.get("apiKey")
    if key is None:
        return True, None, ""
    if not isinstance(key, str):
        raise RotationError("Pi 当前提供方的 apiKey 必须是字符串")
    if key.startswith("!"):
        return False, None, "Pi models.json 通过命令读取密钥，Key Router 不会覆盖该命令"
    if _pi_has_environment_reference(key):
        return False, None, "Pi models.json 通过环境变量读取密钥，Key Router 不会覆盖该引用"
    return True, key, ""


def _state(
    target_id: str,
    options: dict | None = None,
    *,
    extension_versions: dict[str, str] | None = None,
    vscode_instances: list[dict] | None = None,
) -> TargetState:
    title, location_label = TARGET_META[target_id]
    location = {
        "hermes": HERMES_CONFIG,
        "continue": CONTINUE_CONFIG,
        "dsh": DSH_SETTINGS,
        "vscode": CHAT_LM_JSON,
        "opencode_copilot": VSCODE_USER_SETTINGS,
        "deepseek_copilot": VSCODE_USER_SETTINGS,
        "mimo_copilot": VSCODE_USER_SETTINGS,
        "claude": CLAUDE_SETTINGS,
        "pi": PI_MODELS,
    }.get(target_id, location_label)
    options = options if isinstance(options, dict) else {}
    try:
        if target_id == "hermes":
            installations = discover_hermes_installations()
            exists = os.path.isfile(HERMES_ENV) or os.path.isfile(HERMES_CONFIG) or bool(installations)
            env = _read_text(HERMES_ENV) if os.path.isfile(HERMES_ENV) else ""
            config = _read_text(HERMES_CONFIG) if os.path.isfile(HERMES_CONFIG) else ""
            key = _env_get(env, "OPENAI_API_KEY") or _env_get(env, "OPENCODE_GO_API_KEY")
            url = _yaml_get(config, ("model", "base_url"))
            discovery = [
                *installations,
                *[
                    {"path": path, "source": "Hermes 用户配置"}
                    for path in (HERMES_CONFIG, HERMES_ENV)
                    if os.path.isfile(path)
                ],
            ]
        elif target_id == "continue":
            extension = extension_public(target_id, extension_versions, vscode_instances)
            exists = os.path.isfile(CONTINUE_CONFIG)
            config = _read_text(CONTINUE_CONFIG) if exists else ""
            discovery = [{"path": CONTINUE_CONFIG, "source": "标准用户配置"}] if exists else []
            if vscode_instances:
                extension_dirs = [
                    {"path": str(root), "source": "VS Code 扩展目录"}
                    for root in discover_vscode_extension_dirs(vscode_instances)
                    if root.is_dir()
                ]
                discovery = [*vscode_instances, *extension_dirs, *discovery]
            if not extension["installed"]:
                return TargetState(
                    target_id,
                    title,
                    CONTINUE_CONFIG,
                    "missing-extension",
                    "未安装",
                    f"缺少扩展 · {extension['id']}",
                    False,
                    extension=extension,
                    discovery=vscode_instances or discover_vscode_installations(),
                )
            models = _continue_models(config) if exists else []
            if exists and not models:
                return TargetState(
                    target_id,
                    title,
                    CONTINUE_CONFIG,
                    "unsupported",
                    "需配置",
                    "没有可更新的 models 配置",
                    False,
                    extension=extension,
                    discovery=discovery,
                )
            requested_model = str(options.get("modelIndex")) if "modelIndex" in options else ""
            selected_model = next((row for row in models if row["id"] == requested_model), None)
            if len(models) > 1 and selected_model is None:
                return TargetState(
                    target_id,
                    title,
                    CONTINUE_CONFIG,
                    "selection-required",
                    "需选择",
                    f"发现 {len(models)} 个模型，请选择要轮换的模型",
                    False,
                    discovery=discovery,
                    providers=models,
                    extension=extension,
                )
            if selected_model is None and models:
                selected_model = models[0]
            selected_model_id = selected_model["id"] if selected_model else ""
            if selected_model and not selected_model["writable"]:
                return TargetState(
                    target_id,
                    title,
                    CONTINUE_CONFIG,
                    "unsupported",
                    "不可写",
                    selected_model["blockedReason"],
                    False,
                    discovery=discovery,
                    providers=models,
                    selected_provider=selected_model_id,
                    extension=extension,
                )
            url, configured_key = _continue_values(config, selected_model_id or None)
            secret_name = selected_model.get("secretName", "") if selected_model else ""
            continue_env = str(Path(CONTINUE_CONFIG).with_name(".env"))
            env_text = _read_text(continue_env) if secret_name and os.path.isfile(continue_env) else ""
            key = _env_get(env_text, secret_name) if secret_name else configured_key
            if secret_name and os.path.isfile(continue_env):
                discovery.append({"path": continue_env, "source": "Continue 全局密钥"})
            fallback = f"将更新模型 {selected_model['name'] if selected_model else ''}"
            if secret_name:
                fallback += f" · 保留 secrets.{secret_name} 引用"
            return TargetState(
                target_id,
                title,
                CONTINUE_CONFIG,
                "ok" if (url or key) else "ready",
                "已配置" if (url or key) else "可写入",
                _detail(url, key, fallback),
                True,
                url,
                key,
                discovery=discovery,
                providers=models,
                selected_provider=selected_model_id,
                extension=extension,
            )
        elif target_id == "dsh":
            installations = discover_dsh_installations()
            selected_path = str(options.get("settingsPath") or "")
            candidates = discover_dsh_configs(selected_path or None)
            selected = next(
                (
                    item
                    for item in candidates
                    if selected_path and os.path.normcase(item["path"]) == os.path.normcase(selected_path)
                ),
                candidates[0] if candidates else None,
            )
            if not selected:
                detail = "已找到程序，但没有找到 settings.yaml" if installations else "没有找到程序或用户配置"
                return TargetState(
                    target_id,
                    title,
                    installations[0]["path"] if installations else location,
                    "unconfigured" if installations else "missing",
                    "未配置" if installations else "未发现",
                    detail,
                    False,
                    discovery=installations,
                    candidates=candidates,
                )
            settings_path = selected["path"]
            credentials_path = selected["credentialsPath"]
            settings = _read_text(settings_path)
            providers = selected["providers"]
            requested_provider = str(options.get("provider") or "")
            if requested_provider:
                provider = next((row for row in providers if row["id"] == requested_provider), None)
                if provider is None:
                    return TargetState(
                        target_id,
                        title,
                        settings_path,
                        "selection-required",
                        "需选择",
                        "所选提供商已不存在，请重新选择",
                        False,
                        discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                        candidates=candidates,
                        providers=providers,
                    )
            else:
                provider = next((row for row in providers if row["current"]), None)
                writable_providers = [row for row in providers if row["writable"]]
                if provider is None and len(writable_providers) == 1:
                    provider = writable_providers[0]
                elif provider is None and len(writable_providers) > 1:
                    return TargetState(
                        target_id,
                        title,
                        settings_path,
                        "selection-required",
                        "需选择",
                        f"发现 {len(writable_providers)} 个可写提供商，请选择要轮换的提供商",
                        False,
                        discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                        candidates=candidates,
                        providers=providers,
                    )
            if provider is None:
                return TargetState(
                    target_id,
                    title,
                    settings_path,
                    "unsupported",
                    "需配置",
                    "找到配置，但没有带 apiKeyEnv 的可写提供商",
                    False,
                    discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                    candidates=candidates,
                    providers=providers,
                )
            if not provider["writable"]:
                return TargetState(
                    target_id,
                    title,
                    settings_path,
                    "unsupported",
                    "不可写",
                    provider["blockedReason"],
                    False,
                    discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                    candidates=candidates,
                    providers=providers,
                    selected_provider=provider["id"],
                )
            url = provider["baseUrl"] or None
            env_name = provider["apiKeyEnv"]
            credentials = _read_text(credentials_path) if os.path.isfile(credentials_path) else ""
            versioned = _yaml_get(credentials, ("version",)) is not None or bool(
                _yaml_child_keys(credentials, ("refs",))
            )
            key = _yaml_get(credentials, ("refs", env_name) if versioned else (env_name,)) if env_name else None
            return TargetState(
                target_id,
                title,
                settings_path,
                "ok" if (url or key) else "ready",
                "已配置" if (url or key) else "可写入",
                _detail(url, key, f"将更新提供商 {provider['id']}"),
                True,
                url,
                key,
                discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                candidates=candidates,
                providers=providers,
                selected_provider=provider["id"],
            )
        elif target_id == "vscode":
            instances = vscode_instances if vscode_instances is not None else discover_vscode_installations()
            profiles, selected_profile = _select_vscode_profile(instances, options)
            if selected_profile is None:
                return TargetState(
                    target_id,
                    title,
                    "",
                    "selection-required",
                    "需选择",
                    f"发现 {len(profiles)} 个 VS Code 用户数据目录，请选择目标",
                    False,
                    discovery=instances,
                    candidates=profiles,
                )
            profile_paths = _vscode_profile_paths(selected_profile["path"])
            state_db_path = profile_paths["stateDb"]
            local_state_path = profile_paths["localState"]
            settings_path = profile_paths["settings"]
            chat_models_path = profile_paths["chatModels"]
            exists = os.path.isfile(state_db_path) and os.path.isfile(local_state_path)
            providers = _load_json(chat_models_path, []) if exists else []
            provider = next(
                (item for item in providers if isinstance(item, dict) and item.get("name") == "Key Router"), {}
            )
            url = provider.get("url") if isinstance(provider, dict) else None
            discovery = [*instances, selected_profile]
            if os.path.isfile(chat_models_path):
                discovery.append({"path": chat_models_path, "source": "VS Code 自定义模型配置"})
            if os.path.isfile(state_db_path):
                discovery.append({"path": state_db_path, "source": "VS Code 用户数据"})
            capable, reason = vscode_secret_storage_status(state_db_path, local_state_path) if exists else (False, "")
            if exists and not capable:
                return TargetState(
                    target_id,
                    title,
                    state_db_path,
                    "error",
                    "不可写",
                    reason,
                    False,
                    current_url=url,
                    discovery=discovery,
                    candidates=profiles,
                    selected_profile=selected_profile["path"],
                )
            key = _vscode_read_secret(state_db_path, local_state_path) if exists else None
            location = chat_models_path
            return TargetState(
                target_id,
                title,
                location,
                "ok" if (url or key) else "ready",
                "已配置" if (url or key) else "可写入",
                _detail(url, key, "已找到应用，可创建配置"),
                True,
                url,
                key,
                "需退出 VS Code 后写入" if vscode_running() else "",
                discovery=discovery,
                candidates=profiles,
                selected_profile=selected_profile["path"],
            )
        elif target_id in VSCODE_PLUGIN_CONFIG:
            extension = extension_public(target_id, extension_versions, vscode_instances)
            instances = vscode_instances if vscode_instances is not None else discover_vscode_installations()
            if not extension["installed"]:
                return TargetState(
                    target_id,
                    title,
                    VSCODE_USER_SETTINGS,
                    "missing-extension",
                    "未安装",
                    f"缺少扩展 · {extension['id']}",
                    False,
                    extension=extension,
                    discovery=instances,
                )
            profiles, selected_profile = _select_vscode_profile(instances, options)
            if selected_profile is None:
                return TargetState(
                    target_id,
                    title,
                    "",
                    "selection-required",
                    "需选择",
                    f"发现 {len(profiles)} 个 VS Code 用户数据目录，请选择目标",
                    False,
                    discovery=instances,
                    candidates=profiles,
                    extension=extension,
                )
            profile_paths = _vscode_profile_paths(selected_profile["path"])
            state_db_path = profile_paths["stateDb"]
            local_state_path = profile_paths["localState"]
            settings_path = profile_paths["settings"]
            exists = os.path.isfile(state_db_path) and os.path.isfile(local_state_path)
            settings = _load_jsonc(settings_path, {}) if os.path.isfile(settings_path) else {}
            selected_provider = ""
            provider_rows = []
            if target_id == "opencode_copilot":
                extension_state = _vscode_extension_state(EXTENSION_META[target_id]["id"], state_db_path)
                for vendor_id, (vendor_name, vendor_config_key, _vendor_secret_id) in OPENCODE_VENDORS.items():
                    provider_rows.append(
                        {
                            "id": vendor_id,
                            "name": vendor_name,
                            "baseUrl": settings.get(vendor_config_key, "") if isinstance(settings, dict) else "",
                            "writable": not bool(extension_state.get(f"opencode.byokGroup.v1.{vendor_id}", False)),
                        }
                    )
                requested_vendor = str(options.get("vendor") or "opencodego")
                selected = next((row for row in provider_rows if row["id"] == requested_vendor), None)
                if selected is None:
                    return TargetState(
                        target_id,
                        title,
                        settings_path,
                        "unsupported",
                        "需选择",
                        "请选择 OpenCode Go 或 OpenCode Zen",
                        False,
                        discovery=instances,
                        candidates=profiles,
                        providers=provider_rows,
                        selected_profile=selected_profile["path"],
                        extension=extension,
                    )
                if not selected["writable"]:
                    return TargetState(
                        target_id,
                        title,
                        settings_path,
                        "byok-managed",
                        "由 VS Code 管理",
                        f"{selected['name']} 已配置 BYOK 分组，请在 VS Code 的语言模型设置中更换密钥",
                        False,
                        discovery=instances,
                        candidates=profiles,
                        providers=provider_rows,
                        selected_profile=selected_profile["path"],
                        selected_provider=selected["id"],
                        extension=extension,
                    )
                selected_provider = selected["id"]
                _vendor_name, config_key, secret_id = OPENCODE_VENDORS[selected_provider]
            else:
                config_key, secret_id = VSCODE_PLUGIN_CONFIG[target_id]
            url = settings.get(config_key) if isinstance(settings, dict) else None
            discovery = [
                *instances,
                selected_profile,
                *[
                    {"path": str(root), "source": "VS Code 扩展目录"}
                    for root in discover_vscode_extension_dirs(instances)
                    if root.is_dir()
                ],
            ]
            if os.path.isfile(settings_path):
                discovery.append({"path": settings_path, "source": "VS Code 用户设置"})
            if os.path.isfile(state_db_path):
                discovery.append({"path": state_db_path, "source": "VS Code 用户数据"})
            capable, reason = vscode_secret_storage_status(state_db_path, local_state_path) if exists else (False, "")
            if exists and not capable:
                return TargetState(
                    target_id,
                    title,
                    state_db_path,
                    "error",
                    "不可写",
                    reason,
                    False,
                    current_url=url,
                    discovery=discovery,
                    candidates=profiles,
                    selected_profile=selected_profile["path"],
                    extension=extension,
                )
            key = _vscode_read_secret_named(secret_id, state_db_path, local_state_path) if exists else None
            if target_id == "opencode_copilot":
                return TargetState(
                    target_id,
                    title,
                    settings_path,
                    "ok" if (url or key) else "ready",
                    "已配置" if (url or key) else "可写入",
                    _detail(url, key, f"将更新 {OPENCODE_VENDORS[selected_provider][0]}"),
                    True,
                    url,
                    key,
                    "需退出 VS Code 后写入" if vscode_running() else "",
                    discovery=discovery,
                    candidates=profiles,
                    providers=provider_rows,
                    selected_provider=selected_provider,
                    selected_profile=selected_profile["path"],
                    extension=extension,
                )
            location = settings_path
        elif target_id == "claude":
            installations = discover_claude_installations()
            exists = Path(CLAUDE_SETTINGS).parent.is_dir() or os.path.isfile(CLAUDE_SETTINGS) or bool(installations)
            settings = _load_json(CLAUDE_SETTINGS, {}) if exists else {}
            env = settings.get("env", {}) if isinstance(settings, dict) else {}
            url = env.get("ANTHROPIC_BASE_URL") if isinstance(env, dict) else None
            key = (env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY")) if isinstance(env, dict) else None
            discovery = [*installations]
            if os.path.isfile(CLAUDE_SETTINGS):
                discovery.append({"path": CLAUDE_SETTINGS, "source": "Claude 用户配置"})
        else:
            installations = discover_pi_installations()
            exists = (
                Path(PI_SETTINGS).parent.is_dir()
                or os.path.isfile(PI_SETTINGS)
                or os.path.isfile(PI_MODELS)
                or os.path.isfile(PI_AUTH)
                or bool(installations)
            )
            settings = _load_jsonc(PI_SETTINGS, {}) if exists else {}
            if not isinstance(settings, dict):
                raise RotationError("Pi settings.json 顶层必须是对象")
            provider_name = settings.get("defaultProvider") if isinstance(settings, dict) else None
            provider_name = provider_name if isinstance(provider_name, str) and provider_name else "anthropic"
            models = _load_jsonc(PI_MODELS, {}) if exists else {}
            if not isinstance(models, dict):
                raise RotationError("Pi models.json 顶层必须是对象")
            providers = models.get("providers", {}) if isinstance(models, dict) else {}
            if not isinstance(providers, dict):
                raise RotationError("Pi models.json 的 providers 必须是对象")
            provider = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
            discovery = [*installations]
            for path, source in (
                (PI_MODELS, "Pi 模型配置"),
                (PI_AUTH, "Pi 凭据配置"),
                (PI_SETTINGS, "Pi 用户设置"),
            ):
                if os.path.isfile(path):
                    discovery.append({"path": path, "source": source})
            if exists and not provider:
                return TargetState(
                    target_id,
                    title,
                    PI_MODELS,
                    "unconfigured",
                    "需配置",
                    "已找到 Pi，但没有可更新的模型提供商",
                    False,
                    discovery=discovery,
                )
            if not isinstance(provider, dict):
                raise RotationError("Pi 当前提供方配置必须是对象")
            url = provider.get("baseUrl") if isinstance(provider, dict) else None
            writable, key, blocked_reason = _pi_credential_status(provider_name, provider)
            if not writable:
                return TargetState(
                    target_id,
                    title,
                    PI_MODELS,
                    "managed",
                    "凭据托管",
                    blocked_reason,
                    False,
                    url,
                    None,
                    discovery=discovery,
                    selected_provider=provider_name,
                )

        if not exists:
            return TargetState(
                target_id,
                title,
                location,
                "missing",
                "未发现",
                "没有找到本机配置",
                False,
                discovery=discovery,
                extension=locals().get("extension"),
            )
        return TargetState(
            target_id,
            title,
            location,
            "ok" if (url or key) else "ready",
            "已配置" if (url or key) else "可写入",
            _detail(url, key, "已找到应用，可创建配置"),
            True,
            url,
            key,
            "需退出 VS Code 后写入" if target_id in VSCODE_TARGETS and vscode_running() else "",
            discovery=discovery,
            candidates=locals().get("profiles", []),
            selected_profile=(locals().get("selected_profile") or {}).get("path", ""),
            extension=locals().get("extension"),
        )
    except RotationError as exc:
        return TargetState(target_id, title, location, "error", "读取失败", str(exc), False)
    except Exception:
        return TargetState(target_id, title, location, "error", "读取失败", "配置格式不受支持", False)


def detect_targets(target_options: dict | None = None) -> list[dict]:
    options = target_options if isinstance(target_options, dict) else {}
    vscode_instances = discover_vscode_installations()
    extension_versions = installed_vscode_extensions(vscode_instances)
    rows = []
    for target_id in TARGET_ORDER:
        row = _state(
            target_id,
            options.get(target_id),
            extension_versions=extension_versions,
            vscode_instances=vscode_instances,
        ).public()
        if target_id in EXTENSION_META:
            extension = row.get("extension") or extension_public(target_id, extension_versions, vscode_instances)
            roots = discover_vscode_extension_dirs(vscode_instances)
            location = str(
                next((root for root in roots if root.is_dir()), roots[0] if roots else Path(VSCODE_EXTENSIONS_DIR))
            )
            row["installer"] = {
                "targetId": target_id,
                "name": extension["name"],
                "publisher": extension["publisher"],
                "identity": extension["id"],
                "sourceUrl": f"https://marketplace.visualstudio.com/items?itemName={extension['id']}",
                "pathMode": "fixed",
                "folderName": "",
                "sizeLabel": "由 VS Code 管理",
                "note": "扩展安装到当前 VS Code 使用的扩展目录。",
                "kind": "extension",
                "installed": bool(extension["installed"]),
                "enabled": bool(extension["installable"]),
                "location": location,
            }
        elif target_id in agent_installers.INSTALLER_META:
            discoveries = {
                "hermes": discover_hermes_installations,
                "dsh": discover_dsh_installations,
                "claude": discover_claude_installations,
                "pi": discover_pi_installations,
            }[target_id]()
            records = agent_installers.load_install_records(APP_SETTINGS)
            record = records.get(target_id, {}) if isinstance(records, dict) else {}
            location = str(record.get("location") or "") if isinstance(record, dict) else ""
            installer = agent_installers.public_metadata(
                target_id,
                installed=bool(discoveries),
                location=location,
            )
            installer["kind"] = "agent"
            row["installer"] = installer
        else:
            row["installer"] = None
        rows.append(row)
    return rows


def _plan_hermes(
    base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    plan = TargetPlan(state or _state("hermes"))
    env_text = _read_text(HERMES_ENV) if os.path.isfile(HERMES_ENV) else ""
    config_text = _read_text(HERMES_CONFIG) if os.path.isfile(HERMES_CONFIG) else ""
    new_env = _env_set(env_text, "OPENAI_API_KEY", api_key)
    new_config = _yaml_set(config_text, ("model", "provider"), "custom")
    new_config = _yaml_set(new_config, ("model", "base_url"), base_url)
    if new_env != env_text:
        plan.changes.append(Change("hermes", HERMES_ENV, "OPENAI_API_KEY", new_env))
    if new_config != config_text:
        plan.changes.append(Change("hermes", HERMES_CONFIG, "model.provider / model.base_url", new_config))
    return plan


def _plan_continue(
    base_url: str, api_key: str, options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    option = options if isinstance(options, dict) else {}
    plan = TargetPlan(state or _state("continue", option))
    text = _read_text(CONTINUE_CONFIG)
    model_index = plan.target.selected_provider or str(option.get("modelIndex") or "")
    if not model_index and len(_continue_blocks(text)) > 1:
        raise RotationError("Continue 有多个模型，请先选择要轮换的模型")
    _current_url, configured_key = _continue_values(text, model_index or None)
    secret_match = CONTINUE_SECRET_PATTERN.fullmatch(configured_key or "")
    if configured_key and "${{" in configured_key and not secret_match:
        raise RotationError("Continue 当前模型的 apiKey 使用了无法安全轮换的模板表达式")
    updated = _continue_set(text, base_url, None if secret_match else api_key, model_index or None)
    if updated != text:
        summary = "模型 apiBase" if secret_match else "模型 apiBase / apiKey"
        plan.changes.append(Change("continue", CONTINUE_CONFIG, summary, updated))
    if secret_match:
        secret_name = secret_match.group(1)
        env_path = str(Path(CONTINUE_CONFIG).with_name(".env"))
        env_text = _read_text(env_path) if os.path.isfile(env_path) else ""
        updated_env = _env_set(env_text, secret_name, api_key)
        if updated_env != env_text:
            plan.changes.append(Change("continue", env_path, f".env · {secret_name}", updated_env))
    return plan


def _plan_dsh(base_url: str, api_key: str, options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    option = options if isinstance(options, dict) else {}
    target_state = state or _state("dsh", option)
    plan = TargetPlan(target_state)
    settings_path = target_state.location
    candidates = discover_dsh_configs(str(option.get("settingsPath") or settings_path))
    candidate = next(
        (item for item in candidates if os.path.normcase(item["path"]) == os.path.normcase(settings_path)),
        None,
    )
    if not candidate:
        raise RotationError("dsh 配置位置已变化，请重新检测")
    credentials_path = candidate["credentialsPath"]
    settings = _read_text(settings_path)
    provider = target_state.selected_provider or str(option.get("provider") or "")
    if not provider:
        raise RotationError("dsh 没有可更新的提供方")
    env_name = _yaml_get(settings, ("llm-pi-ai", "providers", provider, "apiKeyEnv"))
    if not env_name:
        raise RotationError("dsh 当前提供方没有 apiKeyEnv")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
        raise RotationError("dsh 当前提供方的 apiKeyEnv 不是有效凭据引用")
    updated_settings = _yaml_set(settings, ("llm-pi-ai", "providers", provider, "baseURL"), base_url)
    credentials = _read_text(credentials_path) if os.path.isfile(credentials_path) else "version: 1\nrefs:\n"
    if not credentials.strip():
        credentials = "version: 1\nrefs:\n"
    if _yaml_get(credentials, ("version",)) is not None or _yaml_child_keys(credentials, ("refs",)):
        updated_credentials = _yaml_set(credentials, ("refs", env_name), api_key)
    else:
        # 兼容 dsh 预发布版的顶层平铺凭据格式；dsh 下次启动时会自行迁移。
        updated_credentials = _yaml_set(credentials, (env_name,), api_key)
    if updated_settings != settings:
        plan.changes.append(Change("dsh", settings_path, f"providers.{provider}.baseURL", updated_settings))
    if updated_credentials != credentials:
        plan.changes.append(Change("dsh", credentials_path, f"refs.{env_name}", updated_credentials))
    return plan


def _plan_vscode(
    base_url: str, api_key: str, options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    option = options if isinstance(options, dict) else {}
    plan = TargetPlan(state or _state("vscode", option))
    profile_paths = _vscode_profile_paths(option.get("userDataDir") or plan.target.selected_profile or None)
    state_db_path = profile_paths["stateDb"]
    local_state_path = profile_paths["localState"]
    chat_models_path = profile_paths["chatModels"]
    providers = _load_json(chat_models_path, [])
    if not isinstance(providers, list):
        raise RotationError("chatLanguageModels.json 顶层必须是数组")
    provider = next((item for item in providers if isinstance(item, dict) and item.get("name") == "Key Router"), None)
    if provider is None:
        provider = {
            "name": "Key Router",
            "vendor": "customendpoint",
            "apiKey": VSCODE_SECRET_REF,
            "apiType": "chat-completions",
            "url": base_url,
        }
        providers.append(provider)
    else:
        provider["vendor"] = "customendpoint"
        provider["apiKey"] = VSCODE_SECRET_REF
        provider.setdefault("apiType", "chat-completions")
        provider["url"] = base_url
        if isinstance(provider.get("models"), list):
            for model in provider["models"]:
                if isinstance(model, dict) and "url" in model:
                    model["url"] = base_url
    updated_providers = _json_dump(providers)
    current_providers = _read_text(chat_models_path) if os.path.isfile(chat_models_path) else ""
    if updated_providers != current_providers:
        plan.changes.append(Change("vscode", chat_models_path, "Key Router Custom Endpoint", updated_providers))
    if _vscode_read_secret(state_db_path, local_state_path) != api_key:
        plan.changes.append(
            Change(
                "vscode",
                state_db_path,
                "SecretStorage API Key",
                action=lambda: _vscode_write_secret(api_key, state_db_path, local_state_path),
            )
        )
    if vscode_running():
        plan.warnings.append("VS Code 正在运行，正式应用前必须完全退出")
    return plan


def _plan_vscode_plugin(
    target_id: str,
    base_url: str,
    api_key: str,
    options: dict | None = None,
    state: TargetState | None = None,
) -> TargetPlan:
    option = options if isinstance(options, dict) else {}
    plan = TargetPlan(state or _state(target_id, option))
    profile_paths = _vscode_profile_paths(option.get("userDataDir") or plan.target.selected_profile or None)
    state_db_path = profile_paths["stateDb"]
    local_state_path = profile_paths["localState"]
    settings_path = profile_paths["settings"]
    if target_id == "opencode_copilot":
        vendor = plan.target.selected_provider or "opencodego"
        if vendor not in OPENCODE_VENDORS:
            raise RotationError("OpenCode 目标提供商无效")
        _vendor_name, config_key, secret_id = OPENCODE_VENDORS[vendor]
    else:
        config_key, secret_id = VSCODE_PLUGIN_CONFIG[target_id]
    settings = _read_text(settings_path) if os.path.isfile(settings_path) else "{}\n"
    updated = _jsonc_set_top_level(settings, config_key, base_url)
    if updated != settings:

        def write_setting(config_key=config_key):
            current = _read_text(settings_path) if os.path.isfile(settings_path) else "{}\n"
            _atomic_write_text(settings_path, _jsonc_set_top_level(current, config_key, base_url))

        plan.changes.append(Change(target_id, settings_path, config_key, action=write_setting))
    if _vscode_read_secret_named(secret_id, state_db_path, local_state_path) != api_key:
        plan.changes.append(
            Change(
                target_id,
                state_db_path,
                f"SecretStorage · {secret_id}",
                action=lambda secret_id=secret_id: _vscode_write_secret_named(
                    secret_id,
                    api_key,
                    state_db_path,
                    local_state_path,
                ),
            )
        )
    if vscode_running():
        plan.warnings.append("VS Code 正在运行，正式应用前必须完全退出")
    return plan


def _plan_opencode_copilot(
    base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    return _plan_vscode_plugin("opencode_copilot", base_url, api_key, _options, state)


def _plan_deepseek_copilot(
    base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    return _plan_vscode_plugin("deepseek_copilot", base_url, api_key, _options, state)


def _plan_mimo_copilot(
    base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    return _plan_vscode_plugin("mimo_copilot", base_url, api_key, _options, state)


def _plan_claude(
    base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None
) -> TargetPlan:
    plan = TargetPlan(state or _state("claude"))
    settings = _load_json(CLAUDE_SETTINGS, {})
    if not isinstance(settings, dict):
        raise RotationError("Claude Code settings.json 顶层必须是对象")
    env = settings.setdefault("env", {})
    if not isinstance(env, dict):
        raise RotationError("Claude Code settings.json 的 env 必须是对象")
    env["ANTHROPIC_BASE_URL"] = base_url
    if "ANTHROPIC_AUTH_TOKEN" in env and "ANTHROPIC_API_KEY" not in env:
        env["ANTHROPIC_AUTH_TOKEN"] = api_key
    else:
        env["ANTHROPIC_API_KEY"] = api_key
        if "ANTHROPIC_AUTH_TOKEN" in env:
            env["ANTHROPIC_AUTH_TOKEN"] = api_key
    updated = _json_dump(settings)
    existing = _read_text(CLAUDE_SETTINGS) if os.path.isfile(CLAUDE_SETTINGS) else ""
    if updated != existing:
        plan.changes.append(Change("claude", CLAUDE_SETTINGS, "ANTHROPIC_BASE_URL / 认证令牌", updated))
    return plan


def _plan_pi(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    plan = TargetPlan(state or _state("pi"))
    settings = _load_jsonc(PI_SETTINGS, {})
    if not isinstance(settings, dict):
        raise RotationError("Pi settings.json 顶层必须是对象")
    provider_name = settings.get("defaultProvider") if isinstance(settings, dict) else None
    provider_name = provider_name if isinstance(provider_name, str) and provider_name else "anthropic"
    models = _load_jsonc(PI_MODELS, {})
    if not isinstance(models, dict):
        raise RotationError("Pi models.json 顶层必须是对象")
    providers = models.setdefault("providers", {})
    if not isinstance(providers, dict):
        raise RotationError("Pi models.json 的 providers 必须是对象")
    provider = providers.setdefault(provider_name, {})
    if not isinstance(provider, dict):
        raise RotationError("Pi 当前提供方配置必须是对象")
    writable, _current_key, blocked_reason = _pi_credential_status(provider_name, provider)
    if not writable:
        raise RotationError(blocked_reason)
    provider["baseUrl"] = base_url
    provider["apiKey"] = api_key
    existing = _read_text(PI_MODELS) if os.path.isfile(PI_MODELS) else ""
    updated = _jsonc_replace_nested_strings(
        existing,
        ("providers", provider_name),
        {"baseUrl": base_url, "apiKey": api_key},
    )
    if updated is None:
        updated = _json_dump(models)
    if updated != existing:
        plan.changes.append(Change("pi", PI_MODELS, f"providers.{provider_name}.baseUrl / apiKey", updated))
    return plan


PLANNERS = {
    "hermes": _plan_hermes,
    "continue": _plan_continue,
    "dsh": _plan_dsh,
    "vscode": _plan_vscode,
    "opencode_copilot": _plan_opencode_copilot,
    "deepseek_copilot": _plan_deepseek_copilot,
    "mimo_copilot": _plan_mimo_copilot,
    "claude": _plan_claude,
    "pi": _plan_pi,
}


def _is_sqlite_config(path: str) -> bool:
    candidate = Path(path)
    is_default = os.path.normcase(os.path.normpath(path)) == os.path.normcase(os.path.normpath(VSCODE_STATE_DB))
    return is_default or (candidate.name.lower() == "state.vscdb" and candidate.parent.name.lower() == "globalstorage")


def _sqlite_snapshot(source: Path, destination: Path):
    """使用 SQLite 在线备份 API，确保 WAL 中已提交的数据也进入备份。"""
    source_db = sqlite3.connect(_sqlite_readonly_uri(source), uri=True)
    destination_db = sqlite3.connect(str(destination))
    try:
        source_db.execute("PRAGMA busy_timeout=5000")
        source_db.backup(destination_db)
        if destination_db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RotationError("VS Code SecretStorage 备份校验失败")
    finally:
        destination_db.close()
        source_db.close()
    shutil.copystat(source, destination)


def _clear_sqlite_sidecars(path: str):
    for suffix in ("-wal", "-shm"):
        sidecar = Path(path + suffix)
        if sidecar.is_file():
            sidecar.unlink()


def _backup(paths: list[str]) -> tuple[str, dict[str, str | None]]:
    timestamp = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"
    backup_root = Path(BACKUP_DIR)
    backup_root.mkdir(parents=True, exist_ok=True)
    backup_dir = Path(tempfile.mkdtemp(prefix=f"{timestamp}-", dir=backup_root))
    mapping: dict[str, str | None] = {}
    manifest = []
    for index, path in enumerate(dict.fromkeys(paths), start=1):
        source = Path(path)
        if source.is_file():
            backup_path = backup_dir / f"{index:02d}-{source.name}"
            if _is_sqlite_config(path):
                snapshot_path = backup_dir / f".{index:02d}-{source.name}.snapshot"
                try:
                    _sqlite_snapshot(source, snapshot_path)
                    source_data = snapshot_path.read_bytes()
                finally:
                    if snapshot_path.exists():
                        snapshot_path.unlink()
            else:
                source_data = source.read_bytes()
            try:
                protected = BACKUP_MAGIC + dpapi_encrypt(source_data)
            except OSError as exc:
                raise RotationError("无法加密配置备份，已停止写入") from exc
            _atomic_write_bytes(str(backup_path), protected)
            mapping[path] = str(backup_path)
            manifest.append(
                {
                    "path": path,
                    "backup": backup_path.name,
                    "existed": True,
                    "protection": "windows-dpapi-v1",
                }
            )
        else:
            mapping[path] = None
            manifest.append({"path": path, "backup": None, "existed": False})
    manifest_text = _json_dump(manifest)
    _atomic_write_text(str(backup_dir / "manifest.json"), manifest_text)
    try:
        protected_manifest = BACKUP_MAGIC + dpapi_encrypt(manifest_text.encode("utf-8"))
    except OSError as exc:
        raise RotationError("无法保护备份清单，已停止写入") from exc
    _atomic_write_bytes(str(backup_dir / BACKUP_MANIFEST), protected_manifest)
    return str(backup_dir), mapping


def _restore(mapping: dict[str, str | None]):
    errors = []
    for path, backup_path in reversed(list(mapping.items())):
        try:
            if _is_sqlite_config(path):
                _clear_sqlite_sidecars(path)
            if backup_path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                backup_data = Path(backup_path).read_bytes()
                if backup_data.startswith(BACKUP_MAGIC):
                    backup_data = dpapi_decrypt(backup_data[len(BACKUP_MAGIC) :])
                _atomic_write_bytes(path, backup_data)
            elif os.path.isfile(path):
                os.unlink(path)
            if _is_sqlite_config(path):
                _clear_sqlite_sidecars(path)
        except OSError as exc:
            errors.append((path, exc))
    if errors:
        raise RotationError(f"有 {len(errors)} 个配置位置未能恢复") from errors[0][1]


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((os.path.normcase(str(path)), os.path.normcase(str(parent)))) == os.path.normcase(
            str(parent)
        )
    except ValueError:
        return False


def _restore_backup_directory_unlocked(backup_directory: str) -> int:
    """从 Key Router 自己创建的备份目录恢复，并在改动前校验完整清单。"""
    if not isinstance(backup_directory, str) or not backup_directory.strip():
        raise RotationError("请指定备份目录")
    try:
        backup_root = Path(BACKUP_DIR).resolve(strict=True)
        selected = Path(backup_directory).expanduser().resolve(strict=True)
    except OSError as exc:
        raise RotationError("备份目录不存在或无法访问") from exc
    if not selected.is_dir() or selected == backup_root or not _path_is_within(selected, backup_root):
        raise RotationError("只能恢复 Key Router 备份目录中的一个具体备份")

    protected_manifest_path = selected / BACKUP_MANIFEST
    try:
        if protected_manifest_path.is_file():
            protected = protected_manifest_path.read_bytes()
            if not protected.startswith(BACKUP_MAGIC):
                raise RotationError("受保护的备份清单格式无效")
            manifest_text = dpapi_decrypt(protected[len(BACKUP_MAGIC) :]).decode("utf-8")
        else:
            # 兼容引入受保护清单之前创建的旧备份。
            manifest_text = (selected / "manifest.json").read_text(encoding="utf-8-sig")
        manifest = json.loads(manifest_text)
    except RotationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RotationError("备份清单损坏或不属于当前 Windows 用户") from exc
    if not isinstance(manifest, list) or not manifest:
        raise RotationError("备份清单为空或格式无效")

    mapping: dict[str, str | None] = {}
    for row in manifest:
        if not isinstance(row, dict):
            raise RotationError("备份清单包含无效记录")
        target_value = row.get("path")
        existed = row.get("existed")
        backup_name = row.get("backup")
        if not isinstance(target_value, str) or not target_value or not Path(target_value).is_absolute():
            raise RotationError("备份清单包含无效目标路径")
        if target_value in mapping or not isinstance(existed, bool):
            raise RotationError("备份清单包含重复或无效记录")
        if existed:
            if not isinstance(backup_name, str) or Path(backup_name).name != backup_name:
                raise RotationError("备份清单包含无效文件名")
            try:
                backup_path = (selected / backup_name).resolve(strict=True)
            except OSError as exc:
                raise RotationError("备份文件缺失") from exc
            if not backup_path.is_file() or not _path_is_within(backup_path, selected):
                raise RotationError("备份文件不在所选备份目录中")
            protection = row.get("protection")
            if protection not in (None, "windows-dpapi-v1"):
                raise RotationError("备份使用了不支持的保护格式")
            try:
                backup_data = backup_path.read_bytes()
                if protection == "windows-dpapi-v1" and not backup_data.startswith(BACKUP_MAGIC):
                    raise RotationError("受保护的备份文件格式无效")
                if backup_data.startswith(BACKUP_MAGIC):
                    dpapi_decrypt(backup_data[len(BACKUP_MAGIC) :])
            except RotationError:
                raise
            except OSError as exc:
                raise RotationError("备份文件损坏或不属于当前 Windows 用户") from exc
            mapping[target_value] = str(backup_path)
        else:
            if backup_name is not None:
                raise RotationError("备份清单中的新建文件记录无效")
            mapping[target_value] = None

    _restore(mapping)
    return len(mapping)


def restore_backup_directory(backup_directory: str) -> int:
    lock = _configuration_lock()
    if not lock.acquire():
        raise RotationError("另一个 Key Router 正在修改配置，请稍候")
    try:
        return _restore_backup_directory_unlocked(backup_directory)
    finally:
        lock.release()


def _file_state_digest(path: str) -> str:
    """对一个配置位置取稳定摘要；SQLite 同时纳入 WAL/SHM。"""
    digest = hashlib.sha256()
    candidates = [Path(path)]
    if _is_sqlite_config(path):
        candidates.extend((Path(path + "-wal"), Path(path + "-shm")))
    for candidate in candidates:
        digest.update(str(candidate).encode("utf-8", errors="surrogatepass"))
        if not candidate.is_file():
            digest.update(b"\0missing\0")
            continue
        try:
            before = candidate.stat()
            digest.update(b"\0file\0")
            with candidate.open("rb") as file:
                for chunk in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = candidate.stat()
        except OSError as exc:
            raise RotationError(f"无法读取配置状态：{candidate.name}") from exc
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RotationError(f"配置正在变化，请稍后重新预览：{candidate.name}")
    return digest.hexdigest()


def _plan_digest(changes: list[Change]) -> str:
    """绑定预览计划和所有输入文件状态，但不暴露配置或密钥内容。"""
    digest = hashlib.sha256()
    source_digests = {}
    for change in changes:
        if change.path not in source_digests:
            source_digests[change.path] = _file_state_digest(change.path)
        digest.update(change.target_id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(change.path.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        digest.update(change.summary.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source_digests[change.path].encode("ascii"))
        digest.update(b"\0")
        if change.after_text is not None:
            digest.update(hashlib.sha256(change.after_text.encode("utf-8")).digest())
        else:
            digest.update(b"action")
    return digest.hexdigest()


def run_rotation(
    base_url: str,
    new_key: str,
    target_ids: list[str] | tuple[str, ...],
    *,
    apply: bool = False,
    target_options: dict | None = None,
    expected_plan_digest: str | None = None,
    log: Callable[[str], None] | None = _console_log,
) -> dict:
    """预览或执行批量配置。返回值不包含完整密钥。"""
    url = validate_base_url(base_url)
    key = validate_key(new_key)
    selected = list(dict.fromkeys(target_ids))
    if not selected:
        raise RotationError("请至少选择一个目标工具")
    if any(target_id not in PLANNERS for target_id in selected):
        raise RotationError("包含不支持的目标工具")
    options = target_options if isinstance(target_options, dict) else {}
    if any(key not in selected for key in options):
        raise RotationError("目标选项与所选工具不一致")
    for target_id, value in options.items():
        if target_id not in {"continue", "dsh", *VSCODE_TARGETS} or not isinstance(value, dict):
            raise RotationError("目标选项无效")
        if target_id == "continue":
            allowed = {"modelIndex"}
        elif target_id in VSCODE_TARGETS:
            allowed = {"userDataDir"}
            if target_id == "opencode_copilot":
                allowed.add("vendor")
        else:
            allowed = {"settingsPath", "provider"}
        if any(key not in allowed for key in value):
            raise RotationError(f"{target_id} 目标选项包含未知字段")
        if any(not isinstance(item, str) for item in value.values()):
            raise RotationError(f"{target_id} 目标选项格式无效")

    messages: list[str] = []

    def emit(message: str = ""):
        messages.append(message)
        if log:
            log(message)

    vscode_instances = (
        discover_vscode_installations() if any(item in VSCODE_DISCOVERY_TARGETS for item in selected) else []
    )
    extension_versions = (
        installed_vscode_extensions(vscode_instances) if any(item in EXTENSION_META for item in selected) else {}
    )
    plans: list[TargetPlan] = []
    for target_id in selected:
        target_option = options.get(target_id)
        state = _state(
            target_id,
            target_option,
            extension_versions=extension_versions,
            vscode_instances=vscode_instances,
        )
        if not state.selectable:
            raise RotationError(f"{state.title} 当前不可写入：{state.detail}")
        plans.append(PLANNERS[target_id](url, key, target_option, state))
    changes = [change for plan in plans for change in plan.changes]
    if not changes:
        raise RotationError("所选工具已经是这组配置，无需修改")
    plan_digest = _plan_digest(changes)
    if expected_plan_digest is not None and not hmac.compare_digest(expected_plan_digest, plan_digest):
        raise RotationError("配置文件在预览后发生变化，请重新预览")
    if apply and any(target_id in VSCODE_TARGETS for target_id in selected) and vscode_running():
        raise RotationError("VS Code 正在运行，请完全退出后重新预览")

    emit("预览模式，不会写入文件" if not apply else "正在备份并应用更改")
    emit(f"Base URL：{url}")
    emit(f"API Key：{mask(key)}")
    emit("")
    for plan in plans:
        emit(f"【{plan.target.title}】")
        for change in plan.changes:
            emit(f"  将更新 {Path(change.path).name} · {change.summary}")
        for warning in plan.warnings:
            emit(f"  注意：{warning}")

    backup_dir = None
    if apply:
        lock = _configuration_lock()
        if not lock.acquire():
            raise RotationError("另一个 Key Router 正在修改配置，请稍候")
        try:
            if not hmac.compare_digest(plan_digest, _plan_digest(changes)):
                raise RotationError("配置文件在生成计划后发生变化，请重新预览")
            backup_dir, mapping = _backup([change.path for change in changes])
            if not hmac.compare_digest(plan_digest, _plan_digest(changes)):
                raise RotationError("配置文件在备份期间发生变化，请重新预览")
            emit("")
            emit(f"已备份 {len(mapping)} 个配置位置")
            try:
                for change in changes:
                    change.apply()
                verification_plans = []
                for target_id in selected:
                    target_option = options.get(target_id)
                    verified_state = _state(
                        target_id,
                        target_option,
                        extension_versions=extension_versions,
                        vscode_instances=vscode_instances,
                    )
                    if not verified_state.selectable:
                        raise RotationError(f"{verified_state.title} 写入后无法验证：{verified_state.detail}")
                    verification_plans.append(PLANNERS[target_id](url, key, target_option, verified_state))
                remaining = [change for plan in verification_plans for change in plan.changes]
                if remaining:
                    raise RotationError("写入后验证失败，仍有配置未达到预期状态")
            except Exception as exc:
                try:
                    _restore(mapping)
                except Exception:
                    command = f'Key-Router.exe --restore-backup "{backup_dir}"'
                    raise RotationError(f"写入失败，且自动恢复未完全成功；请运行：{command}") from exc
                raise RotationError("写入失败，已从备份恢复原配置") from exc
            emit(f"已完成 {len(plans)} 个工具的批量配置")
        finally:
            lock.release()
    else:
        emit("")
        emit(f"预览完成：{len(plans)} 个工具，{len(changes)} 处更改")

    return {
        "applied": apply,
        "backup_dir": backup_dir,
        "vscode_running": vscode_running() if any(target_id in VSCODE_TARGETS for target_id in selected) else False,
        "target_ids": selected,
        "change_count": len(changes),
        "plan_digest": plan_digest,
        "changes": [
            {
                "targetId": plan.target.id,
                "target": plan.target.title,
                "file": Path(change.path).name,
                "path": change.path,
                "summary": change.summary,
            }
            for plan in plans
            for change in plan.changes
        ],
        "new_key_masked": mask(key),
        "base_url": url,
        "messages": messages,
    }


def main():
    _configure_console_streams()
    parser = argparse.ArgumentParser(description="Key Router · 批量配置 API 地址与密钥")
    parser.add_argument("--detect", action="store_true", help="检测支持的本机工具")
    parser.add_argument("--restore-backup", metavar="DIR", help="从指定的 Key Router 备份目录恢复")
    parser.add_argument("--url", help="新的 API Base URL")
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key", help="新的 API Key（会出现在命令历史中，交互使用建议省略）")
    key_group.add_argument("--key-stdin", action="store_true", help="从标准输入读取 API Key")
    parser.add_argument("--targets", default=",".join(TARGET_ORDER), help="逗号分隔的目标 ID")
    parser.add_argument("--apply", action="store_true", help="正式写入；默认只预览")
    args = parser.parse_args()
    if args.restore_backup:
        try:
            restored = restore_backup_directory(args.restore_backup)
        except RotationError as exc:
            raise SystemExit(f"错误：{exc}") from exc
        print(f"已从备份恢复 {restored} 个配置位置")
        return
    if args.detect:
        for item in detect_targets():
            print(f"{item['title']}: {item['badge']} · {item['detail']}")
        return
    if args.key_stdin:
        cli_key = sys.stdin.readline().rstrip("\r\n")
    elif args.key is not None:
        cli_key = args.key
    else:
        cli_key = getpass.getpass("新的 API Key：")
    try:
        run_rotation(
            args.url or "",
            cli_key,
            [item.strip() for item in args.targets.split(",") if item.strip()],
            apply=args.apply,
        )
    except RotationError as exc:
        raise SystemExit(f"错误：{exc}") from exc


if __name__ == "__main__":
    main()
