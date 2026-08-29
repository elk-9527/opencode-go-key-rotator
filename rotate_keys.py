# -*- coding: utf-8 -*-
"""Key Router 核心：把一组 Base URL + API Key 安全写入多个 AI 工具。

默认只预览；正式写入前备份全部目标文件。每个适配器只修改明确字段，
不全盘搜索或替换疑似密钥的字符串。日志与返回值均不包含完整密钥。
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
from dataclasses import dataclass, field
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import agent_installers


class RotationError(RuntimeError):
    """可安全展示给界面的错误。"""


def _paths() -> dict[str, str]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    localappdata = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
    # Hermes 的用户配置目录与程序安装目录是两回事。官方默认使用
    # ~/.hermes；HERMES_HOME 只在用户显式覆盖时生效。
    hermes_home = Path(os.environ.get("HERMES_HOME") or home / ".hermes")
    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home / ".claude")
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
        "PI_SETTINGS": str(home / ".pi" / "agent" / "settings.json"),
        "PI_MODELS": str(home / ".pi" / "agent" / "models.json"),
        "BACKUP_DIR": str(app_home / "backups"),
        "APP_SETTINGS": str(app_home / "settings.json"),
    }
    override = os.environ.get("RK_PATHS_JSON")
    if override:
        paths.update({key: str(value) for key, value in json.loads(override).items()})
    return paths


PATHS = _paths()
globals().update(PATHS)


def refresh_runtime_paths() -> None:
    """安装器更新环境变量后，重新解析当前进程使用的配置路径。"""
    global PATHS
    PATHS = _paths()
    globals().update(PATHS)

TARGET_ORDER = (
    "hermes", "continue", "dsh", "vscode",
    "opencode_copilot", "deepseek_copilot", "mimo_copilot",
    "claude", "pi",
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
VSCODE_TARGETS = {"vscode", *VSCODE_PLUGIN_CONFIG}
VSCODE_DISCOVERY_TARGETS = {"continue", *VSCODE_TARGETS}

VSCODE_SECRET_ID = "chat.lm.secret.key-router-api-key"
VSCODE_SECRET_KEY = f"secret://{VSCODE_SECRET_ID}"
VSCODE_SECRET_REF = "${input:" + VSCODE_SECRET_ID + "}"


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
    powershell = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=6, env=environment,
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
            for row in rows if isinstance(row, dict)
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
        rows.append({
            "id": provider_id,
            "name": _yaml_get(settings_text, prefix + ("displayName",)) or provider_id,
            "baseUrl": _yaml_get(settings_text, prefix + ("baseURL",)) or "",
            "apiKeyEnv": _yaml_get(settings_text, prefix + ("apiKeyEnv",)) or "",
            "current": provider_id == current,
            "writable": bool(_yaml_get(settings_text, prefix + ("apiKeyEnv",))),
        })
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
        candidates.append({
            "path": str(path),
            "credentialsPath": str(path.parent / ".credentials.yaml"),
            "source": source,
            "providers": providers,
            "currentProvider": next((row["id"] for row in providers if row["current"]), ""),
        })
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
    return {
        os.path.normcase(str(name))
        for name, obsolete in payload.items()
        if obsolete
    }


def installed_vscode_extensions(
    instances: list[dict] | None = None,
    *,
    query_cli: bool = False,
) -> dict[str, str]:
    installed: dict[str, str] = {}
    vscode = instances if instances is not None else discover_vscode_installations()
    for root in discover_vscode_extension_dirs(vscode):
        if not root.is_dir():
            continue
        obsolete = _obsolete_extension_directories(root)
        for directory in root.iterdir():
            if not directory.is_dir():
                continue
            if os.path.normcase(directory.name) in obsolete:
                continue
            lower = directory.name.lower()
            for metadata in EXTENSION_META.values():
                extension_id = metadata["id"].lower()
                if lower == extension_id or lower.startswith(extension_id + "-"):
                    version = directory.name[len(extension_id):].lstrip("-")
                    installed[extension_id] = version or "已安装"
    if query_cli and vscode:
        instance = vscode[0]
        executable = instance.get("cli") or instance["path"]
        try:
            result = subprocess.run(
                [executable, *_vscode_instance_cli_args(instance), "--list-extensions", "--show-versions"],
                capture_output=True, text=True, timeout=12, creationflags=_creation_flags(),
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


def install_vscode_extension(extension_id: str) -> dict:
    """仅安装白名单中的 VS Code 扩展；调用前应由界面取得用户确认。"""
    allowed = {metadata["id"].lower(): metadata for metadata in EXTENSION_META.values()}
    metadata = allowed.get(extension_id.lower())
    if not metadata:
        raise RotationError("该扩展不在 Key Router 的安装白名单中")
    instances = discover_vscode_installations()
    if not instances:
        raise RotationError("没有找到 VS Code，无法安装扩展")
    instance = instances[0]
    executable = instance.get("cli") or instance["path"]
    try:
        result = subprocess.run(
            [executable, *_vscode_instance_cli_args(instance), "--install-extension", metadata["id"], "--force"],
            capture_output=True, text=True, timeout=180, creationflags=_creation_flags(),
        )
    except subprocess.TimeoutExpired as exc:
        raise RotationError("扩展安装超时，请检查网络或 VS Code 代理设置") from exc
    except OSError as exc:
        raise RotationError("无法启动 VS Code 扩展安装程序") from exc
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode != 0:
        short = output.splitlines()[-1] if output else f"退出码 {result.returncode}"
        raise RotationError(f"扩展安装失败：{short[:300]}")
    versions = installed_vscode_extensions(instances, query_cli=True)
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


def dpapi_decrypt(blob: bytes) -> bytes:
    source = DATA_BLOB(
        len(blob), ctypes.cast(ctypes.create_string_buffer(blob), ctypes.POINTER(ctypes.c_byte))
    )
    output = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(output)
    )
    if not ok:
        raise OSError("无法解密 VS Code 本机密钥")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def get_vscode_aes_key() -> bytes:
    with open(VSCODE_LOCAL_STATE, encoding="utf-8") as file:
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
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}…{value[-4:]} ({len(value)})"


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
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RotationError("Base URL 不能包含账号、密码、查询参数或锚点")
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "http" and parsed.hostname.lower() not in local_hosts:
        raise RotationError("远程地址必须使用 HTTPS；HTTP 仅允许本机地址")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8-sig", errors="strict", newline="") as file:
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
            while index + 1 < len(text) and text[index:index + 2] != "*/":
                index += 1
            index += 2
        else:
            output.append(char)
            index += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(output))


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
    encoded_key = json.dumps(key, ensure_ascii=False)
    encoded_value = json.dumps(value, ensure_ascii=False)
    pattern = re.compile(rf'({re.escape(encoded_key)}\s*:\s*)"(?:\\.|[^"\\])*"')
    if pattern.search(source):
        return pattern.sub(lambda match: match.group(1) + encoded_value, source, count=1)
    open_index = source.find("{")
    if open_index < 0:
        raise RotationError("VS Code settings.json 缺少开始括号")
    newline = "\r\n" if "\r\n" in source else "\n"
    rest = source[open_index + 1:]
    if rest.startswith("\r\n"):
        rest = rest[2:]
    elif rest.startswith("\n"):
        rest = rest[1:]
    comma = "," if parsed else ""
    insertion = f"{newline}  {encoded_key}: {encoded_value}{comma}{newline}"
    return source[:open_index + 1] + insertion + rest


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
    while index < object_end - 1:
        if (
            tokens[index][0] == "string"
            and index + 2 < object_end
            and tokens[index + 1][0] == ":"
        ):
            value_index = index + 2
            value_end = _jsonc_value_end(tokens, value_index)
            if tokens[index][1] == key:
                return value_index, value_end
            index = value_end
        else:
            index += 1
    return None


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


def _unquote_yaml(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value or value in {"null", "~"}:
        return None
    if value[:1] == value[-1:] and value[:1] in {'"', "'"}:
        if value[0] == '"':
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass
        return value[1:-1].replace("''", "'")
    return value.split(" #", 1)[0].strip()


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
        if not raw.strip():
            stack.append((indent, key))


def _yaml_get(text: str, path: tuple[str, ...]) -> str | None:
    for _index, _indent, current, raw in _yaml_entries(text):
        if current == path:
            return _unquote_yaml(raw)
    return None


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
    for index, indent, current, _raw in entries:
        if current == path:
            lines[index] = f"{' ' * indent}{path[-1]}: {_yaml_quote(value)}{newline}"
            return "".join(lines)
    parent = path[:-1]
    parent_entry = next((entry for entry in entries if entry[2] == parent), None)
    if parent_entry:
        parent_index, parent_indent, _current, _raw = parent_entry
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
    if len(path) == 2:
        prefix = "" if not text or text.endswith(("\n", "\r")) else newline
        return text + prefix + f"{path[0]}:{newline}  {path[1]}: {_yaml_quote(value)}{newline}"
    raise RotationError(f"配置缺少字段：{'.'.join(parent)}")


def _env_get(text: str, name: str) -> str | None:
    match = re.search(rf"^\s*{re.escape(name)}\s*=\s*(.*?)\s*$", text, re.M)
    return match.group(1).strip("\"'") if match else None


def _env_set(text: str, name: str, value: str) -> str:
    newline = "\r\n" if "\r\n" in text else "\n"
    replacement = f"{name}={value}"
    pattern = re.compile(rf"^\s*{re.escape(name)}\s*=.*$", re.M)
    if pattern.search(text):
        return pattern.sub(replacement, text, count=1)
    prefix = "" if not text or text.endswith(("\n", "\r")) else newline
    return text + prefix + replacement + newline


def _continue_block(text: str):
    lines = text.splitlines(keepends=True)
    models_index = next(
        (index for index, line in enumerate(lines) if re.match(r"^\s*models:\s*(?:#.*)?$", line.rstrip("\r\n"))),
        None,
    )
    if models_index is None:
        return None
    models_indent = len(lines[models_index]) - len(lines[models_index].lstrip(" "))
    candidates = []
    for index in range(models_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= models_indent:
            break
        if re.match(r"^\s*-\s+", line):
            candidates.append((index, indent))
    if not candidates:
        return None
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
        score = int(bool(re.search(r"^\s*apiBase:\s*", body, re.M))) + int(bool(re.search(r"^\s*apiKey:\s*", body, re.M)))
        blocks.append((score, start, end, item_indent))
    return max(blocks, key=lambda item: item[0])


def _continue_values(text: str) -> tuple[str | None, str | None]:
    block = _continue_block(text)
    if not block:
        return None, None
    _score, start, end, _indent = block
    body = "".join(text.splitlines(keepends=True)[start:end])
    def get(field_name):
        match = re.search(rf"^\s*{field_name}:\s*(.*?)\s*$", body, re.M)
        return _unquote_yaml(match.group(1)) if match else None
    return get("apiBase"), get("apiKey")


def _continue_set(text: str, base_url: str, api_key: str) -> str:
    block = _continue_block(text)
    if not block:
        raise RotationError("Continue 没有可更新的 models 配置")
    _score, start, end, item_indent = block
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    field_indent = item_indent + 2
    for field_name, value in (("apiBase", base_url), ("apiKey", api_key)):
        found = None
        for index in range(start, end):
            if re.match(rf"^\s*{field_name}:\s*", lines[index]):
                found = index
                break
        new_line = f"{' ' * field_indent}{field_name}: {_yaml_quote(value)}{newline}"
        if found is not None:
            lines[found] = new_line
        else:
            lines.insert(end, new_line)
            end += 1
    return "".join(lines)


def _sqlite_readonly_uri(path: str | Path) -> str:
    return Path(path).resolve().as_uri() + "?mode=ro"


def _vscode_read_secret_named(secret_id: str) -> str | None:
    if not os.path.isfile(VSCODE_STATE_DB) or not os.path.isfile(VSCODE_LOCAL_STATE):
        return None
    try:
        aes_key = get_vscode_aes_key()
        db = sqlite3.connect(_sqlite_readonly_uri(VSCODE_STATE_DB), uri=True)
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


def _vscode_read_secret() -> str | None:
    return _vscode_read_secret_named(VSCODE_SECRET_ID)


def vscode_secret_storage_status() -> tuple[bool, str]:
    if not os.path.isfile(VSCODE_STATE_DB) or not os.path.isfile(VSCODE_LOCAL_STATE):
        return False, "没有找到 VS Code SecretStorage"
    try:
        get_vscode_aes_key()
        db = sqlite3.connect(_sqlite_readonly_uri(VSCODE_STATE_DB), uri=True)
        try:
            table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ItemTable'"
            ).fetchone()
            if not table:
                return False, "VS Code SecretStorage 数据表不存在"
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return False, "VS Code SecretStorage 数据库检查失败"
        finally:
            db.close()
    except (OSError, RotationError, sqlite3.Error, KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False, "当前无法安全访问 VS Code SecretStorage"
    if not os.access(VSCODE_STATE_DB, os.W_OK):
        return False, "VS Code SecretStorage 当前不可写"
    return True, ""


def _vscode_write_secret_named(secret_id: str, api_key: str):
    aes_key = get_vscode_aes_key()
    payload = json.dumps({"type": "Buffer", "data": list(vscode_secret_encrypt(api_key, aes_key))})
    db = sqlite3.connect(VSCODE_STATE_DB)
    try:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)", (f"secret://{secret_id}", payload))
        db.commit()
        checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint and checkpoint[0]:
            raise RotationError("VS Code SecretStorage 仍被其他进程占用")
    finally:
        db.close()


def _vscode_write_secret(api_key: str):
    _vscode_write_secret_named(VSCODE_SECRET_ID, api_key)


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
                    for path in (HERMES_CONFIG, HERMES_ENV) if os.path.isfile(path)
                ],
            ]
        elif target_id == "continue":
            extension = extension_public(target_id, extension_versions, vscode_instances)
            exists = os.path.isfile(CONTINUE_CONFIG)
            config = _read_text(CONTINUE_CONFIG) if exists else ""
            url, key = _continue_values(config)
            discovery = ([{"path": CONTINUE_CONFIG, "source": "标准用户配置"}] if exists else [])
            if vscode_instances:
                extension_dirs = [
                    {"path": str(root), "source": "VS Code 扩展目录"}
                    for root in discover_vscode_extension_dirs(vscode_instances) if root.is_dir()
                ]
                discovery = [*vscode_instances, *extension_dirs, *discovery]
            if not extension["installed"]:
                return TargetState(
                    target_id, title, CONTINUE_CONFIG, "missing-extension", "未安装",
                    f"缺少扩展 · {extension['id']}", False,
                    extension=extension,
                    discovery=vscode_instances or discover_vscode_installations(),
                )
            if exists and not _continue_block(config):
                return TargetState(
                    target_id, title, CONTINUE_CONFIG, "unsupported", "需配置",
                    "没有可更新的 models 配置", False, extension=extension,
                    discovery=discovery,
                )
        elif target_id == "dsh":
            installations = discover_dsh_installations()
            selected_path = str(options.get("settingsPath") or "")
            candidates = discover_dsh_configs(selected_path or None)
            selected = next(
                (item for item in candidates if selected_path and os.path.normcase(item["path"]) == os.path.normcase(selected_path)),
                candidates[0] if candidates else None,
            )
            if not selected:
                detail = "已找到程序，但没有找到 settings.yaml" if installations else "没有找到程序或用户配置"
                return TargetState(
                    target_id, title,
                    installations[0]["path"] if installations else location,
                    "unconfigured" if installations else "missing",
                    "未配置" if installations else "未发现",
                    detail, False,
                    discovery=installations,
                    candidates=candidates,
                )
            settings_path = selected["path"]
            credentials_path = selected["credentialsPath"]
            settings = _read_text(settings_path)
            providers = selected["providers"]
            requested_provider = str(options.get("provider") or "")
            provider = next((row for row in providers if row["id"] == requested_provider), None)
            if provider is None:
                provider = next((row for row in providers if row["current"] and row["writable"]), None)
            if provider is None:
                provider = next((row for row in providers if row["writable"]), None)
            if provider is None:
                return TargetState(
                    target_id, title, settings_path, "unsupported", "需配置",
                    "找到配置，但没有带 apiKeyEnv 的可写提供商", False,
                    discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                    candidates=candidates, providers=providers,
                )
            url = provider["baseUrl"] or None
            env_name = provider["apiKeyEnv"]
            credentials = _read_text(credentials_path) if os.path.isfile(credentials_path) else ""
            key = _yaml_get(credentials, ("refs", env_name)) if env_name else None
            return TargetState(
                target_id, title, settings_path,
                "ok" if (url or key) else "ready",
                "已配置" if (url or key) else "可写入",
                _detail(url, key, f"将更新提供商 {provider['id']}"),
                True, url, key,
                discovery=[*installations, {"path": settings_path, "source": selected["source"]}],
                candidates=candidates, providers=providers, selected_provider=provider["id"],
            )
        elif target_id == "vscode":
            instances = vscode_instances if vscode_instances is not None else discover_vscode_installations()
            exists = os.path.isfile(VSCODE_STATE_DB) and os.path.isfile(VSCODE_LOCAL_STATE)
            providers = _load_json(CHAT_LM_JSON, []) if exists else []
            provider = next((item for item in providers if isinstance(item, dict) and item.get("name") == "Key Router"), {})
            url = provider.get("url") if isinstance(provider, dict) else None
            discovery = [*instances]
            if os.path.isfile(CHAT_LM_JSON):
                discovery.append({"path": CHAT_LM_JSON, "source": "VS Code 自定义模型配置"})
            if os.path.isfile(VSCODE_STATE_DB):
                discovery.append({"path": VSCODE_STATE_DB, "source": "VS Code 用户数据"})
            capable, reason = vscode_secret_storage_status() if exists else (False, "")
            if exists and not capable:
                return TargetState(
                    target_id, title, VSCODE_STATE_DB, "error", "不可写",
                    reason, False, current_url=url, discovery=discovery,
                )
            key = _vscode_read_secret() if exists else None
        elif target_id in VSCODE_PLUGIN_CONFIG:
            extension = extension_public(target_id, extension_versions, vscode_instances)
            instances = vscode_instances if vscode_instances is not None else discover_vscode_installations()
            if not extension["installed"]:
                return TargetState(
                    target_id, title, VSCODE_USER_SETTINGS, "missing-extension", "未安装",
                    f"缺少扩展 · {extension['id']}", False,
                    extension=extension, discovery=instances,
                )
            exists = os.path.isfile(VSCODE_STATE_DB) and os.path.isfile(VSCODE_LOCAL_STATE)
            config_key, secret_id = VSCODE_PLUGIN_CONFIG[target_id]
            settings = _load_jsonc(VSCODE_USER_SETTINGS, {}) if os.path.isfile(VSCODE_USER_SETTINGS) else {}
            url = settings.get(config_key) if isinstance(settings, dict) else None
            discovery = [
                *instances,
                *[
                    {"path": str(root), "source": "VS Code 扩展目录"}
                    for root in discover_vscode_extension_dirs(instances) if root.is_dir()
                ],
            ]
            if os.path.isfile(VSCODE_USER_SETTINGS):
                discovery.append({"path": VSCODE_USER_SETTINGS, "source": "VS Code 用户设置"})
            if os.path.isfile(VSCODE_STATE_DB):
                discovery.append({"path": VSCODE_STATE_DB, "source": "VS Code 用户数据"})
            capable, reason = vscode_secret_storage_status() if exists else (False, "")
            if exists and not capable:
                return TargetState(
                    target_id, title, VSCODE_STATE_DB, "error", "不可写",
                    reason, False, current_url=url, discovery=discovery, extension=extension,
                )
            key = _vscode_read_secret_named(secret_id) if exists else None
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
            exists = Path(PI_SETTINGS).parent.is_dir() or os.path.isfile(PI_SETTINGS) or bool(installations)
            settings = _load_jsonc(PI_SETTINGS, {}) if exists else {}
            provider_name = settings.get("defaultProvider") if isinstance(settings, dict) else None
            provider_name = provider_name if isinstance(provider_name, str) and provider_name else "anthropic"
            models = _load_jsonc(PI_MODELS, {}) if exists else {}
            providers = models.get("providers", {}) if isinstance(models, dict) else {}
            provider = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
            if exists and not provider:
                return TargetState(
                    target_id, title, PI_MODELS, "unconfigured", "需配置",
                    "已找到 Pi，但没有可更新的模型提供商", False,
                    discovery=[
                        *installations,
                        *([{"path": PI_MODELS, "source": "Pi 用户配置"}] if os.path.isfile(PI_MODELS) else []),
                    ],
                )
            url = provider.get("baseUrl") if isinstance(provider, dict) else None
            key = provider.get("apiKey") if isinstance(provider, dict) else None
            discovery = [*installations]
            if os.path.isfile(PI_MODELS):
                discovery.append({"path": PI_MODELS, "source": "Pi 用户配置"})

        if not exists:
            return TargetState(
                target_id, title, location, "missing", "未发现", "没有找到本机配置", False,
                discovery=discovery,
                extension=locals().get("extension"),
            )
        return TargetState(
            target_id, title,
            VSCODE_USER_SETTINGS if target_id in VSCODE_PLUGIN_CONFIG else location,
            "ok" if (url or key) else "ready",
            "已配置" if (url or key) else "可写入",
            _detail(url, key, "已找到应用，可创建配置"),
            True, url, key,
            "需退出 VS Code 后写入" if target_id in VSCODE_TARGETS and vscode_running() else "",
            discovery=discovery,
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
            location = str(next((root for root in roots if root.is_dir()), roots[0] if roots else Path(VSCODE_EXTENSIONS_DIR)))
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


def _plan_hermes(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
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


def _plan_continue(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    plan = TargetPlan(state or _state("continue"))
    text = _read_text(CONTINUE_CONFIG)
    updated = _continue_set(text, base_url, api_key)
    if updated != text:
        plan.changes.append(Change("continue", CONTINUE_CONFIG, "模型 apiBase / apiKey", updated))
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
    updated_settings = _yaml_set(settings, ("llm-pi-ai", "providers", provider, "baseURL"), base_url)
    credentials = _read_text(credentials_path) if os.path.isfile(credentials_path) else "refs:\n"
    updated_credentials = _yaml_set(credentials, ("refs", env_name), api_key)
    if updated_settings != settings:
        plan.changes.append(Change("dsh", settings_path, f"providers.{provider}.baseURL", updated_settings))
    if updated_credentials != credentials:
        plan.changes.append(Change("dsh", credentials_path, f"refs.{env_name}", updated_credentials))
    return plan


def _plan_vscode(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    plan = TargetPlan(state or _state("vscode"))
    providers = _load_json(CHAT_LM_JSON, [])
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
    plan.changes.append(Change("vscode", CHAT_LM_JSON, "Key Router Custom Endpoint", _json_dump(providers)))
    plan.changes.append(Change("vscode", VSCODE_STATE_DB, "SecretStorage API Key", action=lambda: _vscode_write_secret(api_key)))
    if vscode_running():
        plan.warnings.append("VS Code 正在运行，正式应用前必须完全退出")
    return plan


def _plan_vscode_plugin(target_id: str, base_url: str, api_key: str, state: TargetState | None = None) -> TargetPlan:
    plan = TargetPlan(state or _state(target_id))
    config_key, secret_id = VSCODE_PLUGIN_CONFIG[target_id]
    settings = _read_text(VSCODE_USER_SETTINGS) if os.path.isfile(VSCODE_USER_SETTINGS) else "{}\n"
    updated = _jsonc_set_top_level(settings, config_key, base_url)
    if updated != settings:
        def write_setting(config_key=config_key):
            current = _read_text(VSCODE_USER_SETTINGS) if os.path.isfile(VSCODE_USER_SETTINGS) else "{}\n"
            _atomic_write_text(VSCODE_USER_SETTINGS, _jsonc_set_top_level(current, config_key, base_url))
        plan.changes.append(Change(target_id, VSCODE_USER_SETTINGS, config_key, action=write_setting))
    plan.changes.append(Change(
        target_id,
        VSCODE_STATE_DB,
        f"SecretStorage · {secret_id}",
        action=lambda secret_id=secret_id: _vscode_write_secret_named(secret_id, api_key),
    ))
    if vscode_running():
        plan.warnings.append("VS Code 正在运行，正式应用前必须完全退出")
    return plan


def _plan_opencode_copilot(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    return _plan_vscode_plugin("opencode_copilot", base_url, api_key, state)


def _plan_deepseek_copilot(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    return _plan_vscode_plugin("deepseek_copilot", base_url, api_key, state)


def _plan_mimo_copilot(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
    return _plan_vscode_plugin("mimo_copilot", base_url, api_key, state)


def _plan_claude(base_url: str, api_key: str, _options: dict | None = None, state: TargetState | None = None) -> TargetPlan:
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
    return os.path.normcase(os.path.normpath(path)) == os.path.normcase(os.path.normpath(VSCODE_STATE_DB))


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
    backup_dir = Path(BACKUP_DIR) / timestamp
    backup_dir.mkdir(parents=True, exist_ok=False)
    mapping: dict[str, str | None] = {}
    manifest = []
    for index, path in enumerate(dict.fromkeys(paths), start=1):
        source = Path(path)
        if source.is_file():
            backup_path = backup_dir / f"{index:02d}-{source.name}"
            if _is_sqlite_config(path):
                _sqlite_snapshot(source, backup_path)
            else:
                shutil.copy2(source, backup_path)
            mapping[path] = str(backup_path)
            manifest.append({"path": path, "backup": backup_path.name, "existed": True})
        else:
            mapping[path] = None
            manifest.append({"path": path, "backup": None, "existed": False})
    _atomic_write_text(str(backup_dir / "manifest.json"), _json_dump(manifest))
    return str(backup_dir), mapping


def _restore(mapping: dict[str, str | None]):
    errors = []
    for path, backup_path in reversed(list(mapping.items())):
        try:
            if _is_sqlite_config(path):
                _clear_sqlite_sidecars(path)
            if backup_path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_path, path)
            elif os.path.isfile(path):
                os.unlink(path)
            if _is_sqlite_config(path):
                _clear_sqlite_sidecars(path)
        except OSError as exc:
            errors.append((path, exc))
    if errors:
        raise RotationError(f"有 {len(errors)} 个配置位置未能恢复") from errors[0][1]


def run_rotation(
    base_url: str,
    new_key: str,
    target_ids: list[str] | tuple[str, ...],
    *,
    apply: bool = False,
    target_options: dict | None = None,
    log: Callable[[str], None] | None = print,
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
        if target_id != "dsh" or not isinstance(value, dict):
            raise RotationError("目标选项无效")
        if any(key not in {"settingsPath", "provider"} for key in value):
            raise RotationError("dsh 目标选项包含未知字段")
        if any(not isinstance(item, str) for item in value.values()):
            raise RotationError("dsh 目标选项格式无效")

    messages: list[str] = []
    def emit(message: str = ""):
        messages.append(message)
        if log:
            log(message)

    vscode_instances = discover_vscode_installations() if any(item in VSCODE_DISCOVERY_TARGETS for item in selected) else []
    extension_versions = installed_vscode_extensions(vscode_instances) if any(item in EXTENSION_META for item in selected) else {}
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
        backup_dir, mapping = _backup([change.path for change in changes])
        emit("")
        emit(f"已备份 {len(mapping)} 个配置位置")
        try:
            for change in changes:
                change.apply()
        except Exception as exc:
            try:
                _restore(mapping)
            except Exception:
                raise RotationError("写入失败，且自动恢复未完全成功；请使用备份目录恢复") from exc
            raise RotationError("写入失败，已从备份恢复原配置") from exc
        emit(f"已完成 {len(plans)} 个工具的批量配置")
    else:
        emit("")
        emit(f"预览完成：{len(plans)} 个工具，{len(changes)} 处更改")

    return {
        "applied": apply,
        "backup_dir": backup_dir,
        "vscode_running": vscode_running() if any(target_id in VSCODE_TARGETS for target_id in selected) else False,
        "target_ids": selected,
        "change_count": len(changes),
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
    parser = argparse.ArgumentParser(description="Key Router · 批量配置 API 地址与密钥")
    parser.add_argument("--detect", action="store_true", help="检测支持的本机工具")
    parser.add_argument("--url", help="新的 API Base URL")
    parser.add_argument("--key", help="新的 API Key")
    parser.add_argument("--targets", default=",".join(TARGET_ORDER), help="逗号分隔的目标 ID")
    parser.add_argument("--apply", action="store_true", help="正式写入；默认只预览")
    args = parser.parse_args()
    if args.detect:
        for item in detect_targets():
            print(f"{item['title']}: {item['badge']} · {item['detail']}")
        return
    try:
        run_rotation(
            args.url or "",
            args.key or "",
            [item.strip() for item in args.targets.split(",") if item.strip()],
            apply=args.apply,
        )
    except RotationError as exc:
        raise SystemExit(f"错误：{exc}") from exc


if __name__ == "__main__":
    main()
