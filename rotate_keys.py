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
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RotationError(RuntimeError):
    """可安全展示给界面的错误。"""


def _paths() -> dict[str, str]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    hermes_home = Path(os.environ.get("HERMES_HOME") or r"E:\Program Files\Hermes")
    paths = {
        "HERMES_ENV": str(hermes_home / ".env"),
        "HERMES_CONFIG": str(hermes_home / "config.yaml"),
        "CONTINUE_CONFIG": str(home / ".continue" / "config.yaml"),
        "DSH_SETTINGS": str(home / ".dsh" / "settings.yaml"),
        "DSH_CREDENTIALS": str(home / ".dsh" / ".credentials.yaml"),
        "VSCODE_STATE_DB": str(appdata / "Code" / "User" / "globalStorage" / "state.vscdb"),
        "VSCODE_LOCAL_STATE": str(appdata / "Code" / "Local State"),
        "CHAT_LM_JSON": str(appdata / "Code" / "User" / "chatLanguageModels.json"),
        "CLAUDE_SETTINGS": str(home / ".claude" / "settings.json"),
        "PI_SETTINGS": str(home / ".pi" / "agent" / "settings.json"),
        "PI_MODELS": str(home / ".pi" / "agent" / "models.json"),
        "BACKUP_DIR": str(Path(__file__).resolve().parent / "backups"),
    }
    override = os.environ.get("RK_PATHS_JSON")
    if override:
        paths.update({key: str(value) for key, value in json.loads(override).items()})
    return paths


PATHS = _paths()
globals().update(PATHS)

TARGET_ORDER = ("hermes", "continue", "dsh", "vscode", "claude", "pi")
TARGET_META = {
    "hermes": ("Hermes", "config.yaml + .env"),
    "continue": ("Continue", "~/.continue/config.yaml"),
    "dsh": ("dsh", "~/.dsh/settings.yaml"),
    "vscode": ("VS Code", "Custom Endpoint + SecretStorage"),
    "claude": ("Claude Code", "~/.claude/settings.json"),
    "pi": ("Pi", "~/.pi/agent/models.json"),
}

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
    key = value.strip()
    if not 4 <= len(key) <= 2048:
        raise RotationError("API Key 长度应为 4–2048 个字符")
    if any(character.isspace() or ord(character) < 32 for character in key):
        raise RotationError("API Key 不能包含空格、换行或控制字符")
    return key


def validate_base_url(value: str) -> str:
    raw = value.strip()
    if not raw or len(raw) > 2048:
        raise RotationError("Base URL 不能为空或过长")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise RotationError("Base URL 格式不正确") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RotationError("Base URL 必须是完整的 http:// 或 https:// 地址")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RotationError("Base URL 不能包含账号、密码、查询参数或锚点")
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "http" and parsed.hostname.lower() not in local_hosts:
        raise RotationError("远程地址必须使用 HTTPS；HTTP 仅允许本机地址")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="strict", newline="") as file:
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
        with open(path, encoding="utf-8") as file:
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


def _vscode_read_secret() -> str | None:
    if not os.path.isfile(VSCODE_STATE_DB) or not os.path.isfile(VSCODE_LOCAL_STATE):
        return None
    aes_key = get_vscode_aes_key()
    db = sqlite3.connect(f"file:{VSCODE_STATE_DB}?mode=ro", uri=True)
    try:
        row = db.execute("SELECT value FROM ItemTable WHERE key=?", (VSCODE_SECRET_KEY,)).fetchone()
    finally:
        db.close()
    if not row:
        return None
    payload = json.loads(row[0])
    return vscode_secret_decrypt(bytes(payload["data"]), aes_key)


def _vscode_write_secret(api_key: str):
    aes_key = get_vscode_aes_key()
    payload = json.dumps({"type": "Buffer", "data": list(vscode_secret_encrypt(api_key, aes_key))})
    db = sqlite3.connect(VSCODE_STATE_DB)
    try:
        db.execute("INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)", (VSCODE_SECRET_KEY, payload))
        db.commit()
    finally:
        db.close()


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


def _state(target_id: str) -> TargetState:
    title, location = TARGET_META[target_id]
    try:
        if target_id == "hermes":
            exists = os.path.isfile(HERMES_ENV) or os.path.isfile(HERMES_CONFIG)
            env = _read_text(HERMES_ENV) if os.path.isfile(HERMES_ENV) else ""
            config = _read_text(HERMES_CONFIG) if os.path.isfile(HERMES_CONFIG) else ""
            key = _env_get(env, "OPENAI_API_KEY") or _env_get(env, "OPENCODE_GO_API_KEY")
            url = _yaml_get(config, ("model", "base_url"))
        elif target_id == "continue":
            exists = os.path.isfile(CONTINUE_CONFIG)
            config = _read_text(CONTINUE_CONFIG) if exists else ""
            url, key = _continue_values(config)
            if exists and not _continue_block(config):
                return TargetState(target_id, title, location, "unsupported", "需配置", "没有 models 配置", False)
        elif target_id == "dsh":
            exists = os.path.isfile(DSH_SETTINGS)
            settings = _read_text(DSH_SETTINGS) if exists else ""
            provider = _yaml_get(settings, ("agent-default-model", "provider"))
            if not provider:
                providers = _yaml_child_keys(settings, ("llm-pi-ai", "providers"))
                provider = providers[0] if providers else None
            if exists and not provider:
                return TargetState(target_id, title, location, "unsupported", "需配置", "没有可用提供方", False)
            url = _yaml_get(settings, ("llm-pi-ai", "providers", provider, "baseURL")) if provider else None
            env_name = _yaml_get(settings, ("llm-pi-ai", "providers", provider, "apiKeyEnv")) if provider else None
            credentials = _read_text(DSH_CREDENTIALS) if os.path.isfile(DSH_CREDENTIALS) else ""
            key = _yaml_get(credentials, ("refs", env_name)) if env_name else None
        elif target_id == "vscode":
            exists = os.path.isfile(VSCODE_STATE_DB) and os.path.isfile(VSCODE_LOCAL_STATE)
            providers = _load_json(CHAT_LM_JSON, []) if exists else []
            provider = next((item for item in providers if isinstance(item, dict) and item.get("name") == "Key Router"), {})
            url = provider.get("url") if isinstance(provider, dict) else None
            key = _vscode_read_secret() if exists else None
        elif target_id == "claude":
            exists = Path(CLAUDE_SETTINGS).parent.is_dir() or os.path.isfile(CLAUDE_SETTINGS)
            settings = _load_json(CLAUDE_SETTINGS, {}) if exists else {}
            env = settings.get("env", {}) if isinstance(settings, dict) else {}
            url = env.get("ANTHROPIC_BASE_URL") if isinstance(env, dict) else None
            key = (env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY")) if isinstance(env, dict) else None
        else:
            exists = Path(PI_SETTINGS).parent.is_dir() or os.path.isfile(PI_SETTINGS)
            settings = _load_jsonc(PI_SETTINGS, {}) if exists else {}
            provider_name = settings.get("defaultProvider") if isinstance(settings, dict) else None
            provider_name = provider_name if isinstance(provider_name, str) and provider_name else "anthropic"
            models = _load_jsonc(PI_MODELS, {}) if exists else {}
            providers = models.get("providers", {}) if isinstance(models, dict) else {}
            provider = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
            url = provider.get("baseUrl") if isinstance(provider, dict) else None
            key = provider.get("apiKey") if isinstance(provider, dict) else None

        if not exists:
            return TargetState(target_id, title, location, "missing", "未安装", "没有找到本机配置", False)
        return TargetState(
            target_id, title, location,
            "ok" if (url or key) else "ready",
            "已配置" if (url or key) else "可写入",
            _detail(url, key, "已找到应用，可创建配置"),
            True, url, key,
            "需退出 VS Code 后写入" if target_id == "vscode" and vscode_running() else "",
        )
    except RotationError as exc:
        return TargetState(target_id, title, location, "error", "读取失败", str(exc), False)
    except Exception:
        return TargetState(target_id, title, location, "error", "读取失败", "配置格式不受支持", False)


def detect_targets() -> list[dict]:
    return [_state(target_id).public() for target_id in TARGET_ORDER]


def _plan_hermes(base_url: str, api_key: str) -> TargetPlan:
    plan = TargetPlan(_state("hermes"))
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


def _plan_continue(base_url: str, api_key: str) -> TargetPlan:
    plan = TargetPlan(_state("continue"))
    text = _read_text(CONTINUE_CONFIG)
    updated = _continue_set(text, base_url, api_key)
    if updated != text:
        plan.changes.append(Change("continue", CONTINUE_CONFIG, "模型 apiBase / apiKey", updated))
    return plan


def _plan_dsh(base_url: str, api_key: str) -> TargetPlan:
    plan = TargetPlan(_state("dsh"))
    settings = _read_text(DSH_SETTINGS)
    provider = _yaml_get(settings, ("agent-default-model", "provider"))
    if not provider:
        providers = _yaml_child_keys(settings, ("llm-pi-ai", "providers"))
        provider = providers[0] if providers else None
    if not provider:
        raise RotationError("dsh 没有可更新的提供方")
    env_name = _yaml_get(settings, ("llm-pi-ai", "providers", provider, "apiKeyEnv"))
    if not env_name:
        raise RotationError("dsh 当前提供方没有 apiKeyEnv")
    updated_settings = _yaml_set(settings, ("llm-pi-ai", "providers", provider, "baseURL"), base_url)
    credentials = _read_text(DSH_CREDENTIALS) if os.path.isfile(DSH_CREDENTIALS) else "refs:\n"
    updated_credentials = _yaml_set(credentials, ("refs", env_name), api_key)
    if updated_settings != settings:
        plan.changes.append(Change("dsh", DSH_SETTINGS, f"providers.{provider}.baseURL", updated_settings))
    if updated_credentials != credentials:
        plan.changes.append(Change("dsh", DSH_CREDENTIALS, f"refs.{env_name}", updated_credentials))
    return plan


def _plan_vscode(base_url: str, api_key: str) -> TargetPlan:
    plan = TargetPlan(_state("vscode"))
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


def _plan_claude(base_url: str, api_key: str) -> TargetPlan:
    plan = TargetPlan(_state("claude"))
    settings = _load_json(CLAUDE_SETTINGS, {})
    if not isinstance(settings, dict):
        raise RotationError("Claude Code settings.json 顶层必须是对象")
    env = settings.setdefault("env", {})
    if not isinstance(env, dict):
        raise RotationError("Claude Code settings.json 的 env 必须是对象")
    env["ANTHROPIC_BASE_URL"] = base_url
    if "ANTHROPIC_API_KEY" in env and "ANTHROPIC_AUTH_TOKEN" not in env:
        env["ANTHROPIC_API_KEY"] = api_key
    else:
        env["ANTHROPIC_AUTH_TOKEN"] = api_key
        if "ANTHROPIC_API_KEY" in env:
            env["ANTHROPIC_API_KEY"] = api_key
    plan.changes.append(Change("claude", CLAUDE_SETTINGS, "ANTHROPIC_BASE_URL / 认证令牌", _json_dump(settings)))
    return plan


def _plan_pi(base_url: str, api_key: str) -> TargetPlan:
    plan = TargetPlan(_state("pi"))
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
    plan.changes.append(Change("pi", PI_MODELS, f"providers.{provider_name}.baseUrl / apiKey", _json_dump(models)))
    return plan


PLANNERS = {
    "hermes": _plan_hermes,
    "continue": _plan_continue,
    "dsh": _plan_dsh,
    "vscode": _plan_vscode,
    "claude": _plan_claude,
    "pi": _plan_pi,
}


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
            shutil.copy2(source, backup_path)
            mapping[path] = str(backup_path)
            manifest.append({"path": path, "backup": backup_path.name, "existed": True})
        else:
            mapping[path] = None
            manifest.append({"path": path, "backup": None, "existed": False})
    _atomic_write_text(str(backup_dir / "manifest.json"), _json_dump(manifest))
    return str(backup_dir), mapping


def _restore(mapping: dict[str, str | None]):
    for path, backup_path in reversed(list(mapping.items())):
        if backup_path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_path, path)
        elif os.path.isfile(path):
            os.unlink(path)


def run_rotation(
    base_url: str,
    new_key: str,
    target_ids: list[str] | tuple[str, ...],
    *,
    apply: bool = False,
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

    messages: list[str] = []
    def emit(message: str = ""):
        messages.append(message)
        if log:
            log(message)

    plans: list[TargetPlan] = []
    for target_id in selected:
        state = _state(target_id)
        if not state.selectable:
            raise RotationError(f"{state.title} 当前不可写入：{state.detail}")
        plans.append(PLANNERS[target_id](url, key))
    changes = [change for plan in plans for change in plan.changes]
    if not changes:
        raise RotationError("所选工具已经是这组配置，无需修改")
    if apply and "vscode" in selected and vscode_running():
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
        "vscode_running": vscode_running() if "vscode" in selected else False,
        "target_ids": selected,
        "change_count": len(changes),
        "changes": [
            {
                "targetId": plan.target.id,
                "target": plan.target.title,
                "file": Path(change.path).name,
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
