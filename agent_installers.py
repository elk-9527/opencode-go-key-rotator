# -*- coding: utf-8 -*-
"""Key Router 的白名单 Agent 安装器。

只接受代码内固定的官方来源。安装目录必须先由本机文件夹选择器确认，
网页不能传入下载地址、命令或未经确认的目标路径。
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable
from urllib.request import Request, urlopen
import zipfile


class InstallerError(RuntimeError):
    """可安全展示给界面的安装错误。"""


INSTALLER_META = {
    "hermes": {
        "name": "Hermes Agent",
        "publisher": "Nous Research",
        "identity": "NousResearch/hermes-agent",
        "sourceUrl": "https://github.com/NousResearch/hermes-agent",
        "pathMode": "select",
        "folderName": "Hermes Agent",
        "sizeLabel": "约 1 GB",
        "note": "Windows 原生版仍处于官方 Beta 阶段。",
    },
    "dsh": {
        "name": "DeepSeek Harness",
        "publisher": "DeepSeek AI",
        "identity": "@deepseek-ai/dsh",
        "sourceUrl": "https://github.com/deepseek-ai/deepseek-harness",
        "pathMode": "select",
        "folderName": "DeepSeek Harness",
        "sizeLabel": "包含独立 Node 运行时",
        "note": "安装官方 npm 包，不使用系统 Node.js。",
    },
    "claude": {
        "name": "Claude Code",
        "publisher": "Anthropic",
        "identity": "Anthropic.ClaudeCode",
        "sourceUrl": "https://code.claude.com/docs/en/installation",
        "pathMode": "fixed",
        "folderName": "",
        "sizeLabel": "官方自动更新",
        "note": "官方安装器固定使用当前用户目录。",
    },
    "pi": {
        "name": "Pi",
        "publisher": "Mario Zechner / earendil-works",
        "identity": "earendil-works/pi",
        "sourceUrl": "https://github.com/earendil-works/pi",
        "pathMode": "select",
        "folderName": "Pi",
        "sizeLabel": "约 45 MB",
        "note": "Windows 使用 Pi 官方单文件，并核对 SHA-256。",
    },
}

HERMES_INSTALLER_URL = "https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.ps1"
CLAUDE_INSTALLER_URL = "https://claude.ai/install.ps1"
PI_RELEASE_API = "https://api.github.com/repos/earendil-works/pi/releases/latest"
NODE_RELEASE_INDEX = "https://nodejs.org/dist/index.json"


def _local_appdata() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")


def default_parent(target_id: str) -> Path:
    if target_id not in INSTALLER_META:
        raise InstallerError("该工具不在 Agent 安装白名单中")
    if target_id == "claude":
        return Path.home() / ".local" / "bin"
    return _local_appdata() / "Programs"


def resolve_install_location(target_id: str, selected_parent: str | Path | None = None) -> Path:
    metadata = INSTALLER_META.get(target_id)
    if not metadata:
        raise InstallerError("该工具不在 Agent 安装白名单中")
    if metadata["pathMode"] == "fixed":
        return default_parent(target_id).resolve()
    parent = Path(selected_parent) if selected_parent else default_parent(target_id)
    if not parent.is_absolute():
        raise InstallerError("安装位置必须是完整路径")
    return (parent / metadata["folderName"]).resolve()


def validate_install_location(target_id: str, location: str | Path) -> Path:
    path = Path(location).resolve()
    metadata = INSTALLER_META.get(target_id)
    if not metadata:
        raise InstallerError("该工具不在 Agent 安装白名单中")
    if path == Path(path.anchor) or path == Path.home().resolve():
        raise InstallerError("请选择磁盘中的子文件夹，不能直接安装到磁盘或用户目录根部")
    if len(str(path)) > 220:
        raise InstallerError("安装路径过长，请选择更短的位置")
    if path.exists() and path.is_symlink():
        raise InstallerError("安装位置不能是符号链接")
    if metadata["pathMode"] == "fixed":
        if os.path.normcase(str(path)) != os.path.normcase(str(default_parent(target_id).resolve())):
            raise InstallerError("该工具只能安装到官方固定位置")
        return path
    if path.name != metadata["folderName"]:
        raise InstallerError("安装位置与所选工具不匹配，请重新选择")
    if path.is_dir() and any(path.iterdir()) and not _looks_managed(target_id, path):
        raise InstallerError("目标文件夹已有其他内容，请选择新的位置")
    return path


def _looks_managed(target_id: str, location: Path) -> bool:
    probes = {
        "hermes": (location / "hermes-agent" / "pyproject.toml", location / "bin" / "hermes.cmd"),
        "dsh": (location / "dsh.cmd", location / "app" / "node_modules" / "@deepseek-ai" / "dsh"),
        "pi": (location / "pi.exe",),
    }.get(target_id, ())
    return any(path.exists() for path in probes)


def load_install_records(settings_path: str | Path) -> dict:
    path = Path(settings_path)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    records = payload.get("installations", {}) if isinstance(payload, dict) else {}
    return records if isinstance(records, dict) else {}


def record_install(settings_path: str | Path, target_id: str, location: Path, version: str) -> None:
    path = Path(settings_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    installations = payload.setdefault("installations", {})
    if not isinstance(installations, dict):
        installations = {}
        payload["installations"] = installations
    installations[target_id] = {"location": str(location), "version": version}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def managed_discovery(settings_path: str | Path, target_id: str) -> list[dict]:
    record = load_install_records(settings_path).get(target_id, {})
    location = Path(str(record.get("location") or "")) if isinstance(record, dict) else Path()
    probes = {
        "hermes": (location / "hermes-agent", location / "bin" / "hermes.cmd"),
        "dsh": (location / "dsh.cmd",),
        "claude": (location / "claude.exe",),
        "pi": (location / "pi.exe",),
    }.get(target_id, ())
    if not str(record.get("location") or "") or not any(path.exists() for path in probes):
        return []
    return [{"path": str(location), "source": "Key Router 安装记录", "detail": str(record.get("version") or "")}]


def public_metadata(target_id: str, *, installed: bool, location: str = "", enabled: bool = True) -> dict | None:
    metadata = INSTALLER_META.get(target_id)
    if not metadata:
        return None
    shown_location = location or str(resolve_install_location(target_id))
    return {
        **metadata,
        "targetId": target_id,
        "installed": installed,
        "enabled": enabled,
        "location": shown_location,
    }


def _request(url: str) -> Request:
    return Request(url, headers={"User-Agent": "Key-Router/0.5", "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.8"})


def _download(url: str, destination: Path, *, max_bytes: int = 700 * 1024 * 1024) -> None:
    total = 0
    with urlopen(_request(url), timeout=60) as response, destination.open("wb") as output:
        declared = int(response.headers.get("Content-Length") or 0)
        if declared > max_bytes:
            raise InstallerError("官方安装包超过允许大小")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise InstallerError("官方安装包超过允许大小")
            output.write(chunk)
    if total == 0:
        raise InstallerError("官方安装包为空")


def _download_json(url: str):
    with urlopen(_request(url), timeout=60) as response:
        body = response.read(8 * 1024 * 1024 + 1)
    if len(body) > 8 * 1024 * 1024:
        raise InstallerError("官方版本信息异常")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerError("无法读取官方版本信息") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_sha256(path: Path, expected: str) -> None:
    expected = expected.lower().removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise InstallerError("官方安装包缺少有效的 SHA-256")
    if not hmac.compare_digest(_sha256(path), expected):
        raise InstallerError("官方安装包校验失败，文件可能不完整")


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    try:
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                relative = Path(member.filename.replace("\\", "/"))
                unix_mode = (member.external_attr >> 16) & 0o170000
                if relative.is_absolute() or ".." in relative.parts or unix_mode == 0o120000:
                    raise InstallerError("官方压缩包包含不安全路径")
                target = (root / relative).resolve()
                if root != target and root not in target.parents:
                    raise InstallerError("官方压缩包包含越界路径")
            bundle.extractall(root)
    except zipfile.BadZipFile as exc:
        raise InstallerError("官方安装包不是有效的 ZIP 文件") from exc


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(command: list[str], *, timeout: int, environment: dict | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=environment,
            creationflags=_creation_flags(),
        )
    except subprocess.TimeoutExpired as exc:
        raise InstallerError("安装超时，请检查网络后重试") from exc
    except OSError as exc:
        raise InstallerError("无法启动官方安装程序") from exc
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode != 0:
        tail = " · ".join(output.splitlines()[-3:]) if output else f"退出码 {result.returncode}"
        raise InstallerError(f"官方安装程序失败：{tail[:360]}")
    return output


def _powershell() -> str:
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def _add_user_path(folder: Path) -> None:
    folder_text = str(folder.resolve())
    if os.name == "nt":
        try:
            import winreg
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                try:
                    current, kind = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    current, kind = "", winreg.REG_EXPAND_SZ
                entries = [part.strip() for part in str(current).split(";") if part.strip()]
                normalized = {os.path.normcase(os.path.normpath(os.path.expandvars(part))) for part in entries}
                if os.path.normcase(os.path.normpath(folder_text)) not in normalized:
                    entries.append(folder_text)
                    winreg.SetValueEx(key, "Path", 0, kind if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) else winreg.REG_EXPAND_SZ, ";".join(entries))
            try:
                ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 2000, None)
            except Exception:
                pass
        except OSError as exc:
            raise InstallerError("工具已安装，但无法加入当前用户 PATH") from exc
    current_entries = os.environ.get("PATH", "").split(os.pathsep)
    if os.path.normcase(folder_text) not in {os.path.normcase(os.path.normpath(item)) for item in current_entries if item}:
        os.environ["PATH"] = folder_text + os.pathsep + os.environ.get("PATH", "")


def _install_pi(location: Path) -> str:
    release = _download_json(PI_RELEASE_API)
    architecture = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "AMD64").lower()
    suffix = "arm64" if "arm64" in architecture else "x64"
    asset_name = f"pi-windows-{suffix}.zip"
    assets = release.get("assets", []) if isinstance(release, dict) else []
    asset = next((item for item in assets if isinstance(item, dict) and item.get("name") == asset_name), None)
    if not asset or not asset.get("browser_download_url"):
        raise InstallerError("Pi 官方版本没有适合当前 Windows 架构的安装包")
    expected = str(asset.get("digest") or "")
    with tempfile.TemporaryDirectory(prefix="key-router-pi-") as temp_name:
        temp = Path(temp_name)
        archive = temp / asset_name
        _download(str(asset["browser_download_url"]), archive)
        if not expected:
            sums_asset = next((item for item in assets if isinstance(item, dict) and item.get("name") == "SHA256SUMS"), None)
            if not sums_asset or not sums_asset.get("browser_download_url"):
                raise InstallerError("Pi 官方版本缺少 SHA-256 校验信息")
            sums = temp / "SHA256SUMS"
            _download(str(sums_asset["browser_download_url"]), sums, max_bytes=2 * 1024 * 1024)
            match = re.search(rf"^([0-9a-f]{{64}})\s+[*]?{re.escape(asset_name)}$", sums.read_text(encoding="utf-8"), re.M | re.I)
            expected = match.group(1) if match else ""
        _verify_sha256(archive, expected)
        extracted = temp / "extracted"
        _safe_extract_zip(archive, extracted)
        executables = list(extracted.rglob("pi.exe"))
        if len(executables) != 1:
            raise InstallerError("Pi 官方安装包结构无法识别")
        source_root = executables[0].parent
        location.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_root, location, dirs_exist_ok=True)
    executable = location / "pi.exe"
    if not executable.is_file():
        raise InstallerError("Pi 安装完成后未找到 pi.exe")
    _add_user_path(location)
    return str(release.get("tag_name") or "已安装")


def _node_release() -> tuple[str, str]:
    releases = _download_json(NODE_RELEASE_INDEX)
    if not isinstance(releases, list):
        raise InstallerError("Node.js 官方版本信息格式异常")
    architecture = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "AMD64").lower()
    arch = "arm64" if "arm64" in architecture else "x64"
    file_marker = f"win-{arch}-zip"
    for release in releases:
        if not isinstance(release, dict) or not release.get("lts"):
            continue
        version = str(release.get("version") or "")
        match = re.match(r"v(\d+)\.", version)
        if match and int(match.group(1)) >= 24 and file_marker in release.get("files", []):
            return version, arch
    raise InstallerError("没有找到兼容的 Node.js LTS 运行时")


def _ensure_private_node(runtime: Path) -> Path:
    executable = runtime / "node.exe"
    if executable.is_file():
        return executable
    version, architecture = _node_release()
    folder_name = f"node-{version}-win-{architecture}"
    asset_name = folder_name + ".zip"
    base_url = f"https://nodejs.org/dist/{version}"
    with tempfile.TemporaryDirectory(prefix="key-router-node-") as temp_name:
        temp = Path(temp_name)
        archive = temp / asset_name
        sums = temp / "SHASUMS256.txt"
        _download(f"{base_url}/{asset_name}", archive)
        _download(f"{base_url}/SHASUMS256.txt", sums, max_bytes=2 * 1024 * 1024)
        match = re.search(rf"^([0-9a-f]{{64}})\s+{re.escape(asset_name)}$", sums.read_text(encoding="utf-8"), re.M | re.I)
        if not match:
            raise InstallerError("Node.js 官方校验清单缺少当前安装包")
        _verify_sha256(archive, match.group(1))
        extracted = temp / "extracted"
        _safe_extract_zip(archive, extracted)
        source = extracted / folder_name
        if not (source / "node.exe").is_file():
            raise InstallerError("Node.js 官方安装包结构无法识别")
        runtime.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, runtime, dirs_exist_ok=True)
    return executable


def _install_dsh(location: Path) -> str:
    node = _ensure_private_node(location / "runtime" / "node")
    npm = node.parent / "npm.cmd"
    app = location / "app"
    app.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
    _run([
        str(npm), "install", "--prefix", str(app), "--omit=dev", "--no-audit", "--no-fund",
        "@deepseek-ai/dsh@latest",
    ], timeout=1800, environment=environment)
    entry = app / "node_modules" / "@deepseek-ai" / "dsh" / "lib" / "bin.js"
    if not entry.is_file():
        raise InstallerError("DSH 官方包安装完成后未找到命令入口")
    launcher = location / "dsh.cmd"
    launcher.write_text('@echo off\r\n"%~dp0runtime\\node\\node.exe" "%~dp0app\\node_modules\\@deepseek-ai\\dsh\\lib\\bin.js" %*\r\n', encoding="utf-8")
    package_json = app / "node_modules" / "@deepseek-ai" / "dsh" / "package.json"
    try:
        version = str(json.loads(package_json.read_text(encoding="utf-8"))["version"])
    except (OSError, KeyError, json.JSONDecodeError):
        version = "已安装"
    _add_user_path(location)
    return version


def _install_hermes(location: Path) -> str:
    location.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="key-router-hermes-") as temp_name:
        script = Path(temp_name) / "install.ps1"
        _download(HERMES_INSTALLER_URL, script, max_bytes=8 * 1024 * 1024)
        _run([
            _powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-HermesHome", str(location), "-InstallDir", str(location / "hermes-agent"),
            "-SkipSetup", "-NonInteractive",
        ], timeout=2400)
    if not (location / "hermes-agent").is_dir():
        raise InstallerError("Hermes 官方安装器结束后未找到程序目录")
    os.environ["HERMES_HOME"] = str(location)
    bin_dir = location / "bin"
    if bin_dir.is_dir():
        _add_user_path(bin_dir)
    return "main"


def _install_claude(location: Path) -> str:
    location.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="key-router-claude-") as temp_name:
        script = Path(temp_name) / "install.ps1"
        _download(CLAUDE_INSTALLER_URL, script, max_bytes=4 * 1024 * 1024)
        _run([_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "latest"], timeout=900)
    executable = location / "claude.exe"
    if not executable.is_file():
        raise InstallerError("Claude Code 官方安装器结束后未找到 claude.exe")
    _add_user_path(location)
    output = _run([str(executable), "--version"], timeout=60)
    return output.splitlines()[0][:80] if output else "已安装"


def install_agent(
    target_id: str,
    location: str | Path,
    settings_path: str | Path,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """安装一个白名单 Agent。调用前必须由界面取得用户确认。"""
    location = validate_install_location(target_id, location)
    notify = progress or (lambda _message: None)
    notify("正在获取官方安装包")
    installers = {
        "hermes": _install_hermes,
        "dsh": _install_dsh,
        "claude": _install_claude,
        "pi": _install_pi,
    }
    installer = installers.get(target_id)
    if not installer:
        raise InstallerError("该工具不在 Agent 安装白名单中")
    notify("正在安装到所选位置")
    version = installer(location)
    notify("正在验证安装结果")
    record_install(settings_path, target_id, location, version)
    return {
        "targetId": target_id,
        "name": INSTALLER_META[target_id]["name"],
        "location": str(location),
        "version": version,
    }
