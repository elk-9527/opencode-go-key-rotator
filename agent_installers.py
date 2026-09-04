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
import re
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


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
        "note": "Windows 原生版已受官方支持；安装时固定到最新正式发布提交。",
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

HERMES_RELEASE_API = "https://api.github.com/repos/NousResearch/hermes-agent/releases/latest"
HERMES_COMMIT_API = "https://api.github.com/repos/NousResearch/hermes-agent/commits/{ref}"
HERMES_INSTALLER_URL = "https://raw.githubusercontent.com/NousResearch/hermes-agent/{commit}/scripts/install.ps1"
CLAUDE_INSTALLER_URL = "https://claude.ai/install.ps1"
PI_RELEASE_API = "https://api.github.com/repos/earendil-works/pi/releases/latest"
NODE_RELEASE_INDEX = "https://nodejs.org/dist/index.json"
DSH_LATEST_API = "https://registry.npmjs.org/@deepseek-ai%2Fdsh/latest"
MAX_ZIP_MEMBERS = 20_000
MAX_ZIP_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 512 * 1024 * 1024
WINDOWS_DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL", *{f"COM{i}" for i in range(1, 10)}, *{f"LPT{i}" for i in range(1, 10)}}


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
    if str(path).startswith("\\\\"):
        raise InstallerError("安装位置不能是网络共享目录")
    if len(str(path)) > 220:
        raise InstallerError("安装路径过长，请选择更短的位置")
    if path.exists() and path.is_symlink():
        raise InstallerError("安装位置不能是符号链接")
    if path.exists() and not path.is_dir():
        raise InstallerError("安装位置必须是文件夹")
    if metadata["pathMode"] == "fixed":
        if os.path.normcase(str(path)) != os.path.normcase(str(default_parent(target_id).resolve())):
            raise InstallerError("该工具只能安装到官方固定位置")
        return path
    if os.path.normcase(path.name) != os.path.normcase(metadata["folderName"]):
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
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as temporary:
            temporary.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def managed_discovery(settings_path: str | Path, target_id: str) -> list[dict]:
    record = load_install_records(settings_path).get(target_id, {})
    if not isinstance(record, dict):
        return []
    raw_location = str(record.get("location") or "")
    location = Path(raw_location) if raw_location else Path()
    probes = {
        "hermes": (location / "hermes-agent", location / "bin" / "hermes.cmd"),
        "dsh": (location / "dsh.cmd",),
        "claude": (location / "claude.exe",),
        "pi": (location / "pi.exe",),
    }.get(target_id, ())
    if not raw_location or not any(path.exists() for path in probes):
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
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise InstallerError("安装器只允许访问完整的 HTTPS 官方地址")
    return Request(
        url,
        headers={
            "User-Agent": "Key-Router/0.6",
            "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.8",
        },
    )


def _validate_response_url(response) -> None:
    parsed = urlsplit(str(response.geturl()))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise InstallerError("官方下载地址发生了不安全的跳转")


def _download(url: str, destination: Path, *, max_bytes: int = 700 * 1024 * 1024) -> None:
    total = 0
    with urlopen(_request(url), timeout=60) as response, destination.open("wb") as output:  # nosec B310
        _validate_response_url(response)
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
    with urlopen(_request(url), timeout=60) as response:  # nosec B310
        _validate_response_url(response)
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
            members = bundle.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise InstallerError("官方压缩包文件数量异常")
            total_size = 0
            seen_targets: set[str] = set()
            for member in members:
                relative = Path(member.filename.replace("\\", "/"))
                unix_mode = (member.external_attr >> 16) & 0o170000
                unsafe_part = any(
                    ":" in part
                    or part.rstrip(" .") != part
                    or part.split(".", 1)[0].upper() in WINDOWS_DEVICE_NAMES
                    for part in relative.parts
                )
                if (
                    not member.filename
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or unsafe_part
                    or unix_mode not in {0, 0o040000, 0o100000}
                ):
                    raise InstallerError("官方压缩包包含不安全路径")
                target = (root / relative).resolve()
                if root != target and root not in target.parents:
                    raise InstallerError("官方压缩包包含越界路径")
                normalized_target = os.path.normcase(str(target))
                if normalized_target in seen_targets:
                    raise InstallerError("官方压缩包包含重复路径")
                seen_targets.add(normalized_target)
                if member.file_size < 0 or member.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise InstallerError("官方压缩包中的单个文件过大")
                total_size += member.file_size
                if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise InstallerError("官方压缩包解压后超过允许大小")
            bundle.extractall(root)
    except zipfile.BadZipFile as exc:
        raise InstallerError("官方安装包不是有效的 ZIP 文件") from exc


def _commit_staged_tree(staging: Path, location: Path) -> None:
    """在同一磁盘内原子切换安装目录；失败时恢复原版本。"""
    location.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    if location.exists():
        previous = location.parent / f".{location.name}.previous-{secrets.token_hex(8)}"
        try:
            os.replace(location, previous)
        except OSError as exc:
            raise InstallerError("现有安装正在使用，无法安全更新") from exc
    try:
        os.replace(staging, location)
    except OSError as exc:
        if previous is not None and previous.exists() and not location.exists():
            try:
                os.replace(previous, location)
            except OSError as restore_exc:
                raise InstallerError(f"无法恢复原安装；原版本保留在 {previous}") from restore_exc
        raise InstallerError("无法切换到新安装，原版本已保留") from exc
    if previous is not None:
        shutil.rmtree(previous, ignore_errors=True)


def _run_in_place_with_rollback(location: Path, action: Callable[[], None]) -> None:
    """为必须写入最终路径的官方安装器保护原安装目录。"""
    previous = None
    if location.exists():
        previous = location.parent / f".{location.name}.previous-{secrets.token_hex(8)}"
        try:
            os.replace(location, previous)
        except OSError as exc:
            raise InstallerError("现有安装正在使用，无法安全更新") from exc
    try:
        location.mkdir(parents=True, exist_ok=False)
        action()
    except Exception as exc:
        failed = None
        if location.exists():
            failed = location.parent / f".{location.name}.failed-{secrets.token_hex(8)}"
            try:
                os.replace(location, failed)
            except OSError:
                failed = None
        if previous is not None and previous.exists():
            if location.exists():
                raise InstallerError(f"安装失败且无法恢复原目录；原版本保留在 {previous}") from exc
            try:
                os.replace(previous, location)
            except OSError as restore_exc:
                raise InstallerError(f"安装失败且无法恢复原目录；原版本保留在 {previous}") from restore_exc
        if failed is not None:
            shutil.rmtree(failed, ignore_errors=True)
        elif previous is None and location.exists():
            shutil.rmtree(location, ignore_errors=True)
        raise
    else:
        if previous is not None:
            shutil.rmtree(previous, ignore_errors=True)


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
    return str(
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )


def _add_user_path(folder: Path) -> bool:
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
                    winreg.SetValueEx(
                        key,
                        "Path",
                        0,
                        kind if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) else winreg.REG_EXPAND_SZ,
                        ";".join(entries),
                    )
            try:
                ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 2000, None)
            except Exception:
                os.environ["KEY_ROUTER_PATH_BROADCAST_FAILED"] = "1"
        except OSError:
            return False
    current_entries = os.environ.get("PATH", "").split(os.pathsep)
    if os.path.normcase(folder_text) not in {
        os.path.normcase(os.path.normpath(item)) for item in current_entries if item
    }:
        os.environ["PATH"] = folder_text + os.pathsep + os.environ.get("PATH", "")
    return True


def _install_pi(location: Path) -> tuple[str, bool]:
    release = _download_json(PI_RELEASE_API)
    architecture = (
        os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "AMD64"
    ).lower()
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
            sums_asset = next(
                (item for item in assets if isinstance(item, dict) and item.get("name") == "SHA256SUMS"), None
            )
            if not sums_asset or not sums_asset.get("browser_download_url"):
                raise InstallerError("Pi 官方版本缺少 SHA-256 校验信息")
            sums = temp / "SHA256SUMS"
            _download(str(sums_asset["browser_download_url"]), sums, max_bytes=2 * 1024 * 1024)
            match = re.search(
                rf"^([0-9a-f]{{64}})\s+[*]?{re.escape(asset_name)}$", sums.read_text(encoding="utf-8"), re.M | re.I
            )
            expected = match.group(1) if match else ""
        _verify_sha256(archive, expected)
        extracted = temp / "extracted"
        _safe_extract_zip(archive, extracted)
        executables = list(extracted.rglob("pi.exe"))
        if len(executables) != 1:
            raise InstallerError("Pi 官方安装包结构无法识别")
        source_root = executables[0].parent
        location.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{location.name}.staging-", dir=location.parent))
        try:
            shutil.copytree(source_root, staging, dirs_exist_ok=True)
            _commit_staged_tree(staging, location)
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
    executable = location / "pi.exe"
    if not executable.is_file():
        raise InstallerError("Pi 安装完成后未找到 pi.exe")
    return str(release.get("tag_name") or "已安装"), _add_user_path(location)


def _node_release() -> tuple[str, str]:
    releases = _download_json(NODE_RELEASE_INDEX)
    if not isinstance(releases, list):
        raise InstallerError("Node.js 官方版本信息格式异常")
    architecture = (
        os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "AMD64"
    ).lower()
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
        match = re.search(
            rf"^([0-9a-f]{{64}})\s+{re.escape(asset_name)}$", sums.read_text(encoding="utf-8"), re.M | re.I
        )
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


def _install_dsh(location: Path) -> tuple[str, bool]:
    metadata = _download_json(DSH_LATEST_API)
    requested_version = str(metadata.get("version") or "") if isinstance(metadata, dict) else ""
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}", requested_version):
        raise InstallerError("DSH 最新正式版本标识无效")
    location.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{location.name}.staging-", dir=location.parent))
    try:
        node = _ensure_private_node(staging / "runtime" / "node")
        npm = node.parent / "npm.cmd"
        app = staging / "app"
        app.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment["PATH"] = str(node.parent) + os.pathsep + environment.get("PATH", "")
        _run(
            [
                str(npm),
                "install",
                "--prefix",
                str(app),
                "--omit=dev",
                "--no-audit",
                "--no-fund",
                "--registry=https://registry.npmjs.org/",
                f"@deepseek-ai/dsh@{requested_version}",
            ],
            timeout=1800,
            environment=environment,
        )
        entry = app / "node_modules" / "@deepseek-ai" / "dsh" / "lib" / "bin.js"
        if not entry.is_file():
            raise InstallerError("DSH 官方包安装完成后未找到命令入口")
        launcher = staging / "dsh.cmd"
        launcher.write_text(
            '@echo off\r\n"%~dp0runtime\\node\\node.exe" "%~dp0app\\node_modules\\@deepseek-ai\\dsh\\lib\\bin.js" %*\r\n',
            encoding="utf-8",
        )
        package_json = app / "node_modules" / "@deepseek-ai" / "dsh" / "package.json"
        try:
            version = str(json.loads(package_json.read_text(encoding="utf-8"))["version"])
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise InstallerError("DSH 安装完成后无法确认版本") from exc
        if version != requested_version:
            raise InstallerError("DSH 安装版本与请求版本不一致")
        _commit_staged_tree(staging, location)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return version, _add_user_path(location)


def _install_hermes(location: Path) -> tuple[str, bool]:
    release = _download_json(HERMES_RELEASE_API)
    tag = str(release.get("tag_name") or "") if isinstance(release, dict) else ""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", tag):
        raise InstallerError("Hermes 最新正式版本标识无效")
    commit_data = _download_json(HERMES_COMMIT_API.format(ref=quote(tag, safe="")))
    commit = str(commit_data.get("sha") or "") if isinstance(commit_data, dict) else ""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise InstallerError("Hermes 正式版本缺少有效提交标识")
    with tempfile.TemporaryDirectory(prefix="key-router-hermes-") as temp_name:
        script = Path(temp_name) / "install.ps1"
        _download(HERMES_INSTALLER_URL.format(commit=commit), script, max_bytes=8 * 1024 * 1024)

        def install() -> None:
            _run(
                [
                    _powershell(),
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                    "-HermesHome",
                    str(location),
                    "-InstallDir",
                    str(location / "hermes-agent"),
                    "-Commit",
                    commit,
                    "-SkipSetup",
                    "-NonInteractive",
                ],
                timeout=2400,
            )
            if not (location / "hermes-agent").is_dir():
                raise InstallerError("Hermes 官方安装器结束后未找到程序目录")

        _run_in_place_with_rollback(
            location,
            install,
        )
    os.environ["HERMES_HOME"] = str(location)
    bin_dir = location / "bin"
    path_ready = _add_user_path(bin_dir) if bin_dir.is_dir() else False
    return tag, path_ready


def _install_claude(location: Path) -> tuple[str, bool]:
    location.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="key-router-claude-") as temp_name:
        script = Path(temp_name) / "install.ps1"
        _download(CLAUDE_INSTALLER_URL, script, max_bytes=4 * 1024 * 1024)
        _run([_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "latest"], timeout=900)
    executable = location / "claude.exe"
    if not executable.is_file():
        raise InstallerError("Claude Code 官方安装器结束后未找到 claude.exe")
    output = _run([str(executable), "--version"], timeout=60)
    return (output.splitlines()[0][:80] if output else "已安装"), _add_user_path(location)


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
    version, path_ready = installer(location)
    notify("正在验证安装结果")
    record_install(settings_path, target_id, location, version)
    return {
        "targetId": target_id,
        "name": INSTALLER_META[target_id]["name"],
        "location": str(location),
        "version": version,
        "warning": "工具已安装，但未能加入当前用户 PATH；可从安装目录直接启动" if not path_ready else "",
    }
