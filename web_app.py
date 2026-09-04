"""Key Router 的本地桌面 Web 界面。

服务只绑定 127.0.0.1，默认使用 Edge / Chrome 的应用窗口模式打开。
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import mimetypes
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import agent_installers
import rotate_keys as core

APP_VERSION = "0.6.0"
MAX_BODY = 32 * 1024
PREVIEW_TTL_SECONDS = 15 * 60
MAX_PREVIEW_TOKENS = 128
INSTALL_TTL_SECONDS = 10 * 60
MAX_INSTALL_TOKENS = 32
IDLE_SHUTDOWN_SECONDS = 60 * 60


SingleInstanceLock = core.ProcessFileLock


def resource_dir() -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "ui"


def safe_text(value) -> str:
    text = str(value)

    text = re.sub(
        r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{4,})",
        lambda match: f"Bearer {core.mask(match.group(1))}",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:api[_ -]?key|auth[_ -]?token|access[_ -]?token|token)\b\s*[:=]\s*)([^\s,;&]+)",
        lambda match: match.group(1) + core.mask(match.group(2).strip("\"'")),
        text,
    )

    return re.sub(r"sk-[A-Za-z0-9_\-]{10,}", lambda match: core.mask(match.group(0)), text)


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, demo=False):
        super().__init__(address, handler)
        self.demo = demo
        self.access_token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self.operation_lock = threading.Lock()
        self.lifecycle_condition = threading.Condition()
        self.active_operations = 0
        self.shutting_down = False
        self.preview_lock = threading.Lock()
        self.preview_tokens: dict[str, tuple[str, str, float]] = {}
        self.install_lock = threading.Lock()
        self.install_tokens: dict[str, tuple[str, str, float]] = {}
        self.last_request_at = time.monotonic()
        self.assets = resource_dir()

    def try_begin_operation(self) -> tuple[bool, str]:
        with self.lifecycle_condition:
            if self.shutting_down:
                return False, "软件正在关闭，请重新启动后再操作"
            if not self.operation_lock.acquire(blocking=False):
                return False, "已有操作正在进行，请稍候"
            self.active_operations += 1
            return True, ""

    def finish_operation(self) -> None:
        self.operation_lock.release()
        with self.lifecycle_condition:
            self.active_operations -= 1
            self.lifecycle_condition.notify_all()

    def request_shutdown(self) -> None:
        with self.lifecycle_condition:
            self.shutting_down = True
        self.shutdown()

    def wait_for_operations(self) -> None:
        with self.lifecycle_condition:
            self.shutting_down = True
            while self.active_operations:
                self.lifecycle_condition.wait()

    def touch(self):
        self.last_request_at = time.monotonic()

    def make_preview_token(
        self,
        base_url: str,
        new_key: str,
        target_ids: list[str],
        target_options: dict,
        plan_digest: str,
    ) -> str:
        token = secrets.token_urlsafe(28)
        digest = self._preview_digest(base_url, new_key, target_ids, target_options)
        with self.preview_lock:
            self.preview_tokens[token] = (digest, plan_digest, time.monotonic())
            self._prune_preview_tokens()
            while len(self.preview_tokens) > MAX_PREVIEW_TOKENS:
                oldest = min(self.preview_tokens, key=lambda item: self.preview_tokens[item][2])
                self.preview_tokens.pop(oldest, None)
        return token

    def consume_preview_token(
        self,
        token: str,
        base_url: str,
        new_key: str,
        target_ids: list[str],
        target_options: dict,
    ) -> str | None:
        with self.preview_lock:
            self._prune_preview_tokens()
            stored = self.preview_tokens.pop(token, None)
        if not stored:
            return None
        digest, plan_digest, _created = stored
        if not secrets.compare_digest(digest, self._preview_digest(base_url, new_key, target_ids, target_options)):
            return None
        return plan_digest

    def _preview_digest(self, base_url: str, new_key: str, target_ids: list[str], target_options: dict) -> str:
        target_payload = json.dumps(target_ids, ensure_ascii=True, separators=(",", ":"))
        options_payload = json.dumps(target_options, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        payload = f"{base_url}\0{new_key}\0{target_payload}\0{options_payload}\0{self.csrf_token}".encode()
        return hashlib.sha256(payload).hexdigest()

    def _prune_preview_tokens(self):
        now = time.monotonic()
        expired = [
            token
            for token, (_digest, _plan_digest, created) in self.preview_tokens.items()
            if now - created > PREVIEW_TTL_SECONDS
        ]
        for token in expired:
            self.preview_tokens.pop(token, None)

    def make_install_token(self, target_id: str, location: str) -> str:
        token = secrets.token_urlsafe(28)
        with self.install_lock:
            self.install_tokens[token] = (target_id, location, time.monotonic())
            self._prune_install_tokens()
            while len(self.install_tokens) > MAX_INSTALL_TOKENS:
                oldest = min(self.install_tokens, key=lambda item: self.install_tokens[item][2])
                self.install_tokens.pop(oldest, None)
        return token

    def consume_install_token(self, token: str, target_id: str) -> str | None:
        with self.install_lock:
            self._prune_install_tokens()
            stored = self.install_tokens.get(token)
            if not stored or not secrets.compare_digest(stored[0], target_id):
                return None
            self.install_tokens.pop(token, None)
            return stored[1]

    def discard_install_token(self, token: str) -> None:
        with self.install_lock:
            self.install_tokens.pop(token, None)

    def _prune_install_tokens(self):
        now = time.monotonic()
        expired = [
            token
            for token, (_target_id, _location, created) in self.install_tokens.items()
            if now - created > INSTALL_TTL_SECONDS
        ]
        for token in expired:
            self.install_tokens.pop(token, None)


class RequestHandler(BaseHTTPRequestHandler):
    server: AppServer

    def log_message(self, _format, *_args):
        return

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; form-action 'self'; "
            "style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        self.server.touch()
        if not self._trusted_host():
            self._json({"ok": False, "error": "请求来源无效"}, HTTPStatus.FORBIDDEN)
            return
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/") and not self._trusted_client():
            self._json({"ok": False, "error": "本地客户端校验失败"}, HTTPStatus.FORBIDDEN)
            return
        if path == "/api/session":
            self._json(
                {
                    "ok": True,
                    "token": self.server.csrf_token,
                    "version": APP_VERSION,
                    "demo": self.server.demo,
                }
            )
            return
        if path == "/api/detect":
            self._detect()
            return
        if path == "/health":
            self._json({"ok": True})
            return
        self._static(path)

    def do_POST(self):
        self.server.touch()
        if not self._trusted_host() or not self._trusted_origin() or not self._trusted_client():
            self._json({"ok": False, "error": "请求来源无效"}, HTTPStatus.FORBIDDEN)
            return
        supplied_token = self.headers.get("X-Key-Rotator-Token", "")
        if not secrets.compare_digest(supplied_token, self.server.csrf_token):
            self._json({"ok": False, "error": "会话校验失败，请刷新窗口"}, HTTPStatus.FORBIDDEN)
            return
        if self.path == "/api/preview":
            self._rotation(apply=False)
        elif self.path == "/api/detect-options":
            try:
                body = self._read_json()
            except ValueError as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            options = body.get("targetOptions", {})
            if not isinstance(options, dict):
                self._json({"ok": False, "error": "目标选项格式无效"}, HTTPStatus.BAD_REQUEST)
                return
            self._detect(options)
        elif self.path == "/api/apply":
            self._rotation(apply=True)
        elif self.path == "/api/pick-install-location":
            self._pick_install_location()
        elif self.path == "/api/install-agent":
            self._install_agent()
        elif self.path == "/api/pick-dsh-config":
            self._pick_dsh_config()
        elif self.path == "/api/shutdown":
            self._json({"ok": True})
            threading.Thread(target=self.server.request_shutdown, daemon=True).start()
        else:
            self._json({"ok": False, "error": "接口不存在"}, HTTPStatus.NOT_FOUND)

    def _trusted_host(self) -> bool:
        port = self.server.server_address[1]
        host = self.headers.get("Host", "").strip().lower()
        return host in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _trusted_origin(self) -> bool:
        if self.headers.get("Sec-Fetch-Site", "").strip().lower() == "cross-site":
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        port = self.server.server_address[1]
        return origin.rstrip("/").lower() in {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        }

    def _trusted_client(self) -> bool:
        supplied = self.headers.get("X-Key-Rotator-Access", "")
        return secrets.compare_digest(supplied, self.server.access_token)

    def _static(self, path: str):
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        if relative not in {"index.html", "styles.css", "theme-init.js", "app.js", "favicon.svg"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        target = self.server.assets / relative
        if not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _detect(self, target_options: dict | None = None):
        try:
            if self.server.demo:
                items = []
                for item_id in core.TARGET_ORDER:
                    title, location = core.TARGET_META[item_id]
                    extension = core.EXTENSION_META.get(item_id)
                    extension = (
                        {**extension, "installed": True, "version": "1.0.0", "installable": True} if extension else None
                    )
                    installer = None
                    if extension:
                        installer = {
                            "targetId": item_id,
                            "name": extension["name"],
                            "publisher": extension["publisher"],
                            "identity": extension["id"],
                            "sourceUrl": f"https://marketplace.visualstudio.com/items?itemName={extension['id']}",
                            "pathMode": "fixed",
                            "folderName": "",
                            "sizeLabel": "由 VS Code 管理",
                            "note": "扩展安装到当前 VS Code 使用的扩展目录。",
                            "kind": "extension",
                            "installed": True,
                            "enabled": True,
                            "location": r"C:\Users\Demo\.vscode\extensions",
                        }
                    elif item_id in agent_installers.INSTALLER_META:
                        installer = agent_installers.public_metadata(item_id, installed=item_id != "pi")
                        installer["kind"] = "agent"
                    candidates = []
                    providers = []
                    selected_provider = ""
                    discovery = [{"path": f"C:\\Users\\Demo\\{item_id}", "source": "演示数据"}]
                    if item_id == "dsh":
                        providers = [
                            {
                                "id": "custom-gateway",
                                "name": "Custom Gateway",
                                "baseUrl": "https://api.example.com/v1",
                                "apiKeyEnv": "CUSTOM_API_KEY",
                                "current": True,
                                "writable": True,
                            }
                        ]
                        candidates = [
                            {
                                "path": r"C:\Users\Demo\.dsh\settings.yaml",
                                "credentialsPath": r"C:\Users\Demo\.dsh\.credentials.yaml",
                                "source": "标准用户目录",
                                "providers": providers,
                                "currentProvider": "custom-gateway",
                            }
                        ]
                        selected_provider = "custom-gateway"
                    items.append(
                        {
                            "id": item_id,
                            "title": title,
                            "location": location,
                            "state": "ok" if item_id not in {"pi"} else "ready",
                            "badge": "已配置" if item_id not in {"pi"} else "可写入",
                            "detail": "https://api.example.com/v1 · sk-d…TAIL (28)"
                            if item_id not in {"pi"}
                            else "已找到应用，可创建配置",
                            "selectable": True,
                            "note": "",
                            "discovery": discovery,
                            "candidates": candidates,
                            "providers": providers,
                            "selectedProvider": selected_provider,
                            "extension": extension,
                            "installer": installer,
                        }
                    )
                running = False
            else:
                items = core.detect_targets(target_options)
                running = core.vscode_running()
            self._json({"ok": True, "items": items, "vscodeRunning": running})
        except Exception:
            self._json({"ok": False, "error": "检测失败，请检查配置文件权限或格式"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _pick_install_location(self):
        try:
            body = self._read_json()
            target_id = str(body.get("targetId", "")).strip()
            if self.server.demo:
                if target_id not in {*core.EXTENSION_META, *agent_installers.INSTALLER_META}:
                    raise core.RotationError("该工具不在安装白名单中")
                location = rf"C:\Users\Demo\Apps\{target_id}"
                token = self.server.make_install_token(target_id, location)
                self._json({"ok": True, "cancelled": False, "location": location, "installToken": token})
                return
            if target_id in core.EXTENSION_META:
                instances = core.discover_vscode_installations()
                if not instances:
                    raise core.RotationError("没有找到 VS Code，无法安装扩展")
                roots = core.discover_vscode_extension_dirs(instances)
                location = str(
                    next(
                        (root for root in roots if root.is_dir()),
                        roots[0] if roots else Path(core.VSCODE_EXTENSIONS_DIR),
                    )
                )
            elif target_id in agent_installers.INSTALLER_META:
                metadata = agent_installers.INSTALLER_META[target_id]
                if metadata["pathMode"] == "fixed":
                    location = str(agent_installers.resolve_install_location(target_id))
                else:
                    selected = pick_install_parent(target_id)
                    if not selected:
                        self._json({"ok": True, "cancelled": True})
                        return
                    location = str(agent_installers.resolve_install_location(target_id, selected))
                    agent_installers.validate_install_location(target_id, location)
            else:
                raise core.RotationError("该工具不在安装白名单中")
            token = self.server.make_install_token(target_id, location)
            self._json({"ok": True, "cancelled": False, "location": location, "installToken": token})
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except (core.RotationError, agent_installers.InstallerError) as exc:
            self._json({"ok": False, "error": safe_text(exc)}, HTTPStatus.CONFLICT)
        except Exception:
            self._json({"ok": False, "error": "无法选择安装位置"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _install_agent(self):
        try:
            body = self._read_json()
            target_id = str(body.get("targetId", "")).strip()
            install_token = str(body.get("installToken", "")).strip()
            if self.server.demo:
                raise core.RotationError("演示模式不会安装工具")
            location = self.server.consume_install_token(install_token, target_id)
            if not location:
                raise core.RotationError("安装确认已失效，请重新选择位置")
            started, reason = self.server.try_begin_operation()
            if not started:
                raise core.RotationError(reason)
            try:
                if target_id in core.EXTENSION_META:
                    installed = core.install_vscode_extension(core.EXTENSION_META[target_id]["id"], location)
                    result = {
                        "targetId": target_id,
                        "name": installed["name"],
                        "location": location,
                        "version": installed["version"],
                    }
                else:
                    result = agent_installers.install_agent(target_id, location, core.APP_SETTINGS)
                    core.refresh_runtime_paths()
            finally:
                self.server.finish_operation()
            self._json({"ok": True, "installed": result})
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except (core.RotationError, agent_installers.InstallerError) as exc:
            self._json({"ok": False, "error": safe_text(exc)}, HTTPStatus.CONFLICT)
        except Exception:
            self._json({"ok": False, "error": "安装失败，请检查网络后重试"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _pick_dsh_config(self):
        try:
            if self.server.demo:
                raise core.RotationError("演示模式不打开本机文件选择器")
            selected = pick_dsh_settings_file()
            if not selected:
                self._json({"ok": True, "cancelled": True})
                return
            candidates = core.discover_dsh_configs(selected)
            match = next(
                (item for item in candidates if os.path.normcase(item["path"]) == os.path.normcase(selected)), None
            )
            if not match:
                raise core.RotationError("所选文件不是可读取的 DSH settings.yaml")
            item = core._state("dsh", {"settingsPath": selected}).public()
            self._json({"ok": True, "cancelled": False, "item": item})
        except core.RotationError as exc:
            self._json({"ok": False, "error": safe_text(exc)}, HTTPStatus.CONFLICT)
        except Exception:
            self._json({"ok": False, "error": "无法读取所选 DSH 配置"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _rotation(self, *, apply: bool):
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        base_url = body.get("baseUrl", "")
        new_key = body.get("newKey", "")
        if not isinstance(base_url, str) or not isinstance(new_key, str):
            self._json({"ok": False, "error": "连接参数格式无效"}, HTTPStatus.BAD_REQUEST)
            return
        target_ids = body.get("targetIds", [])
        target_options = body.get("targetOptions", {})
        if not isinstance(target_ids, list) or any(not isinstance(item, str) for item in target_ids):
            self._json({"ok": False, "error": "目标工具列表无效"}, HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(target_options, dict):
            self._json({"ok": False, "error": "目标选项无效"}, HTTPStatus.BAD_REQUEST)
            return
        target_ids = list(dict.fromkeys(target_ids))
        try:
            base_url = core.validate_base_url(base_url)
            new_key = core.validate_key(new_key)
            if not target_ids:
                raise core.RotationError("请至少选择一个目标工具")
            if any(item not in core.TARGET_ORDER for item in target_ids):
                raise core.RotationError("包含不支持的目标工具")
        except core.RotationError as exc:
            self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        expected_plan_digest = None
        if apply:
            preview_token = str(body.get("previewToken", ""))
            expected_plan_digest = self.server.consume_preview_token(
                preview_token,
                base_url,
                new_key,
                target_ids,
                target_options,
            )
            if not expected_plan_digest:
                self._json({"ok": False, "error": "安全预览已过期或配置已变化，请重新预览"}, HTTPStatus.CONFLICT)
                return
        if self.server.demo and apply:
            self._json({"ok": False, "error": "演示模式不会执行真实替换"}, HTTPStatus.CONFLICT)
            return
        started, reason = self.server.try_begin_operation()
        if not started:
            self._json({"ok": False, "error": reason}, HTTPStatus.CONFLICT)
            return

        try:
            if self.server.demo:
                logs = [
                    "预览模式，不会写入文件",
                    f"Base URL：{base_url}",
                    f"API Key：{core.mask(new_key)}",
                    "",
                    *[f"【{core.TARGET_META[item][0]}】\n  将更新明确的地址与密钥字段" for item in target_ids],
                    "",
                    f"预览完成：{len(target_ids)} 个工具",
                ]
                result = {
                    "applied": False,
                    "vscode_running": False,
                    "backup_dir": None,
                    "changes": [
                        {
                            "targetId": item,
                            "target": core.TARGET_META[item][0],
                            "file": core.TARGET_META[item][1],
                            "path": core.TARGET_META[item][1],
                            "summary": "Base URL / API Key",
                        }
                        for item in target_ids
                    ],
                    "plan_digest": "demo-preview",
                }
            else:
                logs = []
                result = core.run_rotation(
                    base_url,
                    new_key,
                    target_ids,
                    apply=apply,
                    target_options=target_options,
                    expected_plan_digest=expected_plan_digest,
                    log=logs.append,
                )
            payload = {
                "ok": True,
                "applied": result["applied"],
                "vscodeRunning": result["vscode_running"],
                "backupDirectory": result["backup_dir"],
                "changes": result.get("changes", []),
                "logs": [safe_text(line) for line in logs],
            }
            if not apply:
                payload["previewToken"] = self.server.make_preview_token(
                    base_url,
                    new_key,
                    target_ids,
                    target_options,
                    result["plan_digest"],
                )
            self._json(payload)
        except core.RotationError as exc:
            self._json({"ok": False, "error": safe_text(exc)}, HTTPStatus.CONFLICT)
        except Exception:
            self._json({"ok": False, "error": "操作失败，未完成配置写入"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        finally:
            self.server.finish_operation()

    def _read_json(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("不支持分块请求")
        media_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if media_type != "application/json":
            raise ValueError("请求内容类型必须是 JSON")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("请求长度无效") from exc
        if size <= 0 or size > MAX_BODY:
            raise ValueError("请求内容为空或过大")
        try:
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("请求内容不是有效 JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("请求内容必须是 JSON 对象")
        return payload

    def _json(self, data: dict, status=HTTPStatus.OK):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def pick_dsh_settings_file() -> str:
    """由用户显式打开 Windows 文件选择器，不接受网页传入路径或命令。"""
    if os.name != "nt":
        raise core.RotationError("手动定位目前仅支持 Windows")
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = '选择 DSH settings.yaml'
$dialog.Filter = 'DSH settings.yaml|settings.yaml|YAML 文件|*.yaml;*.yml'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  [Console]::Write($dialog.FileName)
}
"""
    powershell = str(
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            timeout=300,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise core.RotationError("文件选择器等待超时") from exc
    except OSError as exc:
        raise core.RotationError("无法打开 Windows 文件选择器") from exc
    if result.returncode != 0:
        raise core.RotationError("Windows 文件选择器运行失败")
    selected = result.stdout.decode("utf-8-sig", errors="replace").strip()
    if selected and Path(selected).name.lower() != "settings.yaml":
        raise core.RotationError("请选择名为 settings.yaml 的 DSH 配置文件")
    return selected


def pick_install_parent(target_id: str) -> str:
    """打开本机文件夹选择器；网页只能取得用户明确选择的目录。"""
    metadata = agent_installers.INSTALLER_META.get(target_id)
    if not metadata:
        raise core.RotationError("该工具不在安装白名单中")
    if os.name != "nt":
        raise core.RotationError("一键安装目前仅支持 Windows")
    title = f"选择 {metadata['name']} 的安装位置"
    initial = agent_installers.default_parent(target_id)
    if not initial.is_dir():
        initial = Path.home()
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = $env:RK_INSTALL_PICKER_TITLE
$dialog.SelectedPath = $env:RK_INSTALL_PICKER_INITIAL
$dialog.ShowNewFolderButton = $true
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  [Console]::Write($dialog.SelectedPath)
}
"""
    powershell = str(
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    environment = os.environ.copy()
    environment["RK_INSTALL_PICKER_TITLE"] = title
    environment["RK_INSTALL_PICKER_INITIAL"] = str(initial)
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            timeout=300,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise core.RotationError("文件夹选择器等待超时") from exc
    except OSError as exc:
        raise core.RotationError("无法打开 Windows 文件夹选择器") from exc
    if result.returncode != 0:
        raise core.RotationError("Windows 文件夹选择器运行失败")
    return result.stdout.decode("utf-8-sig", errors="replace").strip()


def app_browser_path() -> Path | None:
    candidates = []
    for variable, relative in (
        ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe"),
        ("PROGRAMFILES", "Microsoft/Edge/Application/msedge.exe"),
        ("LOCALAPPDATA", "Microsoft/Edge/Application/msedge.exe"),
        ("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
        ("PROGRAMFILES(X86)", "Google/Chrome/Application/chrome.exe"),
        ("LOCALAPPDATA", "Google/Chrome/Application/chrome.exe"),
    ):
        base = os.environ.get(variable)
        if base:
            candidates.append(Path(base) / relative)
    return next((path for path in candidates if path.is_file()), None)


def _cleanup_browser_profile(process: subprocess.Popen, profile_dir: str, on_exit=None):
    try:
        process.wait()
    finally:
        for _attempt in range(5):
            try:
                shutil.rmtree(profile_dir)
                break
            except OSError:
                time.sleep(0.5)
        if on_exit:
            on_exit()


def launch_app_window(url: str, on_exit=None):
    browser = app_browser_path()
    if browser:
        profile_dir = tempfile.mkdtemp(prefix="key-router-browser-")
        try:
            process = subprocess.Popen(
                [
                    str(browser),
                    f"--app={url}",
                    f"--user-data-dir={profile_dir}",
                    "--disable-extensions",
                    "--disable-sync",
                    "--disable-background-mode",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-features=msEdgeSidebarV2",
                    "--window-size=1220,840",
                ]
            )
            threading.Thread(
                target=_cleanup_browser_profile,
                args=(process, profile_dir, on_exit),
                daemon=True,
            ).start()
            return process
        except OSError:
            shutil.rmtree(profile_dir, ignore_errors=True)
    return None


def launch_or_report(server: AppServer, url: str):
    if launch_app_window(url, server.request_shutdown) is not None:
        return
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(
                0,
                "未找到可用的 Microsoft Edge 或 Google Chrome，Key Router 无法打开安全应用窗口。",
                "Key Router",
                0x10,
            )
        except (AttributeError, OSError):
            pass
    server.request_shutdown()


def idle_watchdog(server: AppServer):
    while True:
        time.sleep(30)
        if time.monotonic() - server.last_request_at > IDLE_SHUTDOWN_SECONDS:
            server.request_shutdown()
            return


def smoke_test():
    server = AppServer(("127.0.0.1", 0), RequestHandler, demo=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    with urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:  # nosec B310
        if json.loads(response.read()).get("ok") is not True:
            raise RuntimeError("健康检查失败")
    with urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:  # nosec B310
        page = response.read()
        if b"Key Router" not in page or b'data-theme-choice="system"' not in page:
            raise RuntimeError("静态页面检查失败")
    session_request = Request(
        f"http://127.0.0.1:{port}/api/session",
        headers={"X-Key-Rotator-Access": server.access_token},
    )
    with urlopen(session_request, timeout=5) as response:  # nosec B310
        session = json.loads(response.read())
    preview_request = Request(
        f"http://127.0.0.1:{port}/api/preview",
        data=json.dumps(
            {
                "baseUrl": "https://api.example.com/v1",
                "newKey": "demo-smokeTest1234567890TAIL",
                "targetIds": ["hermes", "claude", "pi"],
            }
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Key-Rotator-Token": session["token"],
            "X-Key-Rotator-Access": server.access_token,
        },
        method="POST",
    )
    with urlopen(preview_request, timeout=5) as response:  # nosec B310
        preview = json.loads(response.read())
        if preview.get("ok") is not True or not preview.get("previewToken"):
            raise RuntimeError("预览接口检查失败")
    server.shutdown()
    server.server_close()
    print("Web app smoke test: OK")


def _report_restore_result(message: str, *, error: bool = False) -> None:
    print(message, file=sys.stderr if error else sys.stdout)
    if os.name == "nt" and getattr(sys, "frozen", False) and os.environ.get("RK_NO_MESSAGE_BOX") != "1":
        try:
            ctypes.windll.user32.MessageBoxW(0, message, "Key Router 备份恢复", 0x10 if error else 0x40)
        except (AttributeError, OSError):
            pass


def main():
    parser = argparse.ArgumentParser(description="Key Router GUI")
    parser.add_argument("--demo", action="store_true", help="使用脱敏演示数据，不读取真实配置")
    parser.add_argument("--no-open", action="store_true", help="只启动本地服务，不自动打开窗口")
    parser.add_argument("--smoke-test", action="store_true", help="运行无风险冒烟测试")
    parser.add_argument("--restore-backup", metavar="DIR", help="从指定的 Key Router 备份目录恢复")
    args = parser.parse_args()
    if args.restore_backup:
        try:
            restored = core.restore_backup_directory(args.restore_backup)
        except core.RotationError as exc:
            _report_restore_result(f"恢复失败：{safe_text(exc)}", error=True)
            return 1
        _report_restore_result(f"已从备份恢复 {restored} 个配置位置")
        return 0
    if args.smoke_test:
        smoke_test()
        return 0

    instance_lock = SingleInstanceLock(Path(core.APP_SETTINGS).with_name("key-router.lock"))
    if not instance_lock.acquire():
        print("Key Router 已在运行；请使用现有窗口。")
        return 0

    server = AppServer(("127.0.0.1", 0), RequestHandler, demo=args.demo)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/#access={server.access_token}"
    port_file = os.environ.get("RK_PORT_FILE")
    if port_file:
        core._atomic_write_text(
            port_file,
            json.dumps({"port": port, "accessToken": server.access_token}, separators=(",", ":")),
        )
    threading.Thread(target=idle_watchdog, args=(server,), daemon=True).start()
    if not args.no_open:
        threading.Timer(0.35, launch_or_report, args=(server, url)).start()
    print(f"Key Router: http://127.0.0.1:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.wait_for_operations()
        server.server_close()
        instance_lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
