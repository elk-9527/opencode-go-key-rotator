# -*- coding: utf-8 -*-
"""Key Router 的本地桌面 Web 界面。

服务只绑定 127.0.0.1，默认使用 Edge / Chrome 的应用窗口模式打开。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
import webbrowser

import rotate_keys as core


APP_VERSION = '0.3.0'
MAX_BODY = 32 * 1024
PREVIEW_TTL_SECONDS = 15 * 60
IDLE_SHUTDOWN_SECONDS = 60 * 60


def resource_dir() -> Path:
    base = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    return base / 'ui'


def safe_text(value) -> str:
    text = str(value)

    def repl(match):
        return core.mask(match.group(0))

    return re.sub(r'sk-[A-Za-z0-9_\-]{10,}', repl, text)


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, demo=False):
        super().__init__(address, handler)
        self.demo = demo
        self.csrf_token = secrets.token_urlsafe(32)
        self.operation_lock = threading.Lock()
        self.preview_tokens: dict[str, tuple[str, float]] = {}
        self.last_request_at = time.monotonic()
        self.assets = resource_dir()

    def touch(self):
        self.last_request_at = time.monotonic()

    def make_preview_token(self, base_url: str, new_key: str, target_ids: list[str]) -> str:
        token = secrets.token_urlsafe(28)
        digest = self._preview_digest(base_url, new_key, target_ids)
        self.preview_tokens[token] = (digest, time.monotonic())
        self._prune_preview_tokens()
        return token

    def consume_preview_token(self, token: str, base_url: str, new_key: str, target_ids: list[str]) -> bool:
        self._prune_preview_tokens()
        stored = self.preview_tokens.pop(token, None)
        if not stored:
            return False
        digest, _created = stored
        return secrets.compare_digest(digest, self._preview_digest(base_url, new_key, target_ids))

    def _preview_digest(self, base_url: str, new_key: str, target_ids: list[str]) -> str:
        target_payload = json.dumps(target_ids, ensure_ascii=True, separators=(',', ':'))
        payload = f'{base_url}\0{new_key}\0{target_payload}\0{self.csrf_token}'.encode('utf-8')
        return hashlib.sha256(payload).hexdigest()

    def _prune_preview_tokens(self):
        now = time.monotonic()
        expired = [
            token for token, (_digest, created) in self.preview_tokens.items()
            if now - created > PREVIEW_TTL_SECONDS
        ]
        for token in expired:
            self.preview_tokens.pop(token, None)


class RequestHandler(BaseHTTPRequestHandler):
    server: AppServer

    def log_message(self, _format, *_args):
        return

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def do_GET(self):
        self.server.touch()
        path = self.path.split('?', 1)[0]
        if path == '/api/session':
            self._json({
                'ok': True,
                'token': self.server.csrf_token,
                'version': APP_VERSION,
                'demo': self.server.demo,
            })
            return
        if path == '/api/detect':
            self._detect()
            return
        if path == '/health':
            self._json({'ok': True})
            return
        self._static(path)

    def do_POST(self):
        self.server.touch()
        if self.headers.get('X-Key-Rotator-Token') != self.server.csrf_token:
            self._json({'ok': False, 'error': '会话校验失败，请刷新窗口'}, HTTPStatus.FORBIDDEN)
            return
        if self.path == '/api/preview':
            self._rotation(apply=False)
        elif self.path == '/api/apply':
            self._rotation(apply=True)
        elif self.path == '/api/shutdown':
            self._json({'ok': True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self._json({'ok': False, 'error': '接口不存在'}, HTTPStatus.NOT_FOUND)

    def _static(self, path: str):
        relative = 'index.html' if path in ('', '/') else path.lstrip('/')
        if relative not in {'index.html', 'styles.css', 'theme-init.js', 'app.js', 'favicon.svg'}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        target = self.server.assets / relative
        if not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or 'application/octet-stream'
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', f'{content_type}; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _detect(self):
        try:
            if self.server.demo:
                items = []
                for item_id in core.TARGET_ORDER:
                    title, location = core.TARGET_META[item_id]
                    items.append({
                        'id': item_id,
                        'title': title,
                        'location': location,
                        'state': 'ok' if item_id not in {'pi'} else 'ready',
                        'badge': '已配置' if item_id not in {'pi'} else '可写入',
                        'detail': 'https://api.example.com/v1 · sk-d…TAIL (28)' if item_id not in {'pi'} else '已找到应用，可创建配置',
                        'selectable': True,
                        'note': '',
                    })
                running = False
            else:
                items = core.detect_targets()
                running = core.vscode_running()
            self._json({'ok': True, 'items': items, 'vscodeRunning': running})
        except Exception as exc:
            self._json({'ok': False, 'error': safe_text(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _rotation(self, *, apply: bool):
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json({'ok': False, 'error': str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        base_url = str(body.get('baseUrl', '')).strip()
        new_key = str(body.get('newKey', '')).strip()
        target_ids = body.get('targetIds', [])
        if not isinstance(target_ids, list) or any(not isinstance(item, str) for item in target_ids):
            self._json({'ok': False, 'error': '目标工具列表无效'}, HTTPStatus.BAD_REQUEST)
            return
        target_ids = list(dict.fromkeys(target_ids))
        try:
            base_url = core.validate_base_url(base_url)
            new_key = core.validate_key(new_key)
            if not target_ids:
                raise core.RotationError('请至少选择一个目标工具')
            if any(item not in core.TARGET_ORDER for item in target_ids):
                raise core.RotationError('包含不支持的目标工具')
        except core.RotationError as exc:
            self._json({'ok': False, 'error': str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if apply:
            preview_token = str(body.get('previewToken', ''))
            if not self.server.consume_preview_token(preview_token, base_url, new_key, target_ids):
                self._json({'ok': False, 'error': '安全预览已过期或配置已变化，请重新预览'}, HTTPStatus.CONFLICT)
                return
        if self.server.demo and apply:
            self._json({'ok': False, 'error': '演示模式不会执行真实替换'}, HTTPStatus.CONFLICT)
            return
        if not self.server.operation_lock.acquire(blocking=False):
            self._json({'ok': False, 'error': '已有操作正在进行，请稍候'}, HTTPStatus.CONFLICT)
            return

        try:
            if self.server.demo:
                logs = [
                    '预览模式，不会写入文件',
                    f'Base URL：{base_url}',
                    f'API Key：{core.mask(new_key)}',
                    '',
                    *[f'【{core.TARGET_META[item][0]}】\n  将更新明确的地址与密钥字段' for item in target_ids],
                    '',
                    f'预览完成：{len(target_ids)} 个工具',
                ]
                result = {
                    'applied': False,
                    'vscode_running': False,
                    'backup_dir': None,
                    'changes': [
                        {
                            'targetId': item,
                            'target': core.TARGET_META[item][0],
                            'file': core.TARGET_META[item][1],
                            'summary': 'Base URL / API Key',
                        }
                        for item in target_ids
                    ],
                }
            else:
                logs = []
                result = core.run_rotation(
                    base_url,
                    new_key,
                    target_ids,
                    apply=apply,
                    log=logs.append,
                )
            payload = {
                'ok': True,
                'applied': result['applied'],
                'vscodeRunning': result['vscode_running'],
                'backupDirectory': result['backup_dir'],
                'changes': result.get('changes', []),
                'logs': [safe_text(line) for line in logs],
            }
            if not apply:
                payload['previewToken'] = self.server.make_preview_token(base_url, new_key, target_ids)
            self._json(payload)
        except core.RotationError as exc:
            self._json({'ok': False, 'error': safe_text(exc)}, HTTPStatus.CONFLICT)
        except Exception as exc:
            self._json({'ok': False, 'error': safe_text(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        finally:
            self.server.operation_lock.release()

    def _read_json(self) -> dict:
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise ValueError('请求长度无效') from exc
        if size <= 0 or size > MAX_BODY:
            raise ValueError('请求内容为空或过大')
        try:
            return json.loads(self.rfile.read(size).decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError('请求内容不是有效 JSON') from exc

    def _json(self, data: dict, status=HTTPStatus.OK):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def app_browser_path() -> Path | None:
    candidates = [
        Path(os.environ.get('PROGRAMFILES(X86)', '')) / 'Microsoft/Edge/Application/msedge.exe',
        Path(os.environ.get('PROGRAMFILES', '')) / 'Microsoft/Edge/Application/msedge.exe',
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Microsoft/Edge/Application/msedge.exe',
        Path(os.environ.get('PROGRAMFILES', '')) / 'Google/Chrome/Application/chrome.exe',
        Path(os.environ.get('PROGRAMFILES(X86)', '')) / 'Google/Chrome/Application/chrome.exe',
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Google/Chrome/Application/chrome.exe',
    ]
    return next((path for path in candidates if path.is_file()), None)


def launch_app_window(url: str):
    browser = app_browser_path()
    if browser:
        try:
            return subprocess.Popen([
                str(browser),
                f'--app={url}',
                '--no-first-run',
                '--disable-features=msEdgeSidebarV2',
                '--window-size=1220,840',
            ])
        except OSError:
            pass
    webbrowser.open(url, new=1)
    return None


def idle_watchdog(server: AppServer):
    while True:
        time.sleep(30)
        if time.monotonic() - server.last_request_at > IDLE_SHUTDOWN_SECONDS:
            server.shutdown()
            return


def smoke_test():
    server = AppServer(('127.0.0.1', 0), RequestHandler, demo=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    with urlopen(f'http://127.0.0.1:{port}/health', timeout=5) as response:
        assert json.loads(response.read())['ok'] is True
    with urlopen(f'http://127.0.0.1:{port}/', timeout=5) as response:
        page = response.read()
        assert 'Key Router'.encode() in page
        assert b'data-theme-choice="system"' in page
    with urlopen(f'http://127.0.0.1:{port}/api/session', timeout=5) as response:
        session = json.loads(response.read())
    preview_request = Request(
        f'http://127.0.0.1:{port}/api/preview',
        data=json.dumps({
            'baseUrl': 'https://api.example.com/v1',
            'newKey': 'demo-smokeTest1234567890TAIL',
            'targetIds': ['hermes', 'claude', 'pi'],
        }).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'X-Key-Rotator-Token': session['token'],
        },
        method='POST',
    )
    with urlopen(preview_request, timeout=5) as response:
        preview = json.loads(response.read())
        assert preview['ok'] is True and preview['previewToken']
    server.shutdown()
    server.server_close()
    print('Web app smoke test: OK')


def main():
    parser = argparse.ArgumentParser(description='Key Router GUI')
    parser.add_argument('--demo', action='store_true', help='使用脱敏演示数据，不读取真实配置')
    parser.add_argument('--no-open', action='store_true', help='只启动本地服务，不自动打开窗口')
    parser.add_argument('--smoke-test', action='store_true', help='运行无风险冒烟测试')
    args = parser.parse_args()
    if args.smoke_test:
        smoke_test()
        return

    server = AppServer(('127.0.0.1', 0), RequestHandler, demo=args.demo)
    port = server.server_address[1]
    url = f'http://127.0.0.1:{port}/'
    threading.Thread(target=idle_watchdog, args=(server,), daemon=True).start()
    if not args.no_open:
        threading.Timer(0.35, launch_app_window, args=(url,)).start()
    print(f'Key Router: {url}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
