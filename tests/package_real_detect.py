# -*- coding: utf-8 -*-
"""在正常桌面用户上下文中只读验证打包 EXE 的真实发现与 SecretStorage 能力。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen


def read_json(url: str, path: str, *, token: str = "", payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Key-Rotator-Token"] = token
    request = Request(url + path.lstrip("/"), data=data, headers=headers, method="POST" if data is not None else "GET")
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read())


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("用法：python tests/package_real_detect.py dist/Key-Router.exe")
    executable = Path(sys.argv[1]).resolve()
    if not executable.is_file():
        raise SystemExit("没有找到待测 EXE")

    with tempfile.TemporaryDirectory(prefix="key-router-real-detect-") as temp:
        port_file = Path(temp) / "server.port"
        environment = os.environ.copy()
        environment["RK_PORT_FILE"] = str(port_file)
        process = subprocess.Popen(
            [str(executable), "--no-open"],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not port_file.is_file():
                if process.poll() is not None:
                    raise RuntimeError(f"打包程序提前退出：{process.returncode}")
                time.sleep(0.1)
            if not port_file.is_file():
                raise RuntimeError("打包程序没有报告本地服务端口")

            url = f"http://127.0.0.1:{int(port_file.read_text(encoding='utf-8'))}/"
            session = read_json(url, "/api/session")
            detected = read_json(url, "/api/detect")
            rows = detected.get("items", [])
            summary = [
                {
                    "id": item.get("id"),
                    "badge": item.get("badge"),
                    "selectable": item.get("selectable"),
                    "detail": item.get("detail"),
                    "location": item.get("location"),
                }
                for item in rows
            ]
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            dsh = next(item for item in rows if item.get("id") == "dsh")
            if not dsh.get("selectable") or not dsh.get("candidates"):
                raise RuntimeError("真实 DSH 配置未被识别为可写")
            for target_id in ("vscode", "opencode_copilot", "deepseek_copilot", "mimo_copilot"):
                item = next(row for row in rows if row.get("id") == target_id)
                if item.get("extension") and not item["extension"].get("installed"):
                    continue
                if not item.get("selectable"):
                    raise RuntimeError(f"真实 {target_id} SecretStorage 不可写：{item.get('detail')}")
            read_json(url, "/api/shutdown", token=session["token"], payload={})
            process.wait(timeout=15)
            print("Packaged real detect: OK")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


if __name__ == "__main__":
    main()
