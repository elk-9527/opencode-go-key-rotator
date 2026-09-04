"""在正常桌面用户上下文中只读验证打包 EXE 的真实发现与 SecretStorage 能力。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen


def read_json(
    url: str,
    path: str,
    *,
    access_token: str,
    token: str = "",
    payload: dict | None = None,
) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Key-Rotator-Access": access_token}
    if token:
        headers["X-Key-Rotator-Token"] = token
    request = Request(url + path.lstrip("/"), data=data, headers=headers, method="POST" if data is not None else "GET")
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read())


def stop_packaged_process(
    process: subprocess.Popen,
    *,
    url: str = "",
    access_token: str = "",
    session_token: str = "",
) -> None:
    """先走应用退出接口，失败时仅清理本测试启动的进程树。"""
    if process.poll() is not None:
        return
    if url and access_token:
        try:
            if not session_token:
                session_token = str(read_json(url, "/api/session", access_token=access_token)["token"])
            read_json(
                url,
                "/api/shutdown",
                access_token=access_token,
                token=session_token,
                payload={},
            )
            process.wait(timeout=15)
            return
        except Exception:
            pass
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


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
        url = ""
        access_token = ""
        session_token = ""
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not port_file.is_file():
                if process.poll() is not None:
                    raise RuntimeError(f"打包程序提前退出：{process.returncode}")
                time.sleep(0.1)
            if not port_file.is_file():
                raise RuntimeError("打包程序没有报告本地服务端口")

            server_info = json.loads(port_file.read_text(encoding="utf-8"))
            url = f"http://127.0.0.1:{int(server_info['port'])}/"
            access_token = str(server_info["accessToken"])
            session = read_json(url, "/api/session", access_token=access_token)
            session_token = str(session["token"])
            detected = read_json(url, "/api/detect", access_token=access_token)
            rows = detected.get("items", [])
            if len(rows) != 9 or len({item.get("id") for item in rows}) != 9:
                raise RuntimeError("真实检测没有返回完整且唯一的九个目标")
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
            failed = [item for item in rows if item.get("state") == "error" or item.get("badge") == "读取失败"]
            if failed:
                raise RuntimeError("真实配置存在读取失败：" + ", ".join(str(item.get("id")) for item in failed))
            for target_id in ("vscode", "opencode_copilot", "deepseek_copilot", "mimo_copilot"):
                item = next(row for row in rows if row.get("id") == target_id)
                if item.get("extension") and not item["extension"].get("installed"):
                    continue
                if not item.get("selectable") and item.get("state") not in {
                    "managed",
                    "byok-managed",
                    "selection-required",
                }:
                    raise RuntimeError(f"真实 {target_id} SecretStorage 不可写：{item.get('detail')}")
            read_json(
                url,
                "/api/shutdown",
                access_token=access_token,
                token=session_token,
                payload={},
            )
            process.wait(timeout=15)
            print("Packaged real detect: OK")
        finally:
            stop_packaged_process(
                process,
                url=url,
                access_token=access_token,
                session_token=session_token,
            )


if __name__ == "__main__":
    main()
