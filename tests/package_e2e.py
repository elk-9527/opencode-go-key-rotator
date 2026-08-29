# -*- coding: utf-8 -*-
"""对打包后的单文件 EXE 执行全目标合成写入验收。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_rotation_flow import NEW_KEY, NEW_URL, RotationFlowTest  # noqa: E402
import rotate_keys as core  # noqa: E402


def request_json(url: str, path: str, *, token: str = "", payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Key-Rotator-Token"] = token
    request = Request(url + path.lstrip("/"), data=data, headers=headers, method="POST" if data is not None else "GET")
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("用法：python tests/package_e2e.py dist/Key-Router.exe")
    executable = Path(sys.argv[1]).resolve()
    if not executable.is_file():
        raise SystemExit("没有找到待测 EXE")

    fixture = RotationFlowTest(methodName="test_apply_updates_all_targets_and_preserves_unrelated_values")
    fixture.setUp()
    process = None
    try:
        port_file = fixture.root / "server.port"
        environment = os.environ.copy()
        environment["RK_PATHS_JSON"] = json.dumps({name: str(path) for name, path in fixture.paths.items()})
        environment["RK_SKIP_VSCODE_CHECK"] = "1"
        environment["RK_PORT_FILE"] = str(port_file)
        process = subprocess.Popen(
            [str(executable), "--no-open"],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not port_file.is_file():
            if process.poll() is not None:
                raise RuntimeError(f"打包程序提前退出：{process.returncode}")
            time.sleep(0.1)
        if not port_file.is_file():
            raise RuntimeError("打包程序没有报告本地服务端口")

        url = f"http://127.0.0.1:{int(port_file.read_text(encoding='utf-8'))}/"
        session = request_json(url, "/api/session")
        detected = request_json(url, "/api/detect")
        if len(detected.get("items", [])) != len(core.TARGET_ORDER):
            raise RuntimeError("打包程序目标检测数量不正确")

        payload = {
            "baseUrl": NEW_URL,
            "newKey": NEW_KEY,
            "targetIds": list(core.TARGET_ORDER),
            "targetOptions": {},
        }
        preview = request_json(url, "/api/preview", token=session["token"], payload=payload)
        payload["previewToken"] = preview["previewToken"]
        applied = request_json(url, "/api/apply", token=session["token"], payload=payload)
        if not applied.get("applied") or len(applied.get("changes", [])) < 9:
            raise RuntimeError("打包程序没有完成全部合成写入")
        backup = Path(applied["backupDirectory"])
        if not (backup / "manifest.json").is_file():
            raise RuntimeError("打包程序没有生成备份清单")

        if NEW_URL not in fixture.paths["DSH_SETTINGS"].read_text(encoding="utf-8"):
            raise RuntimeError("DSH 地址未更新")
        if NEW_KEY not in fixture.paths["DSH_CREDENTIALS"].read_text(encoding="utf-8"):
            raise RuntimeError("DSH 密钥未更新")
        if fixture._decrypt(core.VSCODE_SECRET_KEY) != NEW_KEY:
            raise RuntimeError("VS Code SecretStorage 密钥未更新")

        request_json(url, "/api/shutdown", token=session["token"], payload={})
        process.wait(timeout=15)
        print(f"Packaged E2E: OK ({len(core.TARGET_ORDER)} targets, {len(applied['changes'])} changes)")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        fixture.tearDown()


if __name__ == "__main__":
    main()
