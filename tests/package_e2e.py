"""对打包后的单文件 EXE 执行全目标合成写入验收。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_rotation_flow import CONTINUE_OPTIONS, NEW_KEY, NEW_URL, OLD_KEY, OLD_URL, RotationFlowTest  # noqa: E402

import rotate_keys as core  # noqa: E402


def request_json(
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
    with urlopen(request, timeout=15) as response:
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
                session_token = str(request_json(url, "/api/session", access_token=access_token)["token"])
            request_json(
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
        raise SystemExit("用法：python tests/package_e2e.py dist/Key-Router.exe")
    executable = Path(sys.argv[1]).resolve()
    if not executable.is_file():
        raise SystemExit("没有找到待测 EXE")

    fixture = RotationFlowTest(methodName="test_apply_updates_all_targets_and_preserves_unrelated_values")
    fixture.setUp()
    process = None
    url = ""
    access_token = ""
    session_token = ""
    try:
        port_file = fixture.root / "server.port"
        environment = os.environ.copy()
        environment["RK_PATHS_JSON"] = json.dumps({name: str(path) for name, path in fixture.paths.items()})
        environment["RK_SKIP_VSCODE_CHECK"] = "1"
        environment["RK_PORT_FILE"] = str(port_file)
        environment["RK_NO_MESSAGE_BOX"] = "1"
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

        server_info = json.loads(port_file.read_text(encoding="utf-8"))
        url = f"http://127.0.0.1:{int(server_info['port'])}/"
        access_token = str(server_info["accessToken"])
        session = request_json(url, "/api/session", access_token=access_token)
        session_token = str(session["token"])
        detected = request_json(url, "/api/detect", access_token=access_token)
        if len(detected.get("items", [])) != len(core.TARGET_ORDER):
            raise RuntimeError("打包程序目标检测数量不正确")

        payload = {
            "baseUrl": NEW_URL,
            "newKey": NEW_KEY,
            "targetIds": list(core.TARGET_ORDER),
            "targetOptions": CONTINUE_OPTIONS,
        }
        preview = request_json(
            url,
            "/api/preview",
            access_token=access_token,
            token=session_token,
            payload=payload,
        )
        payload["previewToken"] = preview["previewToken"]
        applied = request_json(
            url,
            "/api/apply",
            access_token=access_token,
            token=session_token,
            payload=payload,
        )
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

        request_json(
            url,
            "/api/shutdown",
            access_token=access_token,
            token=session_token,
            payload={},
        )
        process.wait(timeout=15)
        restored = subprocess.run(
            [str(executable), "--restore-backup", str(backup)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if restored.returncode != 0:
            raise RuntimeError(f"打包程序无法恢复备份：{restored.returncode}")
        if OLD_URL not in fixture.paths["DSH_SETTINGS"].read_text(encoding="utf-8"):
            raise RuntimeError("打包恢复没有还原 DSH 地址")
        if OLD_KEY not in fixture.paths["DSH_CREDENTIALS"].read_text(encoding="utf-8"):
            raise RuntimeError("打包恢复没有还原 DSH 密钥")
        if core._vscode_read_secret() is not None:
            raise RuntimeError("打包恢复没有移除原本不存在的 VS Code 自定义端点密钥")
        restored_secret_id = core.VSCODE_PLUGIN_CONFIG["deepseek_copilot"][1]
        if fixture._decrypt(f"secret://{restored_secret_id}") != OLD_KEY:
            raise RuntimeError("打包恢复没有还原原有 VS Code 扩展密钥")
        print(
            f"Packaged E2E: OK ({len(core.TARGET_ORDER)} targets, "
            f"{len(applied['changes'])} changes, protected restore)"
        )
    finally:
        if process is not None:
            stop_packaged_process(
                process,
                url=url,
                access_token=access_token,
                session_token=session_token,
            )
        fixture.tearDown()


if __name__ == "__main__":
    main()
