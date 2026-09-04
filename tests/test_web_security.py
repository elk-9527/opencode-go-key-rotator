from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import web_app


class WebSecurityTest(unittest.TestCase):
    def setUp(self):
        self.server = web_app.AppServer(("127.0.0.1", 0), web_app.RequestHandler, demo=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        host: str | None = None,
        token: str | None = None,
        origin: str | None = None,
        content_type: str = "application/json",
        content_length: int | None = None,
        extra_headers: dict[str, str] | None = None,
        include_access: bool = True,
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.putrequest(method, path, skip_host=True)
        connection.putheader("Host", host or f"127.0.0.1:{self.port}")
        if include_access:
            connection.putheader("X-Key-Rotator-Access", self.server.access_token)
        if body is not None:
            connection.putheader("Content-Type", content_type)
            connection.putheader("Content-Length", str(content_length if content_length is not None else len(body)))
        if token is not None:
            connection.putheader("X-Key-Rotator-Token", token)
        if origin is not None:
            connection.putheader("Origin", origin)
        for name, value in (extra_headers or {}).items():
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        status = response.status
        connection.close()
        return status, payload

    def session_token(self) -> str:
        status, payload = self.request("GET", "/api/session")
        self.assertEqual(status, 200)
        return payload["token"]

    def preview_body(self) -> bytes:
        return json.dumps(
            {
                "baseUrl": "https://api.example.com/v1",
                "newKey": "demo-token-1234",
                "targetIds": ["hermes"],
                "targetOptions": {},
            }
        ).encode("utf-8")

    def test_rejects_dns_rebinding_host_without_disclosing_session(self):
        status, payload = self.request("GET", "/api/session", host=f"attacker.example:{self.port}")
        self.assertEqual(status, 403)
        self.assertNotIn("token", payload)

    def test_safe_text_masks_common_non_sk_credential_formats(self):
        rendered = web_app.safe_text(
            "Authorization: Bearer abcdefghijklmnop token=plain-secret-value api_key: another-secret-value"
        )
        self.assertNotIn("abcdefghijklmnop", rendered)
        self.assertNotIn("plain-secret-value", rendered)
        self.assertNotIn("another-secret-value", rendered)
        self.assertIn("Bearer", rendered)

    def test_session_requires_launcher_access_token(self):
        status, payload = self.request("GET", "/api/session", include_access=False)
        self.assertEqual(status, 403)
        self.assertNotIn("token", payload)

    def test_single_instance_lock_rejects_second_process_handle(self):
        with tempfile.TemporaryDirectory(prefix="key-router-lock-test-") as root:
            path = Path(root) / "key-router.lock"
            first = web_app.SingleInstanceLock(path)
            second = web_app.SingleInstanceLock(path)
            self.assertTrue(first.acquire())
            try:
                self.assertFalse(second.acquire())
            finally:
                first.release()
            self.assertTrue(second.acquire())
            second.release()

    def test_shutdown_waits_only_for_active_mutating_operation(self):
        self.assertTrue(self.server.daemon_threads)
        started, reason = self.server.try_begin_operation()
        self.assertTrue(started, reason)
        waiter = threading.Thread(target=self.server.wait_for_operations)
        waiter.start()
        time.sleep(0.05)
        self.assertTrue(waiter.is_alive())
        self.server.finish_operation()
        waiter.join(timeout=2)
        self.assertFalse(waiter.is_alive())
        started, reason = self.server.try_begin_operation()
        self.assertFalse(started)
        self.assertIn("正在关闭", reason)

    def test_post_requires_same_origin_session_token_and_json_object(self):
        token = self.session_token()
        body = self.preview_body()

        status, _payload = self.request("POST", "/api/preview", body=body)
        self.assertEqual(status, 403)

        status, _payload = self.request(
            "POST",
            "/api/preview",
            body=body,
            token=token,
            origin=f"http://attacker.example:{self.port}",
        )
        self.assertEqual(status, 403)

        status, _payload = self.request(
            "POST",
            "/api/preview",
            body=body,
            token=token,
            content_type="text/plain",
        )
        self.assertEqual(status, 400)

        status, _payload = self.request(
            "POST",
            "/api/preview",
            body=b"[]",
            token=token,
        )
        self.assertEqual(status, 400)

    def test_legacy_extension_install_endpoint_is_not_exposed(self):
        status, payload = self.request(
            "POST",
            "/api/install-extension",
            body=json.dumps({"extensionId": "ltmoerdani.opencode-copilot-chat"}).encode("utf-8"),
            token=self.session_token(),
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "接口不存在")

    def test_install_location_tokens_are_target_bound_and_revocable(self):
        token = self.server.make_install_token("pi", r"C:\Tools\Pi")
        self.assertIsNone(self.server.consume_install_token(token, "claude"))
        self.assertEqual(self.server.consume_install_token(token, "pi"), r"C:\Tools\Pi")
        self.assertIsNone(self.server.consume_install_token(token, "pi"))

    def test_rejects_oversized_and_chunked_requests(self):
        token = self.session_token()
        status, _payload = self.request(
            "POST",
            "/api/preview",
            body=b"{}",
            token=token,
            content_length=web_app.MAX_BODY + 1,
        )
        self.assertEqual(status, 400)

        status, _payload = self.request(
            "POST",
            "/api/preview",
            body=b"{}",
            token=token,
            extra_headers={"Transfer-Encoding": "chunked"},
        )
        self.assertEqual(status, 400)

    def test_preview_token_is_bound_to_payload_and_single_use(self):
        token = self.session_token()
        body = self.preview_body()
        status, preview = self.request("POST", "/api/preview", body=body, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(preview["previewToken"])

        apply_payload = json.loads(body)
        apply_payload["previewToken"] = preview["previewToken"]
        apply_body = json.dumps(apply_payload).encode("utf-8")
        first_status, _first = self.request("POST", "/api/apply", body=apply_body, token=token)
        self.assertEqual(first_status, 409)
        second_status, second = self.request("POST", "/api/apply", body=apply_body, token=token)
        self.assertEqual(second_status, 409)
        self.assertIn("过期", second["error"])

        status, preview = self.request("POST", "/api/preview", body=body, token=token)
        self.assertEqual(status, 200)
        changed = json.loads(body)
        changed["newKey"] = "different-token-1234"
        changed["previewToken"] = preview["previewToken"]
        changed_body = json.dumps(changed).encode("utf-8")
        status, payload = self.request("POST", "/api/apply", body=changed_body, token=token)
        self.assertEqual(status, 409)
        self.assertIn("变化", payload["error"])

    def test_preview_token_limit_evicts_oldest_by_creation_time(self):
        now = time.monotonic()
        self.server.preview_tokens = {
            "old-token": ("digest-old", "z-plan", now - 2),
            "new-token": ("digest-new", "a-plan", now - 1),
        }
        with mock.patch.object(web_app, "MAX_PREVIEW_TOKENS", 2):
            self.server.make_preview_token("https://api.example.com/v1", "demo-token-1234", ["hermes"], {}, "m-plan")
        self.assertNotIn("old-token", self.server.preview_tokens)
        self.assertIn("new-token", self.server.preview_tokens)

    def test_detect_options_returns_json_error_for_invalid_body(self):
        status, payload = self.request(
            "POST",
            "/api/detect-options",
            body=b"not-json",
            token=self.session_token(),
        )
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])

    def test_browser_discovery_never_uses_relative_environment_fallback(self):
        with tempfile.TemporaryDirectory(prefix="key-router-browser-path-") as root:
            fake = Path(root) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            fake.parent.mkdir(parents=True)
            fake.write_bytes(b"not an executable")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.dict(
                    os.environ,
                    {"PROGRAMFILES(X86)": "", "PROGRAMFILES": "", "LOCALAPPDATA": ""},
                ):
                    self.assertIsNone(web_app.app_browser_path())
            finally:
                os.chdir(previous)

    def test_packaged_entrypoint_supports_manual_backup_restore(self):
        with (
            mock.patch.object(web_app.sys, "argv", ["Key-Router.exe", "--restore-backup", r"C:\backup\one"]),
            mock.patch.object(web_app.core, "restore_backup_directory", return_value=4) as restore,
            mock.patch.object(web_app, "_report_restore_result") as report,
        ):
            self.assertEqual(web_app.main(), 0)
        restore.assert_called_once_with(r"C:\backup\one")
        report.assert_called_once_with("已从备份恢复 4 个配置位置")

    def test_packaged_entrypoint_reports_restore_failure(self):
        with (
            mock.patch.object(web_app.sys, "argv", ["Key-Router.exe", "--restore-backup", r"C:\backup\bad"]),
            mock.patch.object(
                web_app.core,
                "restore_backup_directory",
                side_effect=web_app.core.RotationError("备份清单损坏"),
            ),
            mock.patch.object(web_app, "_report_restore_result") as report,
        ):
            self.assertEqual(web_app.main(), 1)
        report.assert_called_once_with("恢复失败：备份清单损坏", error=True)


if __name__ == "__main__":
    unittest.main()
