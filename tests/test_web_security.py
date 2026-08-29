# -*- coding: utf-8 -*-
from __future__ import annotations

import http.client
import json
import threading
import unittest

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
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.putrequest(method, path, skip_host=True)
        connection.putheader("Host", host or f"127.0.0.1:{self.port}")
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
        return json.dumps({
            "baseUrl": "https://api.example.com/v1",
            "newKey": "demo-token-1234",
            "targetIds": ["hermes"],
            "targetOptions": {},
        }).encode("utf-8")

    def test_rejects_dns_rebinding_host_without_disclosing_session(self):
        status, payload = self.request("GET", "/api/session", host=f"attacker.example:{self.port}")
        self.assertEqual(status, 403)
        self.assertNotIn("token", payload)

    def test_post_requires_same_origin_session_token_and_json_object(self):
        token = self.session_token()
        body = self.preview_body()

        status, _payload = self.request("POST", "/api/preview", body=body)
        self.assertEqual(status, 403)

        status, _payload = self.request(
            "POST", "/api/preview", body=body, token=token,
            origin=f"http://attacker.example:{self.port}",
        )
        self.assertEqual(status, 403)

        status, _payload = self.request(
            "POST", "/api/preview", body=body, token=token, content_type="text/plain",
        )
        self.assertEqual(status, 400)

        status, _payload = self.request(
            "POST", "/api/preview", body=b"[]", token=token,
        )
        self.assertEqual(status, 400)

    def test_rejects_oversized_and_chunked_requests(self):
        token = self.session_token()
        status, _payload = self.request(
            "POST", "/api/preview", body=b"{}", token=token,
            content_length=web_app.MAX_BODY + 1,
        )
        self.assertEqual(status, 400)

        status, _payload = self.request(
            "POST", "/api/preview", body=b"{}", token=token,
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


if __name__ == "__main__":
    unittest.main()
