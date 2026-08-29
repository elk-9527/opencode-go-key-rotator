# -*- coding: utf-8 -*-
"""用完全合成的配置验证六个适配器、备份、回滚和脱敏。"""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import rotate_keys as core


OLD_URL = "https://old.example.com/v1"
NEW_URL = "https://gateway.example.com/v1"
OLD_KEY = "old-demo-key-1234567890-TAIL"
NEW_KEY = "new-demo-token-9876543210-TAIL"
OTHER_KEY = "keep-this-unrelated-secret"
OTHER_SECRET = "secret://chat.lm.secret.unrelated"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def dpapi_encrypt(blob: bytes) -> bytes:
    source_buffer = ctypes.create_string_buffer(blob)
    source = DATA_BLOB(len(blob), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_byte)))
    output = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(output)
    ):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def encoded_secret(value: str, aes_key: bytes) -> str:
    nonce = os.urandom(12)
    blob = b"v10" + nonce + AESGCM(aes_key).encrypt(nonce, value.encode("utf-8"), None)
    return json.dumps({"type": "Buffer", "data": list(blob)})


def file_hash(path: Path) -> str:
    if not path.exists():
        return "<missing>"
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RotationFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="key-router-test-")
        self.root = Path(self.temp.name)
        self.paths = {
            "HERMES_ENV": self.root / "hermes" / ".env",
            "HERMES_CONFIG": self.root / "hermes" / "config.yaml",
            "CONTINUE_CONFIG": self.root / "continue" / "config.yaml",
            "DSH_SETTINGS": self.root / "dsh" / "settings.yaml",
            "DSH_CREDENTIALS": self.root / "dsh" / ".credentials.yaml",
            "VSCODE_STATE_DB": self.root / "vscode" / "state.vscdb",
            "VSCODE_LOCAL_STATE": self.root / "vscode" / "Local State",
            "CHAT_LM_JSON": self.root / "vscode" / "chatLanguageModels.json",
            "CLAUDE_SETTINGS": self.root / "claude" / "settings.json",
            "PI_SETTINGS": self.root / "pi" / "settings.json",
            "PI_MODELS": self.root / "pi" / "models.json",
            "BACKUP_DIR": self.root / "backups",
        }
        self.originals = {}
        for name, path in self.paths.items():
            self.originals[name] = getattr(core, name)
            setattr(core, name, str(path))
        self.originals["vscode_running"] = core.vscode_running
        core.vscode_running = lambda: False
        self._create_fixture()

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(core, name, value)
        self.temp.cleanup()

    def _write(self, name: str, text: str):
        path = self.paths[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _create_fixture(self):
        self._write("HERMES_ENV", f"OPENCODE_GO_API_KEY={OLD_KEY}\nOTHER_SETTING=keep\n")
        self._write(
            "CONTINUE_CONFIG",
            f"""name: Synthetic
models:
  - name: Current
    provider: openai
    model: current-model
    apiBase: {OLD_URL}
    apiKey: {OLD_KEY}
  - name: Untouched
    provider: other
    model: other-model
    apiBase: https://keep.example/v1
    apiKey: {OTHER_KEY}
""",
        )
        self._write(
            "DSH_SETTINGS",
            f"""llm-pi-ai:
  providers:
    opencode-go:
      apiKeyEnv: DEEPSEEK_API_KEY
      api: openai-completions
      baseURL: {OLD_URL}
      models:
        - id: demo
agent-default-model:
  provider: opencode-go
  model: demo
""",
        )
        self._write("DSH_CREDENTIALS", f"version: 1\nrefs:\n  DEEPSEEK_API_KEY: {OLD_KEY}\n")

        aes_key = os.urandom(32)
        self.aes_key = aes_key
        encrypted_key = b"DPAPI" + dpapi_encrypt(aes_key)
        self._write(
            "VSCODE_LOCAL_STATE",
            json.dumps({"os_crypt": {"encrypted_key": base64.b64encode(encrypted_key).decode("ascii")}}),
        )
        self._write(
            "CHAT_LM_JSON",
            json.dumps([{"name": "Existing", "vendor": "openai", "apiKey": "keep"}]),
        )
        db = sqlite3.connect(self.paths["VSCODE_STATE_DB"])
        try:
            db.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
            db.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (OTHER_SECRET, encoded_secret(OTHER_KEY, aes_key)),
            )
            db.commit()
        finally:
            db.close()

        self._write(
            "CLAUDE_SETTINGS",
            json.dumps({
                "env": {
                    "ANTHROPIC_BASE_URL": OLD_URL,
                    "ANTHROPIC_AUTH_TOKEN": OLD_KEY,
                    "KEEP_ME": "yes",
                },
                "theme": "dark",
            }),
        )
        self._write("PI_SETTINGS", json.dumps({"defaultProvider": "anthropic", "theme": "dark"}))
        self._write(
            "PI_MODELS",
            f"""{{
  // JSONC comments and trailing commas are accepted
  "providers": {{
    "anthropic": {{
      "baseUrl": "{OLD_URL}",
      "apiKey": "{OLD_KEY}",
      "modelOverrides": {{"demo": {{"maxTokens": 1234}}}},
    }},
  }},
}}
""",
        )

    def _decrypt(self, secret_key: str) -> str:
        db = sqlite3.connect(self.paths["VSCODE_STATE_DB"])
        try:
            row = db.execute("SELECT value FROM ItemTable WHERE key=?", (secret_key,)).fetchone()
        finally:
            db.close()
        return core.vscode_secret_decrypt(bytes(json.loads(row[0])["data"]), self.aes_key)

    def test_detection_lists_six_selectable_targets_without_raw_keys(self):
        items = core.detect_targets()
        self.assertEqual([item["id"] for item in items], list(core.TARGET_ORDER))
        self.assertTrue(all(item["selectable"] for item in items))
        rendered = json.dumps(items, ensure_ascii=False)
        self.assertNotIn(OLD_KEY, rendered)
        self.assertIn("Claude Code", rendered)
        self.assertIn("Pi", rendered)

    def test_dry_run_is_read_only_and_logs_are_masked(self):
        tracked = list(self.paths.values())
        before = {path: file_hash(path) for path in tracked}
        logs = []
        result = core.run_rotation(
            NEW_URL, NEW_KEY, list(core.TARGET_ORDER), apply=False, log=logs.append
        )
        after = {path: file_hash(path) for path in tracked}
        self.assertEqual(before, after)
        self.assertFalse(result["applied"])
        self.assertFalse(self.paths["BACKUP_DIR"].exists())
        combined = "\n".join(logs)
        self.assertNotIn(OLD_KEY, combined)
        self.assertNotIn(NEW_KEY, combined)
        self.assertIn(NEW_URL, combined)

    def test_apply_updates_all_targets_and_preserves_unrelated_values(self):
        result = core.run_rotation(
            NEW_URL, NEW_KEY, list(core.TARGET_ORDER), apply=True, log=lambda _line: None
        )
        self.assertTrue(result["applied"])
        self.assertTrue(Path(result["backup_dir"]).is_dir())

        hermes_env = self.paths["HERMES_ENV"].read_text(encoding="utf-8")
        self.assertIn(f"OPENAI_API_KEY={NEW_KEY}", hermes_env)
        self.assertIn(f"OPENCODE_GO_API_KEY={OLD_KEY}", hermes_env)
        hermes_config = self.paths["HERMES_CONFIG"].read_text(encoding="utf-8")
        self.assertIn('provider: "custom"', hermes_config)
        self.assertIn(NEW_URL, hermes_config)

        continue_text = self.paths["CONTINUE_CONFIG"].read_text(encoding="utf-8")
        self.assertIn(NEW_URL, continue_text)
        self.assertIn(NEW_KEY, continue_text)
        self.assertIn("https://keep.example/v1", continue_text)
        self.assertIn(OTHER_KEY, continue_text)

        dsh_settings = self.paths["DSH_SETTINGS"].read_text(encoding="utf-8")
        dsh_credentials = self.paths["DSH_CREDENTIALS"].read_text(encoding="utf-8")
        self.assertIn(NEW_URL, dsh_settings)
        self.assertIn(NEW_KEY, dsh_credentials)

        vscode = json.loads(self.paths["CHAT_LM_JSON"].read_text(encoding="utf-8"))
        key_router = next(item for item in vscode if item.get("name") == "Key Router")
        self.assertEqual(key_router["url"], NEW_URL)
        self.assertEqual(key_router["apiKey"], core.VSCODE_SECRET_REF)
        self.assertEqual(self._decrypt(core.VSCODE_SECRET_KEY), NEW_KEY)
        self.assertEqual(self._decrypt(OTHER_SECRET), OTHER_KEY)

        claude = json.loads(self.paths["CLAUDE_SETTINGS"].read_text(encoding="utf-8"))
        self.assertEqual(claude["env"]["ANTHROPIC_BASE_URL"], NEW_URL)
        self.assertEqual(claude["env"]["ANTHROPIC_AUTH_TOKEN"], NEW_KEY)
        self.assertEqual(claude["env"]["KEEP_ME"], "yes")

        pi = json.loads(self.paths["PI_MODELS"].read_text(encoding="utf-8"))
        self.assertEqual(pi["providers"]["anthropic"]["baseUrl"], NEW_URL)
        self.assertEqual(pi["providers"]["anthropic"]["apiKey"], NEW_KEY)
        self.assertEqual(pi["providers"]["anthropic"]["modelOverrides"]["demo"]["maxTokens"], 1234)

        manifest = json.loads((Path(result["backup_dir"]) / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(manifest), 8)

    def test_failed_apply_restores_original_files(self):
        tracked = [
            self.paths["HERMES_ENV"], self.paths["HERMES_CONFIG"],
            self.paths["CHAT_LM_JSON"], self.paths["VSCODE_STATE_DB"],
        ]
        before = {path: file_hash(path) for path in tracked}
        original_writer = core._vscode_write_secret
        core._vscode_write_secret = lambda _key: (_ for _ in ()).throw(OSError("synthetic failure"))
        try:
            with self.assertRaises(core.RotationError):
                core.run_rotation(NEW_URL, NEW_KEY, ["hermes", "vscode"], apply=True, log=None)
        finally:
            core._vscode_write_secret = original_writer
        after = {path: file_hash(path) for path in tracked}
        self.assertEqual(before, after)

    def test_validation_accepts_non_sk_key_and_blocks_unsafe_urls(self):
        self.assertEqual(core.validate_key("token-1234"), "token-1234")
        self.assertEqual(core.validate_base_url("http://127.0.0.1:11434/v1/"), "http://127.0.0.1:11434/v1")
        with self.assertRaises(core.RotationError):
            core.validate_base_url("http://remote.example.com/v1")
        with self.assertRaises(core.RotationError):
            core.validate_base_url("https://example.com/v1?token=secret")


if __name__ == "__main__":
    unittest.main()
