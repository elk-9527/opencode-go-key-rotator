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
    if path.is_dir():
        listing = "\n".join(sorted(str(item.relative_to(path)) for item in path.rglob("*")))
        return "<dir>" + hashlib.sha256(listing.encode("utf-8")).hexdigest()
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
            "VSCODE_USER_SETTINGS": self.root / "vscode" / "settings.json",
            "VSCODE_EXTENSIONS_DIR": self.root / "vscode" / "extensions",
            "CHAT_LM_JSON": self.root / "vscode" / "chatLanguageModels.json",
            "CLAUDE_SETTINGS": self.root / "claude" / "settings.json",
            "PI_SETTINGS": self.root / "pi" / "settings.json",
            "PI_MODELS": self.root / "pi" / "models.json",
            "BACKUP_DIR": self.root / "backups",
            "APP_SETTINGS": self.root / "app-settings.json",
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
        for metadata in core.EXTENSION_META.values():
            (self.paths["VSCODE_EXTENSIONS_DIR"] / f"{metadata['id'].lower()}-1.0.0").mkdir(parents=True)
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
        self._write(
            "VSCODE_USER_SETTINGS",
            f"""{{
  // comments must survive
  "opencodego.apiBaseUrl": "{OLD_URL}",
  "deepseek-copilot.baseUrl": "{OLD_URL}",
  "mimo-copilot.baseUrl": "{OLD_URL}",
  "editor.fontSize": 14,
}}
""",
        )
        db = sqlite3.connect(self.paths["VSCODE_STATE_DB"])
        try:
            db.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
            db.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (OTHER_SECRET, encoded_secret(OTHER_KEY, aes_key)),
            )
            for _config_key, secret_id in core.VSCODE_PLUGIN_CONFIG.values():
                db.execute(
                    "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                    (f"secret://{secret_id}", encoded_secret(OLD_KEY, aes_key)),
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

    def test_detection_lists_all_selectable_targets_without_raw_keys(self):
        items = core.detect_targets()
        self.assertEqual([item["id"] for item in items], list(core.TARGET_ORDER))
        self.assertTrue(all(item["selectable"] for item in items))
        rendered = json.dumps(items, ensure_ascii=False)
        self.assertNotIn(OLD_KEY, rendered)
        self.assertIn("Claude Code", rendered)
        self.assertIn("Pi", rendered)
        self.assertIn("ltmoerdani.opencode-copilot-chat", rendered)
        indexed = {item["id"]: item for item in items}
        self.assertEqual(indexed["pi"]["installer"]["identity"], "earendil-works/pi")
        self.assertEqual(indexed["continue"]["installer"]["kind"], "extension")
        self.assertEqual(indexed["claude"]["installer"]["pathMode"], "fixed")

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

        vscode_settings_text = self.paths["VSCODE_USER_SETTINGS"].read_text(encoding="utf-8")
        self.assertIn("// comments must survive", vscode_settings_text)
        vscode_settings = json.loads(core._strip_jsonc(vscode_settings_text))
        for config_key, secret_id in core.VSCODE_PLUGIN_CONFIG.values():
            self.assertEqual(vscode_settings[config_key], NEW_URL)
            self.assertEqual(self._decrypt(f"secret://{secret_id}"), NEW_KEY)

        claude = json.loads(self.paths["CLAUDE_SETTINGS"].read_text(encoding="utf-8"))
        self.assertEqual(claude["env"]["ANTHROPIC_BASE_URL"], NEW_URL)
        self.assertEqual(claude["env"]["ANTHROPIC_AUTH_TOKEN"], NEW_KEY)
        self.assertEqual(claude["env"]["KEEP_ME"], "yes")

        pi_text = self.paths["PI_MODELS"].read_text(encoding="utf-8")
        self.assertIn("// JSONC comments and trailing commas are accepted", pi_text)
        pi = json.loads(core._strip_jsonc(pi_text))
        self.assertEqual(pi["providers"]["anthropic"]["baseUrl"], NEW_URL)
        self.assertEqual(pi["providers"]["anthropic"]["apiKey"], NEW_KEY)
        self.assertEqual(pi["providers"]["anthropic"]["modelOverrides"]["demo"]["maxTokens"], 1234)

        manifest = json.loads((Path(result["backup_dir"]) / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(manifest), 8)

    def test_failed_apply_restores_original_files(self):
        tracked = [
            self.paths["HERMES_ENV"], self.paths["HERMES_CONFIG"],
            self.paths["CHAT_LM_JSON"],
        ]
        before = {path: file_hash(path) for path in tracked}
        database = sqlite3.connect(self.paths["VSCODE_STATE_DB"])
        try:
            database_before = database.execute("SELECT key, value FROM ItemTable ORDER BY key").fetchall()
        finally:
            database.close()
        original_writer = core._vscode_write_secret
        core._vscode_write_secret = lambda _key: (_ for _ in ()).throw(OSError("synthetic failure"))
        try:
            with self.assertRaises(core.RotationError):
                core.run_rotation(NEW_URL, NEW_KEY, ["hermes", "vscode"], apply=True, log=None)
        finally:
            core._vscode_write_secret = original_writer
        after = {path: file_hash(path) for path in tracked}
        self.assertEqual(before, after)
        database = sqlite3.connect(self.paths["VSCODE_STATE_DB"])
        try:
            database_after = database.execute("SELECT key, value FROM ItemTable ORDER BY key").fetchall()
            self.assertEqual(database.execute("PRAGMA quick_check").fetchone()[0], "ok")
        finally:
            database.close()
        self.assertEqual(database_before, database_after)

    def test_dsh_manual_path_and_provider_are_used_without_drive_scan(self):
        manual = self.root / "portable-dsh" / "settings.yaml"
        manual.parent.mkdir(parents=True)
        manual.write_text(
            f"""llm-pi-ai:
  providers:
    route-a:
      apiKeyEnv: ROUTE_A_KEY
      baseURL: {OLD_URL}
    route-b:
      apiKeyEnv: ROUTE_B_KEY
      baseURL: https://second.example/v1
agent-default-model:
  provider: route-a
""",
            encoding="utf-8",
        )
        (manual.parent / ".credentials.yaml").write_text(
            f"refs:\n  ROUTE_A_KEY: {OLD_KEY}\n  ROUTE_B_KEY: {OTHER_KEY}\n",
            encoding="utf-8",
        )
        options = {"dsh": {"settingsPath": str(manual), "provider": "route-b"}}
        state = core._state("dsh", options["dsh"])
        self.assertTrue(state.selectable)
        self.assertEqual(state.location, str(manual))
        self.assertEqual(state.selected_provider, "route-b")
        result = core.run_rotation(
            NEW_URL, NEW_KEY, ["dsh"], target_options=options, apply=False, log=None
        )
        self.assertTrue(all(change["path"].startswith(str(manual.parent)) for change in result["changes"]))
        self.assertNotIn(NEW_URL, manual.read_text(encoding="utf-8"))

    def test_missing_extension_exposes_identity_and_install_is_whitelisted(self):
        missing_id = core.EXTENSION_META["opencode_copilot"]["id"].lower()
        for directory in self.paths["VSCODE_EXTENSIONS_DIR"].iterdir():
            if directory.name.lower().startswith(missing_id + "-"):
                directory.rmdir()
        item = next(row for row in core.detect_targets() if row["id"] == "opencode_copilot")
        self.assertFalse(item["selectable"])
        self.assertEqual(item["badge"], "未安装")
        self.assertEqual(item["extension"]["id"], "ltmoerdani.opencode-copilot-chat")
        self.assertEqual(item["extension"]["publisher"], "ltmoerdani")
        with self.assertRaises(core.RotationError):
            core.install_vscode_extension("unknown.publisher-extension")

    def test_obsolete_extension_folder_is_not_reported_as_installed(self):
        metadata = core.EXTENSION_META["opencode_copilot"]
        directory_name = f"{metadata['id'].lower()}-1.0.0"
        (self.paths["VSCODE_EXTENSIONS_DIR"] / ".obsolete").write_text(
            json.dumps({directory_name: True}), encoding="utf-8"
        )
        installed = core.installed_vscode_extensions([], query_cli=False)
        self.assertNotIn(metadata["id"].lower(), installed)

    def test_custom_vscode_extension_directory_from_shortcut_is_detected(self):
        metadata = core.EXTENSION_META["opencode_copilot"]
        standard = self.paths["VSCODE_EXTENSIONS_DIR"] / f"{metadata['id'].lower()}-1.0.0"
        standard.rmdir()
        custom = self.root / "portable-code" / "extensions"
        (custom / f"{metadata['id'].lower()}-2.0.0").mkdir(parents=True)
        instances = [{
            "path": str(self.root / "Code.exe"),
            "arguments": f'--extensions-dir="{custom}"',
            "workingDirectory": str(self.root),
        }]
        installed = core.installed_vscode_extensions(instances, query_cli=False)
        self.assertEqual(installed[metadata["id"].lower()], "2.0.0")

    def test_vscode_secret_storage_failure_disables_writes(self):
        original = core.get_vscode_aes_key
        core.get_vscode_aes_key = lambda: (_ for _ in ()).throw(OSError("blocked"))
        try:
            item = core._state("vscode", vscode_instances=[])
        finally:
            core.get_vscode_aes_key = original
        self.assertFalse(item.selectable)
        self.assertEqual(item.badge, "不可写")
        self.assertNotIn("blocked", item.detail)

    def test_claude_new_config_uses_api_key_header_variable(self):
        self.paths["CLAUDE_SETTINGS"].unlink()
        state = core.TargetState(
            "claude", "Claude Code", str(self.paths["CLAUDE_SETTINGS"]),
            "ready", "可写入", "test", True,
        )
        plan = core._plan_claude(NEW_URL, NEW_KEY, state=state)
        self.assertEqual(len(plan.changes), 1)
        payload = json.loads(plan.changes[0].after_text)
        self.assertEqual(payload["env"]["ANTHROPIC_API_KEY"], NEW_KEY)
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", payload["env"])

    def test_pi_without_existing_provider_is_not_selectable(self):
        self.paths["PI_MODELS"].write_text('{"providers": {}}\n', encoding="utf-8")
        item = core._state("pi")
        self.assertFalse(item.selectable)
        self.assertEqual(item.badge, "需配置")

    def test_sqlite_wal_backup_is_complete_and_restore_removes_sidecars(self):
        path = self.paths["VSCODE_STATE_DB"]
        writer = sqlite3.connect(path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO ItemTable(key, value) VALUES (?, ?)", ("wal-only", "before"))
        writer.commit()
        self.assertTrue(Path(str(path) + "-wal").is_file())

        _backup_dir, mapping = core._backup([str(path)])
        snapshot = sqlite3.connect(mapping[str(path)])
        try:
            self.assertEqual(snapshot.execute("SELECT value FROM ItemTable WHERE key='wal-only'").fetchone()[0], "before")
            self.assertEqual(snapshot.execute("PRAGMA quick_check").fetchone()[0], "ok")
        finally:
            snapshot.close()

        writer.execute("UPDATE ItemTable SET value='after' WHERE key='wal-only'")
        writer.commit()
        writer.close()
        Path(str(path) + "-wal").write_bytes(b"stale-wal")
        Path(str(path) + "-shm").write_bytes(b"stale-shm")
        core._restore(mapping)

        restored = sqlite3.connect(path)
        try:
            self.assertEqual(restored.execute("SELECT value FROM ItemTable WHERE key='wal-only'").fetchone()[0], "before")
            self.assertEqual(restored.execute("PRAGMA quick_check").fetchone()[0], "ok")
        finally:
            restored.close()
        self.assertFalse(Path(str(path) + "-wal").exists())
        self.assertFalse(Path(str(path) + "-shm").exists())

    def test_validation_accepts_non_sk_key_and_blocks_unsafe_urls(self):
        self.assertEqual(core.validate_key("token-1234"), "token-1234")
        self.assertEqual(core.validate_base_url("http://127.0.0.1:11434/v1/"), "http://127.0.0.1:11434/v1")
        with self.assertRaises(core.RotationError):
            core.validate_base_url("http://remote.example.com/v1")
        with self.assertRaises(core.RotationError):
            core.validate_base_url("https://example.com/v1?token=secret")
        for unsafe in (
            "https://example.com:abc/v1",
            "https://example.com:65536/v1",
            " https://example.com/v1",
            "https://example.com/v1\r\n",
            "https://example.com\\@evil.example/v1",
        ):
            with self.subTest(unsafe=repr(unsafe)):
                with self.assertRaises(core.RotationError):
                    core.validate_base_url(unsafe)
        with self.assertRaises(core.RotationError):
            core.validate_key(" token-1234")
        settings = '{\n  "editor.fontSize": 14 // keep this comment\n}\n'
        updated = core._jsonc_set_top_level(settings, "demo.baseUrl", NEW_URL)
        self.assertEqual(json.loads(core._strip_jsonc(updated))["demo.baseUrl"], NEW_URL)
        self.assertIn("// keep this comment", updated)


if __name__ == "__main__":
    unittest.main()
