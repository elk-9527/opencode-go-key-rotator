"""用完全合成的配置验证六个适配器、备份、回滚和脱敏。"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import rotate_keys as core

OLD_URL = "https://old.example.com/v1"
NEW_URL = "https://gateway.example.com/v1"
OLD_KEY = "old-demo-key-1234567890-TAIL"
NEW_KEY = "new-demo-token-9876543210-TAIL"
OTHER_KEY = "keep-this-unrelated-secret"
OTHER_SECRET = "secret://chat.lm.secret.unrelated"
CONTINUE_OPTIONS = {"continue": {"modelIndex": "0"}}


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
        self.pi_env_patcher = mock.patch.dict(
            os.environ,
            {name: "" for name in set(core.PI_PROVIDER_ENV.values())},
        )
        self.pi_env_patcher.start()
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
            "PI_AUTH": self.root / "pi" / "auth.json",
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
        self.pi_env_patcher.stop()
        self.temp.cleanup()

    def _write(self, name: str, text: str):
        path = self.paths[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _create_fixture(self):
        for metadata in core.EXTENSION_META.values():
            directory = self.paths["VSCODE_EXTENSIONS_DIR"] / f"{metadata['id'].lower()}-1.0.0"
            directory.mkdir(parents=True)
            publisher, name = metadata["id"].split(".", 1)
            (directory / "package.json").write_text(
                json.dumps({"publisher": publisher, "name": name, "version": "1.0.0"}), encoding="utf-8"
            )
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
            json.dumps(
                {
                    "env": {
                        "ANTHROPIC_BASE_URL": OLD_URL,
                        "ANTHROPIC_AUTH_TOKEN": OLD_KEY,
                        "KEEP_ME": "yes",
                    },
                    "theme": "dark",
                }
            ),
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
        self.assertTrue(all(item["selectable"] for item in items if item["id"] != "continue"))
        rendered = json.dumps(items, ensure_ascii=False)
        self.assertNotIn(OLD_KEY, rendered)
        self.assertIn("Claude Code", rendered)
        self.assertIn("Pi", rendered)
        self.assertIn("ltmoerdani.opencode-copilot-chat", rendered)
        indexed = {item["id"]: item for item in items}
        self.assertFalse(indexed["continue"]["selectable"])
        self.assertEqual(indexed["continue"]["badge"], "需选择")
        self.assertEqual(len(indexed["continue"]["providers"]), 2)
        self.assertEqual(indexed["pi"]["installer"]["identity"], "earendil-works/pi")
        self.assertEqual(indexed["continue"]["installer"]["kind"], "extension")
        self.assertEqual(indexed["claude"]["installer"]["pathMode"], "fixed")

    def test_dry_run_is_read_only_and_logs_are_masked(self):
        tracked = list(self.paths.values())
        before = {path: file_hash(path) for path in tracked}
        logs = []
        result = core.run_rotation(
            NEW_URL,
            NEW_KEY,
            list(core.TARGET_ORDER),
            apply=False,
            target_options=CONTINUE_OPTIONS,
            log=logs.append,
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
            NEW_URL,
            NEW_KEY,
            list(core.TARGET_ORDER),
            apply=True,
            target_options=CONTINUE_OPTIONS,
            log=lambda _line: None,
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
        self.assertTrue(all(row.get("protection") == "windows-dpapi-v1" for row in manifest if row["existed"]))
        for backup_file in Path(result["backup_dir"]).iterdir():
            if backup_file.name not in {"manifest.json", core.BACKUP_MANIFEST}:
                self.assertNotIn(OLD_KEY.encode("utf-8"), backup_file.read_bytes())

    def test_manual_restore_uses_protected_manifest_and_restores_original_files(self):
        original_env = self.paths["HERMES_ENV"].read_bytes()
        self.assertFalse(self.paths["HERMES_CONFIG"].exists())
        result = core.run_rotation(NEW_URL, NEW_KEY, ["hermes"], apply=True, log=None)
        backup_dir = Path(result["backup_dir"])
        self.assertTrue((backup_dir / core.BACKUP_MANIFEST).is_file())

        public_manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
        public_manifest[0]["path"] = str(self.root / "must-not-be-written.txt")
        (backup_dir / "manifest.json").write_text(json.dumps(public_manifest), encoding="utf-8")
        self.paths["HERMES_ENV"].write_text("corrupted=yes\n", encoding="utf-8")
        self.paths["HERMES_CONFIG"].write_text("corrupted: yes\n", encoding="utf-8")

        restored = core.restore_backup_directory(str(backup_dir))
        self.assertEqual(restored, 2)
        self.assertEqual(self.paths["HERMES_ENV"].read_bytes(), original_env)
        self.assertFalse(self.paths["HERMES_CONFIG"].exists())
        self.assertFalse((self.root / "must-not-be-written.txt").exists())

    def test_manual_restore_rejects_directory_outside_backup_root(self):
        self.paths["BACKUP_DIR"].mkdir(parents=True)
        with self.assertRaisesRegex(core.RotationError, "只能恢复"):
            core.restore_backup_directory(str(self.root))

    def test_failed_apply_restores_original_files(self):
        tracked = [
            self.paths["HERMES_ENV"],
            self.paths["HERMES_CONFIG"],
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

    def test_post_write_verification_detects_silent_failure_and_restores(self):
        before_env = self.paths["HERMES_ENV"].read_bytes()
        before_config = file_hash(self.paths["HERMES_CONFIG"])
        original_apply = core.Change.apply

        def silently_skip_env(change):
            if change.target_id == "hermes" and change.summary == "OPENAI_API_KEY":
                return
            original_apply(change)

        core.Change.apply = silently_skip_env
        try:
            with self.assertRaises(core.RotationError):
                core.run_rotation(NEW_URL, NEW_KEY, ["hermes"], apply=True, log=None)
        finally:
            core.Change.apply = original_apply
        self.assertEqual(self.paths["HERMES_ENV"].read_bytes(), before_env)
        self.assertEqual(file_hash(self.paths["HERMES_CONFIG"]), before_config)

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
        result = core.run_rotation(NEW_URL, NEW_KEY, ["dsh"], target_options=options, apply=False, log=None)
        self.assertTrue(all(change["path"].startswith(str(manual.parent)) for change in result["changes"]))
        self.assertNotIn(NEW_URL, manual.read_text(encoding="utf-8"))

    def test_missing_extension_exposes_identity_and_install_is_whitelisted(self):
        missing_id = core.EXTENSION_META["opencode_copilot"]["id"].lower()
        for directory in self.paths["VSCODE_EXTENSIONS_DIR"].iterdir():
            if directory.name.lower().startswith(missing_id + "-"):
                shutil.rmtree(directory)
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
        shutil.rmtree(standard)
        custom = self.root / "portable-code" / "extensions"
        custom_extension = custom / f"{metadata['id'].lower()}-2.0.0"
        custom_extension.mkdir(parents=True)
        publisher, name = metadata["id"].split(".", 1)
        (custom_extension / "package.json").write_text(
            json.dumps({"publisher": publisher, "name": name, "version": "2.0.0"}), encoding="utf-8"
        )
        instances = [
            {
                "path": str(self.root / "Code.exe"),
                "arguments": f'--extensions-dir="{custom}"',
                "workingDirectory": str(self.root),
            }
        ]
        installed = core.installed_vscode_extensions(instances, query_cli=False)
        self.assertEqual(installed[metadata["id"].lower()], "2.0.0")

    def test_vscode_discovery_never_executes_unrelated_shortcut_target(self):
        unrelated = self.root / "malicious-helper.exe"
        unrelated.write_bytes(b"fixture")
        shortcut = {
            "path": str(unrelated),
            "source": "开始菜单快捷方式",
            "arguments": "",
            "workingDirectory": str(self.root),
        }
        with (
            mock.patch.object(core, "_command_discovery", return_value=[]),
            mock.patch.object(core, "_registry_app_paths", return_value=[]),
            mock.patch.object(core, "_shortcut_targets", return_value=[shortcut]),
        ):
            discovered = core.discover_vscode_installations()
        self.assertNotIn(str(unrelated), {item["path"] for item in discovered})

    def test_extension_install_is_bound_to_confirmed_extension_directory(self):
        metadata = core.EXTENSION_META["opencode_copilot"]
        custom = self.root / "portable-code" / "extensions"
        instances = [
            {
                "path": str(self.root / "portable-code" / "Code.exe"),
                "cli": str(self.root / "portable-code" / "bin" / "code.cmd"),
                "arguments": f'--extensions-dir="{custom}"',
                "workingDirectory": str(self.root),
            }
        ]

        def fake_run(command, **_kwargs):
            self.assertIn(f"--extensions-dir={custom.resolve()}", command)
            installed = custom / f"{metadata['id'].lower()}-3.0.0"
            installed.mkdir(parents=True)
            publisher, name = metadata["id"].split(".", 1)
            (installed / "package.json").write_text(
                json.dumps({"publisher": publisher, "name": name, "version": "3.0.0"}),
                encoding="utf-8",
            )
            return mock.Mock(returncode=0, stdout="installed", stderr="")

        with (
            mock.patch.object(core, "discover_vscode_installations", return_value=instances),
            mock.patch.object(core.subprocess, "run", side_effect=fake_run) as runner,
        ):
            installed = core.install_vscode_extension(metadata["id"], str(custom))
        self.assertEqual(installed["version"], "3.0.0")
        runner.assert_called_once()

    def test_extension_install_rejects_unconfirmed_directory(self):
        metadata = core.EXTENSION_META["opencode_copilot"]
        instances = [{"path": str(self.root / "Code.exe"), "arguments": "", "workingDirectory": str(self.root)}]
        with (
            mock.patch.object(core, "discover_vscode_installations", return_value=instances),
            mock.patch.object(core.subprocess, "run") as runner,
            self.assertRaisesRegex(core.RotationError, "重新确认"),
        ):
            core.install_vscode_extension(metadata["id"], str(self.root / "untrusted-extensions"))
        runner.assert_not_called()

    def test_forged_extension_folder_name_is_not_treated_as_installed(self):
        metadata = core.EXTENSION_META["opencode_copilot"]
        for directory in self.paths["VSCODE_EXTENSIONS_DIR"].iterdir():
            if directory.name.lower().startswith(metadata["id"].lower() + "-"):
                shutil.rmtree(directory)
        forged = self.paths["VSCODE_EXTENSIONS_DIR"] / f"{metadata['id'].lower()}-99.0.0"
        forged.mkdir(parents=True)
        (forged / "package.json").write_text(
            json.dumps({"publisher": "attacker", "name": "lookalike", "version": "99.0.0"}), encoding="utf-8"
        )
        installed = core.installed_vscode_extensions([], query_cli=False)
        self.assertNotIn(metadata["id"].lower(), installed)

    def test_custom_vscode_user_data_directory_is_selected_and_written(self):
        custom_root = self.root / "portable-code" / "data"
        custom_paths = core._vscode_profile_paths(custom_root)
        for path in custom_paths.values():
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.paths["VSCODE_STATE_DB"], custom_paths["stateDb"])
        shutil.copy2(self.paths["VSCODE_LOCAL_STATE"], custom_paths["localState"])
        shutil.copy2(self.paths["VSCODE_USER_SETTINGS"], custom_paths["settings"])
        shutil.copy2(self.paths["CHAT_LM_JSON"], custom_paths["chatModels"])
        instances = [
            {
                "path": str(self.root / "portable-code" / "Code.exe"),
                "arguments": f'--user-data-dir="{custom_root}"',
                "workingDirectory": str(self.root),
                "source": "测试快捷方式",
            }
        ]
        original_discovery = core.discover_vscode_installations
        core.discover_vscode_installations = lambda: instances
        try:
            state = core._state(
                "deepseek_copilot",
                extension_versions={core.EXTENSION_META["deepseek_copilot"]["id"].lower(): "1.0.0"},
                vscode_instances=instances,
            )
            self.assertFalse(state.selectable)
            self.assertEqual(state.badge, "需选择")
            default_before = self.paths["VSCODE_USER_SETTINGS"].read_bytes()
            core.run_rotation(
                NEW_URL,
                NEW_KEY,
                ["deepseek_copilot"],
                apply=True,
                target_options={"deepseek_copilot": {"userDataDir": str(custom_root)}},
                log=None,
            )
        finally:
            core.discover_vscode_installations = original_discovery
        self.assertEqual(self.paths["VSCODE_USER_SETTINGS"].read_bytes(), default_before)
        custom_settings = json.loads(core._strip_jsonc(Path(custom_paths["settings"]).read_text(encoding="utf-8")))
        self.assertEqual(custom_settings["deepseek-copilot.baseUrl"], NEW_URL)
        self.assertEqual(
            core._vscode_read_secret_named(
                "deepseek-copilot.apiKey",
                custom_paths["stateDb"],
                custom_paths["localState"],
            ),
            NEW_KEY,
        )

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
            "claude",
            "Claude Code",
            str(self.paths["CLAUDE_SETTINGS"]),
            "ready",
            "可写入",
            "test",
            True,
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

    def test_pi_environment_reference_is_preserved_and_not_selectable(self):
        original = self.paths["PI_MODELS"].read_text(encoding="utf-8")
        referenced = original.replace(OLD_KEY, "$PI_GATEWAY_KEY")
        self.paths["PI_MODELS"].write_text(referenced, encoding="utf-8")

        item = core._state("pi")
        self.assertFalse(item.selectable)
        self.assertEqual(item.badge, "凭据托管")
        self.assertIn("环境变量", item.detail)
        with self.assertRaisesRegex(core.RotationError, "环境变量"):
            core._plan_pi(NEW_URL, NEW_KEY)
        self.assertEqual(self.paths["PI_MODELS"].read_text(encoding="utf-8"), referenced)

    def test_pi_command_reference_is_preserved_and_not_selectable(self):
        original = self.paths["PI_MODELS"].read_text(encoding="utf-8")
        referenced = original.replace(OLD_KEY, "!secret-tool lookup service pi")
        self.paths["PI_MODELS"].write_text(referenced, encoding="utf-8")

        item = core._state("pi")
        self.assertFalse(item.selectable)
        self.assertIn("命令", item.detail)
        with self.assertRaisesRegex(core.RotationError, "命令"):
            core._plan_pi(NEW_URL, NEW_KEY)
        self.assertEqual(self.paths["PI_MODELS"].read_text(encoding="utf-8"), referenced)

    def test_pi_auth_file_takes_precedence_and_is_not_overwritten(self):
        self._write("PI_AUTH", json.dumps({"anthropic": {"type": "oauth", "access": "private"}}))
        original_models = self.paths["PI_MODELS"].read_text(encoding="utf-8")
        original_auth = self.paths["PI_AUTH"].read_text(encoding="utf-8")

        item = core._state("pi")
        self.assertFalse(item.selectable)
        self.assertIn("auth.json", item.detail)
        with self.assertRaisesRegex(core.RotationError, "auth.json"):
            core._plan_pi(NEW_URL, NEW_KEY)
        self.assertEqual(self.paths["PI_MODELS"].read_text(encoding="utf-8"), original_models)
        self.assertEqual(self.paths["PI_AUTH"].read_text(encoding="utf-8"), original_auth)

    def test_pi_process_environment_takes_precedence(self):
        original = self.paths["PI_MODELS"].read_text(encoding="utf-8")
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "managed-elsewhere"}):
            item = core._state("pi")
            self.assertFalse(item.selectable)
            self.assertIn("ANTHROPIC_API_KEY", item.detail)
            with self.assertRaisesRegex(core.RotationError, "ANTHROPIC_API_KEY"):
                core._plan_pi(NEW_URL, NEW_KEY)
        self.assertEqual(self.paths["PI_MODELS"].read_text(encoding="utf-8"), original)

    def test_pi_escaped_prefixes_are_literals_and_can_be_rotated(self):
        for escaped in ("$$literal-dollar", "$!literal-bang"):
            with self.subTest(escaped=escaped):
                original = self.paths["PI_MODELS"].read_text(encoding="utf-8")
                self.paths["PI_MODELS"].write_text(original.replace(OLD_KEY, escaped), encoding="utf-8")
                item = core._state("pi")
                self.assertTrue(item.selectable)
                plan = core._plan_pi(NEW_URL, NEW_KEY, state=item)
                self.assertEqual(len(plan.changes), 1)
                payload = json.loads(core._strip_jsonc(plan.changes[0].after_text or ""))
                self.assertEqual(payload["providers"]["anthropic"]["apiKey"], NEW_KEY)
                self.paths["PI_MODELS"].write_text(original, encoding="utf-8")

    def test_pi_coding_agent_dir_overrides_default_paths(self):
        custom = self.root / "portable-pi"
        with mock.patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(custom)}):
            paths = core._paths()
        self.assertEqual(paths["PI_SETTINGS"], str(custom / "settings.json"))
        self.assertEqual(paths["PI_MODELS"], str(custom / "models.json"))
        self.assertEqual(paths["PI_AUTH"], str(custom / "auth.json"))

    def test_sqlite_wal_backup_is_complete_and_restore_removes_sidecars(self):
        path = self.paths["VSCODE_STATE_DB"]
        writer = sqlite3.connect(path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO ItemTable(key, value) VALUES (?, ?)", ("wal-only", "before"))
        writer.commit()
        self.assertTrue(Path(str(path) + "-wal").is_file())

        _backup_dir, mapping = core._backup([str(path)])
        encrypted = Path(mapping[str(path)]).read_bytes()
        self.assertTrue(encrypted.startswith(core.BACKUP_MAGIC))
        snapshot_path = self.root / "decrypted-snapshot.vscdb"
        snapshot_path.write_bytes(core.dpapi_decrypt(encrypted[len(core.BACKUP_MAGIC) :]))
        snapshot = sqlite3.connect(snapshot_path)
        try:
            self.assertEqual(
                snapshot.execute("SELECT value FROM ItemTable WHERE key='wal-only'").fetchone()[0], "before"
            )
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
            self.assertEqual(
                restored.execute("SELECT value FROM ItemTable WHERE key='wal-only'").fetchone()[0], "before"
            )
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
            "https://example.com:/v1",
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

    def test_jsonc_helpers_preserve_string_content_and_replace_only_effective_top_level_value(self):
        source = '{"text": "keep, } value",}\n'
        self.assertEqual(json.loads(core._strip_jsonc(source))["text"], "keep, } value")

        settings = """{
  "nested": {"demo.baseUrl": "https://inner.example/v1"},
  "demo.baseUrl": "https://stale.example/v1",
  "demo.baseUrl": null,
}
"""
        updated = core._jsonc_set_top_level(settings, "demo.baseUrl", NEW_URL)
        parsed = json.loads(core._strip_jsonc(updated))
        self.assertEqual(parsed["demo.baseUrl"], NEW_URL)
        self.assertEqual(parsed["nested"]["demo.baseUrl"], "https://inner.example/v1")

    def test_mask_does_not_reveal_most_of_short_keys(self):
        rendered = core.mask("token1234")
        self.assertNotIn("toke", rendered)
        self.assertNotIn("1234", rendered)
        self.assertIn("(9)", rendered)

    def test_console_log_survives_non_utf8_windows_output(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", write_through=True)
        try:
            with mock.patch.object(core.sys, "stdout", stream):
                core._console_log("预览完成")
            self.assertIn(b"\\u9884", raw.getvalue())
        finally:
            stream.detach()

    def test_second_identical_rotation_is_a_noop(self):
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            list(core.TARGET_ORDER),
            apply=True,
            target_options=CONTINUE_OPTIONS,
        )
        with self.assertRaisesRegex(core.RotationError, "无需修改"):
            core.run_rotation(
                NEW_URL,
                NEW_KEY,
                list(core.TARGET_ORDER),
                apply=False,
                target_options=CONTINUE_OPTIONS,
            )

    def test_continue_requires_explicit_model_selection_and_updates_only_that_model(self):
        state = core._state(
            "continue", extension_versions={core.EXTENSION_META["continue"]["id"].lower(): "1.0.0"}, vscode_instances=[]
        )
        self.assertFalse(state.selectable)
        self.assertEqual(state.badge, "需选择")
        with self.assertRaisesRegex(core.RotationError, "当前不可写入"):
            core.run_rotation(NEW_URL, NEW_KEY, ["continue"], apply=False)

        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["continue"],
            apply=True,
            target_options={"continue": {"modelIndex": "1"}},
            log=None,
        )
        text = self.paths["CONTINUE_CONFIG"].read_text(encoding="utf-8")
        self.assertIn(f"apiBase: {OLD_URL}", text)
        self.assertIn(f'apiBase: "{NEW_URL}"', text)
        self.assertIn(f"apiKey: {OLD_KEY}", text)
        self.assertIn(f'apiKey: "{NEW_KEY}"', text)

    def test_continue_ignores_nested_lists_and_nested_api_fields(self):
        self.paths["CONTINUE_CONFIG"].write_text(
            f"""name: Nested lists
models:
  - name: First
    provider: openai
    model: first
    roles:
      - chat
      - edit
    requestOptions:
      apiKey: keep-nested
    apiBase: {OLD_URL}
    apiKey: {OLD_KEY}
  - name: Second
    provider: openai
    model: second
    apiBase: https://second.example/v1
    apiKey: second-key
""",
            encoding="utf-8",
        )
        models = core._continue_models(self.paths["CONTINUE_CONFIG"].read_text(encoding="utf-8"))
        self.assertEqual([model["name"] for model in models], ["First", "Second"])
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["continue"],
            apply=True,
            target_options={"continue": {"modelIndex": "0"}},
            log=None,
        )
        updated = self.paths["CONTINUE_CONFIG"].read_text(encoding="utf-8")
        self.assertIn("apiKey: keep-nested", updated)
        self.assertIn(f'    apiKey: "{NEW_KEY}"', updated)
        self.assertIn("apiKey: second-key", updated)

    def test_continue_secret_reference_is_preserved_and_env_value_is_rotated(self):
        self.paths["CONTINUE_CONFIG"].write_text(
            """name: Secure Continue
version: 1.0.0
schema: v1
models:
  - name: Secure model
    provider: openai
    model: secure-demo
    apiBase: https://old.example.com/v1 # keep base comment
    apiKey: ${{ secrets.CONTINUE_ROTATE_KEY }} # keep key comment
""",
            encoding="utf-8",
        )
        continue_env = self.paths["CONTINUE_CONFIG"].with_name(".env")
        continue_env.write_text(f"KEEP_ME=yes\nCONTINUE_ROTATE_KEY={OLD_KEY}\n", encoding="utf-8")

        state = core._state("continue", {"modelIndex": "0"})
        self.assertTrue(state.selectable)
        self.assertEqual(state.current_key, OLD_KEY)
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["continue"],
            target_options={"continue": {"modelIndex": "0"}},
            apply=True,
            log=None,
        )

        config = self.paths["CONTINUE_CONFIG"].read_text(encoding="utf-8")
        self.assertIn("${{ secrets.CONTINUE_ROTATE_KEY }} # keep key comment", config)
        self.assertIn(f'apiBase: "{NEW_URL}" # keep base comment', config)
        self.assertNotIn(NEW_KEY, config)
        env_text = continue_env.read_text(encoding="utf-8")
        self.assertEqual(core._env_get(env_text, "CONTINUE_ROTATE_KEY"), NEW_KEY)
        self.assertIn("KEEP_ME=yes", env_text)

    def test_dotenv_duplicate_exports_are_all_rotated_and_comments_survive(self):
        original = (
            f"export OPENAI_API_KEY='{OLD_KEY}' # first definition\r\n"
            "KEEP_ME=yes\r\n"
            f"OPENAI_API_KEY={OTHER_KEY} # effective definition\r\n"
        )
        self.paths["HERMES_ENV"].write_text(original, encoding="utf-8", newline="")
        self.assertEqual(core._env_get(original, "OPENAI_API_KEY"), OTHER_KEY)

        core.run_rotation(NEW_URL, NEW_KEY, ["hermes"], apply=True, log=None)
        updated = self.paths["HERMES_ENV"].read_text(encoding="utf-8")
        self.assertEqual(updated.count(f"OPENAI_API_KEY={NEW_KEY}"), 2)
        self.assertIn("export OPENAI_API_KEY=", updated)
        self.assertIn("# first definition", updated)
        self.assertIn("# effective definition", updated)
        self.assertIn("KEEP_ME=yes", updated)
        self.assertEqual(core._env_get(updated, "OPENAI_API_KEY"), NEW_KEY)

    def test_continue_unknown_template_expression_is_not_overwritten(self):
        self.paths["CONTINUE_CONFIG"].write_text(
            """models:
  - name: External input
    provider: openai
    model: demo
    apiBase: https://old.example.com/v1
    apiKey: ${{ inputs.SECRET_NAME }}
""",
            encoding="utf-8",
        )
        before = self.paths["CONTINUE_CONFIG"].read_bytes()
        state = core._state("continue", {"modelIndex": "0"})
        self.assertFalse(state.selectable)
        self.assertIn("模板表达式", state.detail)
        with self.assertRaisesRegex(core.RotationError, "不可写入"):
            core.run_rotation(
                NEW_URL,
                NEW_KEY,
                ["continue"],
                target_options={"continue": {"modelIndex": "0"}},
                apply=True,
                log=None,
            )
        self.assertEqual(self.paths["CONTINUE_CONFIG"].read_bytes(), before)

    def test_continue_duplicate_fields_follow_last_yaml_value(self):
        self.paths["CONTINUE_CONFIG"].write_text(
            f"""models:
  - name: Duplicate fields
    provider: openai
    model: demo
    apiBase: https://ignored.example/v1
    apiBase: {OLD_URL}
    apiKey: ${{{{ secrets.IGNORED_SECRET }}}}
    apiKey: {OLD_KEY}
""",
            encoding="utf-8",
        )
        ignored_env = self.paths["CONTINUE_CONFIG"].with_name(".env")
        state = core._state("continue", {"modelIndex": "0"})
        self.assertEqual(state.current_url, OLD_URL)
        self.assertEqual(state.current_key, OLD_KEY)
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["continue"],
            target_options={"continue": {"modelIndex": "0"}},
            apply=True,
            log=None,
        )
        updated = self.paths["CONTINUE_CONFIG"].read_text(encoding="utf-8")
        self.assertIn(f'    apiBase: "{NEW_URL}"', updated)
        self.assertIn(f'    apiKey: "{NEW_KEY}"', updated)
        self.assertFalse(ignored_env.exists())

    def test_hermes_scalar_model_placeholder_is_upgraded_to_mapping(self):
        self.paths["HERMES_CONFIG"].write_text('model: "" # not configured yet\nkeep: yes\n', encoding="utf-8")
        core.run_rotation(NEW_URL, NEW_KEY, ["hermes"], apply=True, log=None)
        updated = self.paths["HERMES_CONFIG"].read_text(encoding="utf-8")
        self.assertIn("model: # not configured yet", updated)
        self.assertEqual(core._yaml_get(updated, ("model", "provider")), "custom")
        self.assertEqual(core._yaml_get(updated, ("model", "base_url")), NEW_URL)
        self.assertEqual(core._yaml_get(updated, ("keep",)), "yes")

    def test_new_dsh_credentials_use_current_versioned_document(self):
        self.paths["DSH_CREDENTIALS"].unlink()
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["dsh"],
            apply=True,
            target_options={"dsh": {"settingsPath": str(self.paths["DSH_SETTINGS"]), "provider": "opencode-go"}},
            log=None,
        )
        credentials = self.paths["DSH_CREDENTIALS"].read_text(encoding="utf-8")
        self.assertEqual(core._yaml_get(credentials, ("version",)), "1")
        self.assertEqual(core._yaml_get(credentials, ("refs", "DEEPSEEK_API_KEY")), NEW_KEY)

    def test_dsh_environment_override_is_reported_instead_of_writing_ineffective_credentials(self):
        settings_text = self.paths["DSH_SETTINGS"].read_text(encoding="utf-8")
        settings_text = settings_text.replace(
            "agent-default-model:\n",
            "    alternate:\n"
            "      apiKeyEnv: ALTERNATE_API_KEY\n"
            "      baseURL: https://alternate.example/v1\n"
            "agent-default-model:\n",
        )
        self.paths["DSH_SETTINGS"].write_text(settings_text, encoding="utf-8")
        before_settings = self.paths["DSH_SETTINGS"].read_bytes()
        before_credentials = self.paths["DSH_CREDENTIALS"].read_bytes()
        with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": OLD_KEY}):
            options = {"dsh": {"settingsPath": str(self.paths["DSH_SETTINGS"])}}
            state = core._state("dsh", options["dsh"])
            self.assertFalse(state.selectable)
            self.assertEqual(state.selected_provider, "opencode-go")
            self.assertIn("环境变量", state.detail)
            with self.assertRaisesRegex(core.RotationError, "不可写入"):
                core.run_rotation(NEW_URL, NEW_KEY, ["dsh"], target_options=options, apply=True, log=None)
        self.assertEqual(self.paths["DSH_SETTINGS"].read_bytes(), before_settings)
        self.assertEqual(self.paths["DSH_CREDENTIALS"].read_bytes(), before_credentials)

    def test_legacy_dsh_flat_credentials_remain_migratable(self):
        self.paths["DSH_CREDENTIALS"].write_text(f"DEEPSEEK_API_KEY: {OLD_KEY}\n", encoding="utf-8")
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["dsh"],
            apply=True,
            target_options={"dsh": {"settingsPath": str(self.paths["DSH_SETTINGS"]), "provider": "opencode-go"}},
            log=None,
        )
        credentials = self.paths["DSH_CREDENTIALS"].read_text(encoding="utf-8")
        self.assertNotIn("refs:", credentials)
        self.assertEqual(core._yaml_get(credentials, ("DEEPSEEK_API_KEY",)), NEW_KEY)

    def test_opencode_vendor_selection_supports_zen_and_respects_byok_authority(self):
        zen_options = {"opencode_copilot": {"vendor": "opencodezen"}}
        core.run_rotation(
            NEW_URL,
            NEW_KEY,
            ["opencode_copilot"],
            apply=True,
            target_options=zen_options,
            log=None,
        )
        settings = json.loads(core._strip_jsonc(self.paths["VSCODE_USER_SETTINGS"].read_text(encoding="utf-8")))
        self.assertEqual(settings["opencodezen.apiBaseUrl"], NEW_URL)
        self.assertEqual(self._decrypt("secret://opencodezen.apiKey"), NEW_KEY)
        self.assertEqual(settings["opencodego.apiBaseUrl"], OLD_URL)

        database = sqlite3.connect(self.paths["VSCODE_STATE_DB"])
        try:
            database.execute(
                "INSERT OR REPLACE INTO ItemTable(key, value) VALUES (?, ?)",
                (
                    core.EXTENSION_META["opencode_copilot"]["id"],
                    json.dumps({"opencode.byokGroup.v1.opencodego": True}),
                ),
            )
            database.commit()
        finally:
            database.close()
        state = core._state("opencode_copilot", {"vendor": "opencodego"})
        self.assertFalse(state.selectable)
        self.assertEqual(state.state, "byok-managed")
        self.assertEqual(state.badge, "由 VS Code 管理")

    def test_apply_rejects_when_configuration_changed_after_preview(self):
        preview = core.run_rotation(NEW_URL, NEW_KEY, ["hermes"], apply=False)
        with self.paths["HERMES_ENV"].open("a", encoding="utf-8") as file:
            file.write("CHANGED_AFTER_PREVIEW=yes\n")
        with self.assertRaisesRegex(core.RotationError, "预览后发生变化"):
            core.run_rotation(
                NEW_URL,
                NEW_KEY,
                ["hermes"],
                apply=True,
                expected_plan_digest=preview["plan_digest"],
            )
        self.assertFalse(self.paths["BACKUP_DIR"].exists())

    def test_apply_rejects_concurrent_key_router_writer_before_backup(self):
        lock = core._configuration_lock()
        self.assertTrue(lock.acquire())
        try:
            with self.assertRaisesRegex(core.RotationError, "另一个 Key Router"):
                core.run_rotation(NEW_URL, NEW_KEY, ["hermes"], apply=True, log=None)
        finally:
            lock.release()
        self.assertFalse(self.paths["BACKUP_DIR"].exists())


if __name__ == "__main__":
    unittest.main()
