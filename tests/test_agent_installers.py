from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import agent_installers as installers


class AgentInstallerTest(unittest.TestCase):
    def test_public_metadata_uses_only_whitelisted_agents(self):
        for target_id in ("hermes", "dsh", "claude", "pi"):
            metadata = installers.public_metadata(target_id, installed=False)
            self.assertEqual(metadata["targetId"], target_id)
            self.assertTrue(metadata["sourceUrl"].startswith("https://"))
            self.assertIn(metadata["pathMode"], {"select", "fixed"})
        self.assertIsNone(installers.public_metadata("unknown", installed=False))

    def test_install_location_rejects_broad_or_unrelated_nonempty_folder(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-path-") as temp_name:
            root = Path(temp_name)
            location = root / "Pi"
            location.mkdir()
            self.assertEqual(installers.validate_install_location("pi", location), location.resolve())
            (location / "foreign.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(installers.InstallerError):
                installers.validate_install_location("pi", location)
            (location / "pi.exe").write_bytes(b"fixture")
            self.assertEqual(installers.validate_install_location("pi", location), location.resolve())
            file_location = root / "PiFile"
            file_location.write_bytes(b"not a directory")
            with self.assertRaises(installers.InstallerError):
                installers.validate_install_location("pi", file_location)
            with self.assertRaisesRegex(installers.InstallerError, "网络共享"):
                installers.validate_install_location("pi", r"\\server\share\Pi")

    def test_zip_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-zip-") as temp_name:
            root = Path(temp_name)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.exe", b"bad")
            with self.assertRaises(installers.InstallerError):
                installers._safe_extract_zip(archive, root / "out")
            self.assertFalse((root / "escape.exe").exists())

    def test_zip_resource_limits_are_enforced_before_extraction(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-limits-") as temp_name:
            root = Path(temp_name)
            archive = root / "large.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr("payload.bin", b"x" * 33)
            with mock.patch.object(installers, "MAX_ZIP_UNCOMPRESSED_BYTES", 32):
                with self.assertRaises(installers.InstallerError):
                    installers._safe_extract_zip(archive, root / "large-out")
            self.assertFalse((root / "large-out" / "payload.bin").exists())

            many_archive = root / "many.zip"
            with zipfile.ZipFile(many_archive, "w") as bundle:
                bundle.writestr("one.txt", b"1")
                bundle.writestr("two.txt", b"2")
            with mock.patch.object(installers, "MAX_ZIP_MEMBERS", 1):
                with self.assertRaises(installers.InstallerError):
                    installers._safe_extract_zip(many_archive, root / "many-out")
            self.assertFalse((root / "many-out" / "one.txt").exists())

    def test_zip_duplicate_and_windows_ambiguous_paths_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-paths-") as temp_name:
            root = Path(temp_name)
            duplicate = root / "duplicate.zip"
            with zipfile.ZipFile(duplicate, "w") as bundle:
                bundle.writestr("same.txt", b"one")
                bundle.writestr("SAME.TXT", b"two")
            with self.assertRaises(installers.InstallerError):
                installers._safe_extract_zip(duplicate, root / "duplicate-out")

            alternate_stream = root / "stream.zip"
            with zipfile.ZipFile(alternate_stream, "w") as bundle:
                bundle.writestr("payload.txt:secret", b"bad")
            with self.assertRaises(installers.InstallerError):
                installers._safe_extract_zip(alternate_stream, root / "stream-out")

            device_name = root / "device.zip"
            with zipfile.ZipFile(device_name, "w") as bundle:
                bundle.writestr("bin/CON.txt", b"bad")
            with self.assertRaises(installers.InstallerError):
                installers._safe_extract_zip(device_name, root / "device-out")

    def test_sha256_verification_detects_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-hash-") as temp_name:
            path = Path(temp_name) / "asset.zip"
            path.write_bytes(b"official fixture")
            installers._verify_sha256(path, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(installers.InstallerError):
                installers._verify_sha256(path, "0" * 64)

    def test_download_redirect_must_remain_https(self):
        class Response:
            def __init__(self, url):
                self.url = url

            def geturl(self):
                return self.url

        installers._validate_response_url(Response("https://release-assets.githubusercontent.com/file.zip"))
        for url in ("http://example.com/file.zip", "https://user:pass@example.com/file.zip"):
            with self.assertRaises(installers.InstallerError):
                installers._validate_response_url(Response(url))

    def test_install_record_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-record-") as temp_name:
            root = Path(temp_name)
            settings = root / "settings.json"
            location = root / "Pi"
            location.mkdir()
            (location / "pi.exe").write_bytes(b"fixture")
            installers.record_install(settings, "pi", location, "v1.2.3")
            self.assertEqual(installers.load_install_records(settings)["pi"]["version"], "v1.2.3")
            discovery = installers.managed_discovery(settings, "pi")
            self.assertEqual(discovery[0]["path"], str(location))

    def test_malformed_install_record_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-record-") as temp_name:
            settings = Path(temp_name) / "settings.json"
            settings.write_text(json.dumps({"installations": {"pi": "not-an-object"}}), encoding="utf-8")
            self.assertEqual(installers.managed_discovery(settings, "pi"), [])

    def test_unknown_agent_cannot_be_installed(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-unknown-") as temp_name:
            with self.assertRaises(installers.InstallerError):
                installers.install_agent("unknown", Path(temp_name) / "Unknown", Path(temp_name) / "settings.json")

    def test_staged_install_replaces_atomically_and_restores_on_switch_failure(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-stage-") as temp_name:
            root = Path(temp_name)
            location = root / "Pi"
            location.mkdir()
            (location / "old.txt").write_text("old", encoding="utf-8")
            staging = root / ".Pi.staging"
            staging.mkdir()
            (staging / "new.txt").write_text("new", encoding="utf-8")
            installers._commit_staged_tree(staging, location)
            self.assertFalse((location / "old.txt").exists())
            self.assertEqual((location / "new.txt").read_text(encoding="utf-8"), "new")

            with self.assertRaises(installers.InstallerError):
                installers._commit_staged_tree(root / "missing-stage", location)
            self.assertEqual((location / "new.txt").read_text(encoding="utf-8"), "new")

    def test_in_place_installer_restores_existing_tree_after_failure(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-rollback-") as temp_name:
            root = Path(temp_name)
            location = root / "Hermes Agent"
            location.mkdir()
            (location / "old.txt").write_text("old", encoding="utf-8")

            def fail_after_partial_write():
                (location / "partial.txt").write_text("partial", encoding="utf-8")
                raise installers.InstallerError("simulated failure")

            with self.assertRaisesRegex(installers.InstallerError, "simulated failure"):
                installers._run_in_place_with_rollback(location, fail_after_partial_write)
            self.assertEqual((location / "old.txt").read_text(encoding="utf-8"), "old")
            self.assertFalse((location / "partial.txt").exists())


if __name__ == "__main__":
    unittest.main()
