# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

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

    def test_zip_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-zip-") as temp_name:
            root = Path(temp_name)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape.exe", b"bad")
            with self.assertRaises(installers.InstallerError):
                installers._safe_extract_zip(archive, root / "out")
            self.assertFalse((root / "escape.exe").exists())

    def test_sha256_verification_detects_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-hash-") as temp_name:
            path = Path(temp_name) / "asset.zip"
            path.write_bytes(b"official fixture")
            installers._verify_sha256(path, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(installers.InstallerError):
                installers._verify_sha256(path, "0" * 64)

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

    def test_unknown_agent_cannot_be_installed(self):
        with tempfile.TemporaryDirectory(prefix="key-router-installer-unknown-") as temp_name:
            with self.assertRaises(installers.InstallerError):
                installers.install_agent("unknown", Path(temp_name) / "Unknown", Path(temp_name) / "settings.json")


if __name__ == "__main__":
    unittest.main()
