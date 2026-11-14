"""Upstream F-Droid listing and current source-release metadata contract."""
from pathlib import Path
import re
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "fastlane/metadata/android/en-US"
GRADLE = ROOT / "android/app/build.gradle.kts"


class FDroidMetadataTests(unittest.TestCase):
    def test_current_version_has_matching_changelog_and_release_notes(self):
        gradle = GRADLE.read_text()
        code = re.search(r'versionCode\s*=\s*(\d+)\b', gradle)
        version = re.search(r'versionName\s*=\s*"([^"]+)"', gradle)
        self.assertIsNotNone(code)
        self.assertIsNotNone(version)
        self.assertGreater(int(code.group(1)), 0)
        self.assertIn('applicationId = "io.github.pocketufw"', gradle)
        self.assertIn('namespace = "io.github.pocketufw"', gradle)
        self.assertNotIn('io.github.pocketufw.alpha', gradle)
        self.assertIn('io.github.pocketufw', (ROOT / 'boot-service').read_text())
        self.assertIn('/data/user_de/0/io.github.pocketufw/files',
                      (ROOT / 'udp-config').read_text())
        for script in ('boot-service', 'udp-config'):
            self.assertNotIn('io.github.pocketufw.alpha',
                             (ROOT / script).read_text())
        notes = (META / f"changelogs/{code.group(1)}.txt").read_text()
        self.assertTrue(10 < len(notes.strip()) <= 500)
        release = (ROOT / f"docs/releases/{version.group(1)}.md").read_text()
        self.assertIn(f"# PocketUFW {version.group(1)}", release)
        self.assertIn(f"versionCode {code.group(1)}", release)

    def test_listing_is_present_and_accurate(self):
        self.assertEqual((META / 'title.txt').read_text().strip(), 'PocketUFW')
        summary = (META / 'short_description.txt').read_text().strip()
        self.assertTrue(10 < len(summary) < 80)
        self.assertFalse(summary.endswith('.'))
        description = (META / 'full_description.txt').read_text()
        for required in ('root', 'IPv4', 'IPv6', 'Tailscale', 'Magisk',
                         'beta', 'Android', 'not universal'):
            self.assertIn(required.lower(), description.lower())

    def test_neon_listing_icon_is_png_512_square(self):
        png = (META / 'images/icon.png').read_bytes()
        self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(struct.unpack('>II', png[16:24]), (512, 512))


if __name__ == '__main__':
    unittest.main()
