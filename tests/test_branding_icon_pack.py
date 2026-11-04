"""Sanity checks for PocketUFW alpha branding and the optional icon picker pack."""
import struct
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "android/app"
PACK = ROOT / "android/iconpack"
AN = "{http://schemas.android.com/apk/res/android}"


class BrandingIconPackTests(unittest.TestCase):
    def test_release_companion_iconpack_has_upgrade_version(self):
        build = (PACK / "build.gradle.kts").read_text()
        self.assertIn('applicationId = "io.github.pocketufw.neonicons"', build)
        self.assertIn('versionCode = 3', build)
        self.assertIn('versionName = "1.1.1"', build)

    def test_neon_icon_art_fills_canvas_without_excess_transparency(self):
        # Inspect the PNG alpha bounding box, not its nominal 512px canvas.
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow not installed')
        p = PACK / 'src/main/res/drawable-nodpi/pocketufw_neon.png'
        image = Image.open(p).convert('RGBA')
        alpha = image.getchannel('A')
        bounds = alpha.getbbox()
        self.assertEqual(image.size, (512, 512))
        self.assertIsNotNone(bounds)
        self.assertGreaterEqual(bounds[2] - bounds[0], 420)
        self.assertGreaterEqual(bounds[3] - bounds[1], 420)

    def test_icon_pack_requires_no_permissions_or_services(self):
        manifest = ET.parse(PACK / "src/main/AndroidManifest.xml").getroot()
        self.assertEqual(manifest.findall("uses-permission"), [])
        app = manifest.find("application")
        self.assertEqual(app.findall("service"), [])
        self.assertEqual(app.findall("receiver"), [])
        self.assertEqual(app.findall("provider"), [])
        actions = {
            action.get(AN + "name")
            for action in manifest.findall(".//intent-filter/action")
        }
        self.assertIn("org.adw.launcher.THEMES", actions)
        self.assertIn("com.novalauncher.THEME", actions)
        self.assertNotIn("android.intent.category.LAUNCHER", {
            category.get(AN + "name")
            for category in manifest.findall(".//intent-filter/category")
        })

    def test_appfilter_points_at_the_real_pocketufw_activity(self):
        expected = (
            "ComponentInfo{io.github.pocketufw/"
            "io.github.pocketufw.MainActivity}"
        )
        for name in ("assets", "res/xml"):
            with self.subTest(name=name):
                root = ET.parse(PACK / "src/main" / name / "appfilter.xml").getroot()
                matches = [
                    element for element in root.findall("item")
                    if element.get("component") == expected
                ]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].get("drawable"), "pocketufw_neon")

    def test_alpha_footer_reads_real_version(self):
        text = (APP / "src/main/java/io/github/pocketufw/MainActivity.kt").read_text()
        self.assertIn("BuildConfig.VERSION_NAME", text)
        self.assertNotIn('PocketUFW · 0.1.0-alpha13 ·', text)

    def test_official_adaptive_launcher_references_neon(self):
        path = APP / "src/main/res/mipmap-anydpi-v26/ic_launcher.xml"
        tree = ET.parse(path)
        foreground = tree.find("foreground")
        self.assertEqual(
            foreground.get(AN + "drawable"),
            "@drawable/pocket_penguin_neon_foreground",
        )

    def test_branding_pngs_have_correct_signatures(self):
        paths = [
            ROOT / "assets/branding/pocketufw-neon-penguin.png",
            APP / "src/main/res/drawable-nodpi/pocket_penguin_neon_foreground.png",
            APP / "src/main/res/drawable-nodpi/pocket_penguin_neon_home.png",
            PACK / "src/main/res/drawable-nodpi/pocketufw_neon.png",
        ]
        for path in paths:
            with self.subTest(path=path):
                data = path.read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                width, height = struct.unpack(">II", data[16:24])
                self.assertGreater(width, 128)
                self.assertGreater(height, 128)


if __name__ == "__main__":
    unittest.main()
