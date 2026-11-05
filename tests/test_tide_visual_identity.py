"""Static contracts for the shared Tide action shape and shield mascot."""
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
KOTLIN = ROOT / 'android/app/src/main/java/io/github/pocketufw'
ASSETS = ROOT / 'android/app/src/main/res/drawable-nodpi'

class TideVisualIdentityTests(unittest.TestCase):
    def test_all_rectangular_actions_use_one_soft_corner_shape(self):
        shared = (KOTLIN / 'TideComponents.kt').read_text()
        self.assertIn('TideActionShape = RoundedCornerShape(12.dp)', shared)
        self.assertIn('TideActionMinHeight = 48.dp', shared)
        self.assertIn('vertical = 10.dp', shared)
        for name in ('TideComponents.kt', 'TideScreen.kt', 'TideCounters.kt',
                     'UdpExceptionsPanel.kt', 'KernelStatusTab.kt'):
            with self.subTest(file=name):
                source = (KOTLIN / name).read_text()
                self.assertIn('shape = TideActionShape', source)
                self.assertNotIn('RoundedCornerShape(9.dp)', source)
        # Settings no longer contains a rectangular VPN refresh action.
        settings = (KOTLIN / 'TideSettings.kt').read_text()
        self.assertNotIn('OutlinedButton(', settings)

    def test_main_screen_shares_the_original_shield_penguin_identity(self):
        source = (KOTLIN / 'TideScreen.kt').read_text()
        self.assertIn('R.drawable.pocket_penguin_neon_badge', source)
        self.assertNotIn('R.drawable.pocket_penguin)', source)
        self.assertTrue((ASSETS / 'pocket_penguin_neon_home.png').is_file())
        self.assertFalse((ASSETS / 'pocket_penguin.webp').exists())
        png = (ASSETS / 'pocket_penguin_neon_badge.png').read_bytes()
        self.assertEqual(png[:8], b'\x89PNG\r\n\x1a\n')
        self.assertEqual(struct.unpack('>II', png[16:24]), (448, 448))

if __name__ == '__main__':
    unittest.main()
