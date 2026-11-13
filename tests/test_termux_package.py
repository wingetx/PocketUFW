"""Standalone asset integrity and documented installation in temporary folders."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGER = ROOT / 'tools/package-termux'


class TermuxPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pufw-package-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.assets = self.base / 'release assets'

    def package(self):
        result = subprocess.run(['sh', str(PACKAGER), str(self.assets)],
                                cwd=self.base, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_assets_are_standalone_exact_and_have_a_portable_checksum(self):
        self.package()
        self.assertEqual({p.name for p in self.assets.iterdir()}, {'pufw', 'pufw.sha256', 'Termux-setup.md'})
        helper = (ROOT / 'tools/pufw').read_bytes()
        self.assertEqual((self.assets / 'pufw').read_bytes(), helper)
        self.assertEqual((self.assets / 'pufw').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.assets / 'pufw.sha256').read_text(), f'{hashlib.sha256(helper).hexdigest()}  pufw\n')
        self.assertEqual((self.assets / 'Termux-setup.md').read_bytes(), (ROOT / 'docs/termux.md').read_bytes())
        subprocess.run(['sha256sum', '-c', 'pufw.sha256'], cwd=self.assets, check=True, capture_output=True)

    def test_packaging_refuses_to_overwrite_existing_assets(self):
        self.package()
        (self.assets / 'pufw').write_text('existing candidate\n')
        result = subprocess.run(['sh', str(PACKAGER), str(self.assets)], capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.assets / 'pufw').read_text(), 'existing candidate\n')

    def test_documented_private_copy_and_checksum_gate_before_install(self):
        self.package()
        # No real Termux environment, permissions, root requests or network access.
        fake_home = self.base / 'termux home'
        downloads = fake_home / 'storage/downloads'
        downloads.mkdir(parents=True)
        fake_prefix = self.base / 'termux prefix'
        (fake_prefix / 'bin').mkdir(parents=True)
        destination = fake_prefix / 'bin/pufw'
        for name in ['pufw', 'pufw.sha256']:
            (downloads / name).write_bytes((self.assets / name).read_bytes())
        blocks = re.findall(r'```sh\n(.*?)\n```', (ROOT / 'docs/termux.md').read_text(), re.S)
        self.assertEqual(blocks[0], 'termux-setup-storage')  # The user grants this separately.
        # Substitute task-specific variables rather than changing the host HOME.
        command = (blocks[1] + '\n' + blocks[2]).replace('$HOME', '$PUFW_TEST_HOME').replace('$PREFIX', '$PUFW_TEST_PREFIX')
        environment = os.environ | {'PUFW_TEST_HOME': str(fake_home), 'PUFW_TEST_PREFIX': str(fake_prefix)}
        result = subprocess.run(['sh', '-ec', command], cwd=fake_home, env=environment,
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('pufw: OK', result.stdout)
        self.assertEqual(destination.read_bytes(), (ROOT / 'tools/pufw').read_bytes())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        for failure in ['tampered', 'missing checksum']:
            with self.subTest(failure=failure):
                destination.write_text('keep installed helper\n')
                if failure == 'tampered':
                    (downloads / 'pufw').write_text('unexpected download\n')
                else:
                    (downloads / 'pufw.sha256').unlink()
                result = subprocess.run(['sh', '-ec', command], cwd=fake_home, env=environment,
                                        capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(destination.read_text(), 'keep installed helper\n')


if __name__ == '__main__':
    unittest.main()
