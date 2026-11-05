"""Root-only app-owned DE policy; tests use a disposable temp directory."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'udp-config'


class UdpConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pufw-de-config-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dir = self.root / 'device-protected'
        self.dir.mkdir()
        self.file = self.dir / 'udp-committed.conf'
        self.env = {**os.environ, 'POCKETUFW_CONFIG_DIR': str(self.dir)}

    def run_cli(self, *args):
        return subprocess.run(['/bin/sh', str(SCRIPT), *args],
                              text=True, capture_output=True, env=self.env, timeout=5)

    def test_default_is_automatic_and_leaves_no_cruft(self):
        result = self.run_cli('read')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), 'mode=AUTOMATIC')
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_write_read_clear_are_atomic_and_validated(self):
        result = self.run_cli('write', '41476', '45567')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ['mode=COMMITTED', 'udp4=41476', 'udp6=45567'])
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.file.read_text(), 'udp4=41476\nudp6=45567\n')
        self.assertEqual(self.run_cli('write', 'none', 'none').returncode, 0)
        self.assertEqual(self.run_cli('clear').stdout.strip(), 'mode=AUTOMATIC')
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_rejects_bad_ports_without_clobbering_previous(self):
        self.assertEqual(self.run_cli('write', '41476', 'none').returncode, 0)
        initial = self.file.read_bytes()
        for bad in ('', '0', '01', '01234', '-1', '65536', 'all', '1;touch /tmp/no',
                    '9999999999999999999'):
            with self.subTest(bad=bad):
                self.assertNotEqual(self.run_cli('write', bad, 'none').returncode, 0)
                self.assertEqual(self.file.read_bytes(), initial)
        self.assertEqual(list(self.dir.iterdir()), [self.file])

    def test_corrupt_format_is_not_evaluated_or_returned_as_verified(self):
        for data in ('udp4=41476\nudp6=$(echo bad)\n',
                     'udp4=41476\nudp6=65536\n',
                     'udp4=41476\nudp6=none\nextra=BAD\n',
                     'udp4=none\nudp6=none',
                     'udp6=none\nudp4=41476\n'):
            with self.subTest(data=data):
                self.file.write_text(data)
                result = self.run_cli('read')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('mode=COMMITTED', result.stdout)

    def test_symlinks_refused_without_modifying_target(self):
        target = self.root / 'unrelated'
        target.write_text('keep me')
        self.file.symlink_to(target)
        self.assertNotEqual(self.run_cli('read').returncode, 0)
        self.assertNotEqual(self.run_cli('write', '41476', 'none').returncode, 0)
        self.assertNotEqual(self.run_cli('clear').returncode, 0)
        self.assertEqual(target.read_text(), 'keep me')

    def test_symlinked_directory_refused_without_touching_its_target(self):
        real = self.root / 'somewhere-else'
        real.mkdir()
        saved = real / 'udp-committed.conf'
        saved.write_text('udp4=41476\nudp6=none\n')
        link = self.root / 'linked'
        link.symlink_to(real)
        self.env['POCKETUFW_CONFIG_DIR'] = str(link)
        for command in (('read',), ('write', '45678', 'none'), ('clear',)):
            with self.subTest(command=command[0]):
                self.assertNotEqual(self.run_cli(*command).returncode, 0)
                self.assertEqual(saved.read_text(), 'udp4=41476\nudp6=none\n')


if __name__ == '__main__':
    unittest.main()
