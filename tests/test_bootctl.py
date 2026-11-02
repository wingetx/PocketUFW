"""Isolated tests for root-owned Magisk boot restoration.

Never touches the real /data/adb tree or modifies the host firewall.
Source files are copied into a disposable test directory with fixed
root paths rewritten to temporary locations.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class BootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pufw-boot-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = self.root / "pocketufw"
        self.service_dir = self.root / "service.d"
        self.service_dir.mkdir()
        self.hook = self.service_dir / "pocketufw.sh"
        self.app = self.root / "engine"
        self.app.mkdir()
        self.fakebin = self.root / "bin"
        self.fakebin.mkdir()
        self.state = self.root / "state"
        self.state.write_text("ACTIVE\n")
        self.calls = self.root / "enable-calls"
        self.config_dir = self.root / "device-protected"
        self.config_dir.mkdir()
        self.env = dict(os.environ,
                        POCKETUFW_CONFIG_DIR=str(self.config_dir),
                        PATH=f"{self.fakebin}:/usr/bin:/bin",
                        TEST_ENGINE_STATE=str(self.state),
                        TEST_ENGINE_CALLS=str(self.calls))

        for cmd, script in {
            "id": "#!/bin/sh\n[ \"$1\" = -u ] && { echo 0; exit 0; }\n/usr/bin/id \"$@\"\n",
            "magisk": "#!/bin/sh\nexit 0\n",
            "getprop": "#!/bin/sh\necho 1\n",
            "pm": "#!/bin/sh\n[ \"$TEST_PM_MISSING\" = 1 ] && exit 1\n[ \"$1\" = path ] && echo 'package:/data/app/placeholder/base.apk'\n",
        }.items():
            target = self.fakebin / cmd
            target.write_text(script)
            target.chmod(0o700)

        (self.app / "pocketufw").write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "verify) cat \"$TEST_ENGINE_STATE\"; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "enable) echo ACTIVE > \"$TEST_ENGINE_STATE\"; "
            "echo called >> \"$TEST_ENGINE_CALLS\"; "
            "echo \"$*\" >> \"$TEST_ENGINE_CALLS.args\" ;;\n"
            "*) exit 5 ;;\n"
            "esac\n"
        )
        (self.app / "vpn-probe").write_text("#!/bin/sh\nexit 0\n")
        (self.app / "udp-config").write_text((PROJECT / "udp-config").read_text())

        source = (PROJECT / "bootctl").read_text()
        source = source.replace("STORE='/data/adb/pocketufw'",
                                f"STORE='{self.store}'")
        source = source.replace("HOOK='/data/adb/service.d/pocketufw.sh'",
                                f"HOOK='{self.hook}'")
        source = source.replace("[ -d /data/adb/service.d ]",
                                f"[ -d '{self.service_dir}' ]")
        (self.app / "bootctl").write_text(source)

        service = (PROJECT / "boot-service").read_text()
        service = service.replace("STORE='/data/adb/pocketufw'",
                                  f"STORE='{self.store}'")
        service = service.replace("HOOK='/data/adb/service.d/pocketufw.sh'",
                                  f"HOOK='{self.hook}'")
        service = service.replace("PATH=/system/bin:/system/xbin:/vendor/bin",
                                  f"PATH={self.fakebin}:/usr/bin:/bin")
        (self.app / "boot-service").write_text(service)

    def call(self, command, env=None):
        return subprocess.run(
            ["/bin/sh", str(self.app / "bootctl"), command],
            capture_output=True, text=True,
            env={**self.env, **(env or {})}, timeout=8
        )

    def boot(self, env=None):
        return subprocess.run(
            ["/bin/sh", str(self.hook)],
            capture_output=True, text=True,
            env={**self.env, **(env or {})}, timeout=8
        )

    def test_install_status_disable_owns_only_its_files(self):
        self.assertEqual(self.call("status").stdout.strip(), "boot=DISABLED")
        other = self.service_dir / "someone_else.sh"
        other.write_text("leave me alone")
        on = self.call("enable")
        self.assertEqual(on.returncode, 0, on.stderr)
        self.assertEqual(on.stdout.strip(), "boot=ENABLED")
        self.assertEqual(self.call("status").stdout.strip(), "boot=ENABLED")
        self.assertEqual(self.hook.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o700)
        self.assertTrue((self.store / "boot.enabled").exists())
        self.assertTrue((self.store / "pocketufw").exists())
        self.assertTrue((self.store / "udp-config").exists())
        self.assertEqual(self.call("disable").stdout.strip(), "boot=DISABLED")
        self.assertEqual(self.call("status").stdout.strip(), "boot=DISABLED")
        self.assertFalse(self.store.exists())
        self.assertFalse(self.hook.exists())
        self.assertEqual(other.read_text(), "leave me alone")

    def test_cannot_arm_if_live_firewall_is_off(self):
        self.state.write_text("INACTIVE\n")
        result = self.call("enable")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.store.exists())

    def test_refuses_existing_unrelated_boot_hook(self):
        self.hook.write_text("#!/bin/sh\n# not ours\n")
        result = self.call("enable")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("belongs to something else", result.stderr)
        self.assertIn("not ours", self.hook.read_text())

    def test_boot_is_idempotent_and_restores_when_inactive(self):
        self.assertEqual(self.call("enable").returncode, 0)
        self.assertEqual(self.boot().returncode, 0)
        self.assertFalse(self.calls.exists())
        self.state.write_text("INACTIVE\n")
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(self.state.read_text().strip(), "ACTIVE")
        self.assertEqual(self.calls.read_text().splitlines(), ["called"])

    def test_committed_manual_ports_reloaded_at_boot_without_app_process(self):
        config = subprocess.run(['/bin/sh', str(self.app / 'udp-config'),
                                 'write', '41476', '45567'],
                                text=True, capture_output=True, env=self.env)
        self.assertEqual(config.returncode, 0, config.stderr)
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        restored = self.boot()
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(self.state.read_text().strip(), 'ACTIVE')
        args = Path(str(self.calls) + '.args').read_text()
        self.assertIn('--tailscale-udp4 41476', args)
        self.assertIn('--tailscale-udp6 45567', args)
        self.assertNotIn('--auto-tailscale', args)
        self.assertEqual(self.call('disable').returncode, 0)
        self.assertFalse(self.store.exists())
        # App-owned config persists when Magisk's hook is deliberately disabled.
        self.assertTrue((self.config_dir / 'udp-committed.conf').exists())

    def test_committed_no_exceptions_does_not_auto_detect(self):
        config = subprocess.run(['/bin/sh', str(self.app / 'udp-config'),
                                 'write', 'none', 'none'],
                                text=True, capture_output=True, env=self.env)
        self.assertEqual(config.returncode, 0, config.stderr)
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(Path(str(self.calls) + '.args').read_text().strip(), 'enable')

    def test_corrupt_committed_config_does_not_execute_untrusted_input(self):
        self.assertEqual(self.call('enable').returncode, 0)
        (self.config_dir / 'udp-committed.conf').write_text('udp4=$(touch /tmp/pwn)\nudp6=none\n')
        self.state.write_text('INACTIVE\n')
        self.assertNotEqual(self.boot().returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.state.read_text().strip(), 'INACTIVE')

    def test_degraded_boot_state_is_never_overwritten(self):
        self.assertEqual(self.call("enable").returncode, 0)
        self.state.write_text("DEGRADED\n")
        self.assertNotEqual(self.boot().returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.state.read_text().strip(), "DEGRADED")

    def test_uninstalled_app_disarms_on_next_boot(self):
        self.assertEqual(self.call("enable").returncode, 0)
        self.assertEqual(self.boot({"TEST_PM_MISSING": "1"}).returncode, 0)
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.store.exists())

    def test_symlink_data_directory_is_refused(self):
        self.store.symlink_to(self.root / "other")
        result = self.call("enable")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.hook.exists())


if __name__ == "__main__":
    unittest.main()
