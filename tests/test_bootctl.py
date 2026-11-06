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
        self.disable_calls = Path(str(self.calls) + ".disable")
        self.order = self.root / "order"
        # Absent by default: Android removes it on uninstall.
        self.app_data = self.root / "app-data"
        self.config_dir = self.root / "device-protected"
        self.config_dir.mkdir()
        self.env = dict(os.environ,
                        POCKETUFW_CONFIG_DIR=str(self.config_dir),
                        PATH=f"{self.fakebin}:/usr/bin:/bin",
                        TEST_ENGINE_STATE=str(self.state),
                        TEST_ENGINE_CALLS=str(self.calls),
                        TEST_ORDER_LOG=str(self.order),
                        POCKETUFW_APP_DATA_DIR=str(self.app_data))

        for cmd, script in {
            "id": "#!/bin/sh\n[ \"$1\" = -u ] && { echo 0; exit 0; }\n/usr/bin/id \"$@\"\n",
            "magisk": "#!/bin/sh\nexit 0\n",
            # Reports boot_completed=1 after TEST_BOOT_READY_AFTER polls answered 0.
            "getprop": "#!/bin/sh\n"
                       "[ \"$1\" = sys.boot_completed ] || exit 3\n"
                       "echo getprop >> \"$TEST_ORDER_LOG\"\n"
                       "[ \"${TEST_BOOT_READY_AFTER:-0}\" != never ] || { echo 0; exit 0; }\n"
                       "polls=$(grep -c '^getprop$' \"$TEST_ORDER_LOG\")\n"
                       "if [ \"$polls\" -gt \"${TEST_BOOT_READY_AFTER:-0}\" ]; then echo 1; else echo 0; fi\n",
            "sleep": "#!/bin/sh\n"
                     "echo \"sleep $1\" >> \"$TEST_ORDER_LOG\"\n"
                     "[ -z \"${TEST_REMOVE_WHILE_SLEEPING:-}\" ] || rm -f \"$TEST_REMOVE_WHILE_SLEEPING\"\n",
            "pm": "#!/bin/sh\n"
                  "echo pm >> \"$TEST_ORDER_LOG\"\n"
                  "[ -z \"${TEST_REMOVE_DURING_PM:-}\" ] || rm -f \"$TEST_REMOVE_DURING_PM\"\n"
                  "[ \"$1\" = path ] && [ \"$2\" = io.github.pocketufw ] || exit 9\n"
                  "case \"${TEST_PM_MODE:-ok}\" in\n"
                  "  ok) echo 'package:/data/app/placeholder/base.apk' ;;\n"
                  "  gone) exit 1 ;;\n"
                  "  transient) echo 'cmd: Failure calling service package: Broken pipe (32)' >&2; exit 224 ;;\n"
                  "  one-with-package) echo 'package:/data/app/placeholder/base.apk'; exit 1 ;;\n"
                  "  ok-no-package) exit 0 ;;\n"
                  "esac\n",
        }.items():
            target = self.fakebin / cmd
            target.write_text(script)
            target.chmod(0o700)

        (self.app / "pocketufw").write_text(
            "#!/bin/sh\n"
            "echo \"engine:$*\" >> \"$TEST_ORDER_LOG\"\n"
            "[ -z \"${TEST_REMOVE_DURING_VERIFY:-}\" ] || rm -f \"$TEST_REMOVE_DURING_VERIFY\"\n"
            "case \"$1\" in\n"
            "verify) cat \"$TEST_ENGINE_STATE\"; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "enable) [ \"${TEST_ENGINE_FAIL_ENABLE:-0}\" = 1 ] && exit 7; "
            "echo \"${TEST_ENGINE_ENABLE_RESULT:-ACTIVE}\" > \"$TEST_ENGINE_STATE\"; "
            "echo called >> \"$TEST_ENGINE_CALLS\"; "
            "echo \"$*\" >> \"$TEST_ENGINE_CALLS.args\" ;;\n"
            "disable) echo called >> \"$TEST_ENGINE_CALLS.disable\"; "
            "echo INACTIVE > \"$TEST_ENGINE_STATE\" ;;\n"
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
        self.order.unlink(missing_ok=True)
        return subprocess.run(
            ["/bin/sh", str(self.hook)],
            capture_output=True, text=True,
            env={**self.env, **(env or {})}, timeout=8
        )

    def order_lines(self):
        return self.order.read_text().splitlines() if self.order.exists() else []

    def enable_args(self):
        path = Path(str(self.calls) + '.args')
        return path.read_text().splitlines() if path.exists() else []

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

    def test_corrupt_committed_config_is_not_executed_and_still_enables(self):
        self.assertEqual(self.call('enable').returncode, 0)
        pwned = self.root / 'pwned'
        (self.config_dir / 'udp-committed.conf').write_text(f'udp4=$(touch {pwned})\nudp6=none\n')
        self.state.write_text('INACTIVE\n')
        self.assertEqual(self.boot().returncode, 0)
        self.assertFalse(pwned.exists())
        self.assertEqual(self.enable_args(), ['enable'])
        self.assertEqual(self.state.read_text().strip(), 'ACTIVE')

    def test_unreadable_or_unknown_saved_config_still_enables_without_exceptions(self):
        def missing_dir():
            return {'POCKETUFW_CONFIG_DIR': str(self.root / 'no-such-dir')}

        def unsafe_symlink():
            target = self.root / 'elsewhere'
            target.write_text('udp4=41641\nudp6=none\n')
            (self.config_dir / 'udp-committed.conf').symlink_to(target)
            return {}

        def unknown_mode():
            (self.store / 'udp-config').write_text('#!/bin/sh\necho mode=FUTURE\n')
            return {}

        def empty_output():
            (self.store / 'udp-config').write_text('#!/bin/sh\nexit 0\n')
            return {}

        def failing():
            (self.store / 'udp-config').write_text('#!/bin/sh\necho mode=AUTOMATIC\nexit 3\n')
            return {}

        def copy_missing():
            (self.store / 'udp-config').unlink()
            return {}

        for setup in (missing_dir, unsafe_symlink, unknown_mode, empty_output, failing, copy_missing):
            with self.subTest(case=setup.__name__):
                for leftover in (self.calls, Path(str(self.calls) + '.args'),
                                 self.config_dir / 'udp-committed.conf'):
                    leftover.unlink(missing_ok=True)
                self.state.write_text('ACTIVE\n')
                self.assertEqual(self.call('enable').returncode, 0)
                env = setup()
                self.state.write_text('INACTIVE\n')
                restored = self.boot(env)
                self.assertEqual(restored.returncode, 0, restored.stderr)
                self.assertEqual(self.enable_args(), ['enable'])
                self.assertEqual(self.state.read_text().strip(), 'ACTIVE')

    def test_missing_probe_copy_still_enables(self):
        # Engine decides what to do without a probe; boot must not give up first.
        self.assertEqual(self.call('enable').returncode, 0)
        (self.store / 'vpn-probe').unlink()
        self.state.write_text('INACTIVE\n')
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(self.enable_args(), ['enable --auto-tailscale'])
        self.assertEqual(self.state.read_text().strip(), 'ACTIVE')

    def test_missing_engine_copy_or_marker_does_nothing(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        (self.store / 'boot.enabled').unlink()
        self.assertEqual(self.boot().returncode, 0)
        # It still asks whether the app exists, and nothing more while it does.
        self.assertEqual(self.order_lines(), ['getprop', 'pm'])
        self.assertTrue(self.hook.exists())
        self.state.write_text('ACTIVE\n')
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        (self.store / 'pocketufw').unlink()
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(self.order_lines(), ['getprop', 'pm'])
        self.assertTrue(self.hook.exists())

    def test_automatic_mode_passes_auto_tailscale(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(self.enable_args(), ['enable --auto-tailscale'])

    def test_waits_for_boot_completed_before_doing_anything(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        self.assertEqual(self.boot({'TEST_BOOT_READY_AFTER': '3'}).returncode, 0)
        lines = self.order_lines()
        self.assertEqual(lines[:7], ['getprop', 'sleep 2', 'getprop', 'sleep 2', 'getprop', 'sleep 2', 'getprop'])
        self.assertEqual(lines[7], 'pm')
        self.assertEqual(lines[8:], ['engine:verify', 'engine:enable --auto-tailscale', 'engine:verify'])

    def test_wait_limit_installs_the_firewall_and_skips_only_the_uninstall_check(self):
        for pm_mode in ('ok', 'gone'):
            with self.subTest(pm=pm_mode):
                self.calls.unlink(missing_ok=True)
                Path(str(self.calls) + '.args').unlink(missing_ok=True)
                self.state.write_text('ACTIVE\n')
                self.assertEqual(self.call('enable').returncode, 0)
                self.state.write_text('INACTIVE\n')
                result = self.boot({'TEST_BOOT_READY_AFTER': 'never', 'TEST_PM_MODE': pm_mode})
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = self.order_lines()
                self.assertEqual(lines.count('sleep 2'), 90)
                self.assertNotIn('pm', lines)
                self.assertEqual(self.enable_args(), ['enable --auto-tailscale'])
                self.assertEqual(self.state.read_text().strip(), 'ACTIVE')
                self.assertTrue(self.hook.exists())
                self.assertTrue((self.store / 'boot.enabled').exists())

    def test_wait_limit_still_never_replaces_a_partial_firewall(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('DEGRADED\n')
        self.assertNotEqual(self.boot({'TEST_BOOT_READY_AFTER': 'never'}).returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.disable_calls.exists())

    def test_opt_out_during_the_wait_stops_the_boot_restore(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        result = self.boot({'TEST_BOOT_READY_AFTER': 'never',
                            'TEST_REMOVE_WHILE_SLEEPING': str(self.store / 'boot.enabled')})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.order_lines(), ['getprop', 'sleep 2'])
        self.assertFalse(self.calls.exists())

    def test_opt_out_during_the_last_checks_stops_the_boot_restore(self):
        marker = str(self.store / 'boot.enabled')
        for variable, last_call in (('TEST_REMOVE_DURING_PM', 'pm'), ('TEST_REMOVE_DURING_VERIFY', 'engine:verify')):
            with self.subTest(during=last_call):
                self.state.write_text('ACTIVE\n')
                self.assertEqual(self.call('enable').returncode, 0)
                self.state.write_text('INACTIVE\n')
                result = self.boot({variable: marker})
                self.assertEqual(result.returncode, 0)
                self.assertEqual(self.order_lines()[-1], last_call)
                self.assertFalse(self.calls.exists())

    def test_ambiguous_package_manager_answers_never_disarm(self):
        cases = (('transient', False), ('one-with-package', False), ('ok-no-package', False),
                 ('gone', True))
        for mode, data_dir_present in cases:
            with self.subTest(pm=mode, data_dir=data_dir_present):
                for leftover in (self.calls, Path(str(self.calls) + '.args')):
                    leftover.unlink(missing_ok=True)
                self.state.write_text('ACTIVE\n')
                self.assertEqual(self.call('enable').returncode, 0)
                if data_dir_present:
                    self.app_data.mkdir(exist_ok=True)
                self.state.write_text('INACTIVE\n')
                result = self.boot({'TEST_PM_MODE': mode})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(self.hook.exists())
                self.assertTrue((self.store / 'pocketufw').exists())
                self.assertTrue((self.store / 'boot.enabled').exists())
                self.assertEqual(self.enable_args(), ['enable --auto-tailscale'])
                self.assertEqual(self.state.read_text().strip(), 'ACTIVE')
                if data_dir_present:
                    self.app_data.rmdir()

    def test_default_app_data_dir_is_the_production_package(self):
        self.assertIn('${POCKETUFW_APP_DATA_DIR:-/data/user_de/0/io.github.pocketufw}',
                      (PROJECT / 'boot-service').read_text())

    def test_verifies_after_enable_and_reports_failure_without_wiping(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        result = self.boot({'TEST_ENGINE_ENABLE_RESULT': 'DEGRADED'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.order_lines()[-2:], ['engine:enable --auto-tailscale', 'engine:verify'])
        self.assertFalse(self.disable_calls.exists())
        self.assertEqual(self.state.read_text().strip(), 'DEGRADED')

    def test_engine_enable_failure_is_reported_for_every_saved_mode(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.state.write_text('INACTIVE\n')
        self.assertNotEqual(self.boot({'TEST_ENGINE_FAIL_ENABLE': '1'}).returncode, 0)
        (self.config_dir / 'udp-committed.conf').write_text('udp4=41641\nudp6=none\n')
        self.assertNotEqual(self.boot({'TEST_ENGINE_FAIL_ENABLE': '1'}).returncode, 0)
        (self.config_dir / 'udp-committed.conf').write_text('garbage\n')
        self.assertNotEqual(self.boot({'TEST_ENGINE_FAIL_ENABLE': '1'}).returncode, 0)
        self.assertFalse(self.disable_calls.exists())

    def test_never_wipes_or_replaces_partial_or_unknown_firewall(self):
        self.assertEqual(self.call('enable').returncode, 0)
        for state in ('DEGRADED', 'SOMETHING-ELSE', ''):
            with self.subTest(state=state):
                self.state.write_text(state + '\n')
                self.assertNotEqual(self.boot().returncode, 0)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.disable_calls.exists())
                self.assertEqual(self.state.read_text().strip(), state)
                self.assertEqual(self.order_lines()[-1], 'engine:verify')

    def test_active_firewall_is_left_alone(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.assertEqual(self.boot().returncode, 0)
        self.assertEqual(self.order_lines()[-1], 'engine:verify')
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.disable_calls.exists())

    # --- status: an armed hook must be complete and running what the app shipped. ---

    def test_status_requires_every_installed_copy(self):
        for name in ('pocketufw', 'vpn-probe', 'udp-config', 'boot.enabled'):
            with self.subTest(missing=name):
                self.assertEqual(self.call('enable').returncode, 0)
                self.assertEqual(self.call('status').stdout.strip(), 'boot=ENABLED')
                (self.store / name).unlink()
                self.assertEqual(self.call('status').stdout.strip(), 'boot=DEGRADED')

    def test_status_reports_stale_when_any_installed_copy_differs(self):
        for path in (self.store / 'pocketufw', self.store / 'vpn-probe',
                     self.store / 'udp-config', self.hook):
            with self.subTest(copy=path.name):
                self.assertEqual(self.call('enable').returncode, 0)
                self.assertEqual(self.call('status').stdout.strip(), 'boot=ENABLED')
                with path.open('a') as fh:
                    fh.write('# an older build\n')
                self.assertEqual(self.call('status').stdout.strip(), 'boot=STALE')
                # Installing refreshes the copies.
                self.assertEqual(self.call('enable').returncode, 0)
                self.assertEqual(self.call('status').stdout.strip(), 'boot=ENABLED')

    def test_status_reports_stale_when_the_app_upgrade_changed_a_source(self):
        self.assertEqual(self.call('enable').returncode, 0)
        with (self.app / 'boot-service').open('a') as fh:
            fh.write('# a newer build\n')
        self.assertEqual(self.call('status').stdout.strip(), 'boot=STALE')

    def test_unreadable_source_is_not_called_stale(self):
        for name in ('pocketufw', 'vpn-probe', 'udp-config', 'boot-service'):
            with self.subTest(source=name):
                source = self.app / name
                kept = source.read_text()
                self.assertEqual(self.call('enable').returncode, 0)
                source.unlink()
                self.assertEqual(self.call('status').stdout.strip(), 'boot=ENABLED')
                source.write_text(kept)

    def test_missing_copy_outranks_stale(self):
        self.assertEqual(self.call('enable').returncode, 0)
        with (self.store / 'pocketufw').open('a') as fh:
            fh.write('# an older build\n')
        (self.store / 'udp-config').unlink()
        self.assertEqual(self.call('status').stdout.strip(), 'boot=DEGRADED')

    def test_hook_conflict_outranks_stale(self):
        self.assertEqual(self.call('enable').returncode, 0)
        with (self.store / 'pocketufw').open('a') as fh:
            fh.write('# an older build\n')
        self.hook.write_text('#!/bin/sh\n# not ours\n')
        self.assertEqual(self.call('status').stdout.strip(), 'boot=CONFLICT')

    def test_installed_copies_are_private_and_identical_to_the_source(self):
        self.assertEqual(self.call('enable').returncode, 0)
        for name in ('pocketufw', 'vpn-probe', 'udp-config'):
            with self.subTest(copy=name):
                self.assertEqual((self.store / name).read_bytes(), (self.app / name).read_bytes())
                self.assertEqual((self.store / name).stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.hook.read_bytes(), (self.app / 'boot-service').read_bytes())
        self.assertEqual((self.store / 'boot.enabled').stat().st_mode & 0o777, 0o600)

    def test_cannot_arm_on_a_firewall_that_is_not_active(self):
        for state in ('DEGRADED', 'INACTIVE'):
            with self.subTest(state=state):
                self.state.write_text(state + '\n')
                self.assertNotEqual(self.call('enable').returncode, 0)
                self.assertFalse(self.hook.exists())
        # Even if a verifier printed something else with a zero exit.
        (self.app / 'pocketufw').write_text('#!/bin/sh\necho DEGRADED\n')
        self.assertNotEqual(self.call('enable').returncode, 0)
        self.assertFalse(self.hook.exists())

    def test_symlinked_data_directory_does_not_write_through(self):
        target = self.root / 'other'
        target.mkdir()
        self.store.symlink_to(target)
        self.assertNotEqual(self.call('enable').returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(self.call('status').stdout.strip(), 'boot=CONFLICT')

    def test_symlinked_boot_file_is_refused(self):
        self.assertEqual(self.call('enable').returncode, 0)
        target = self.root / 'other-file'
        target.write_text('keep')
        (self.store / 'pocketufw').unlink()
        (self.store / 'pocketufw').symlink_to(target)
        self.assertNotEqual(self.call('enable').returncode, 0)
        self.assertEqual(target.read_text(), 'keep')

    def test_degraded_boot_state_is_never_overwritten(self):
        self.assertEqual(self.call("enable").returncode, 0)
        self.state.write_text("DEGRADED\n")
        self.assertNotEqual(self.boot().returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.disable_calls.exists())
        self.assertEqual(self.state.read_text().strip(), "DEGRADED")

    def test_uninstalled_app_disarms_on_next_boot(self):
        self.assertEqual(self.call("enable").returncode, 0)
        self.state.write_text("INACTIVE\n")
        self.assertEqual(self.boot({"TEST_PM_MODE": "gone"}).returncode, 0)
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.store.exists())
        self.assertFalse(self.calls.exists())

    # --- Cleanup once the app is gone, from states an interruption can leave. ---

    def run_file(self, path, env=None):
        self.order.unlink(missing_ok=True)
        return subprocess.run(['/bin/sh', str(path)], capture_output=True, text=True,
                              env={**self.env, **(env or {})}, timeout=8)

    def test_a_hook_missing_its_marker_or_engine_still_removes_itself(self):
        for missing in ('boot.enabled', 'pocketufw'):
            with self.subTest(missing=missing):
                self.state.write_text('ACTIVE\n')
                self.assertEqual(self.call('enable').returncode, 0)
                (self.store / missing).unlink()
                self.state.write_text('INACTIVE\n')
                self.assertEqual(self.boot({'TEST_PM_MODE': 'gone'}).returncode, 0)
                self.assertFalse(self.hook.exists())
                self.assertFalse(self.store.exists())
                self.assertFalse(self.calls.exists())

    def test_a_hook_missing_its_marker_never_removes_itself_on_an_ambiguous_answer(self):
        self.assertEqual(self.call('enable').returncode, 0)
        (self.store / 'boot.enabled').unlink()
        for mode in ('ok', 'transient', 'one-with-package', 'ok-no-package'):
            with self.subTest(pm=mode):
                self.assertEqual(self.boot({'TEST_PM_MODE': mode}).returncode, 0)
                self.assertTrue(self.hook.exists())
                self.assertTrue(self.store.exists())

    def test_app_gone_also_removes_stage_files(self):
        self.assertEqual(self.call('enable').returncode, 0)
        stage = Path(str(self.hook) + '.stage')
        stage.write_bytes(self.hook.read_bytes())
        for name in ('.pocketufw.stage', '.vpn-probe.stage', '.udp-config.stage', '.boot.enabled.stage'):
            (self.store / name).write_text('partial')
        self.assertEqual(self.boot({'TEST_PM_MODE': 'gone'}).returncode, 0)
        self.assertFalse(stage.exists())
        self.assertFalse(self.hook.exists())
        self.assertFalse(self.store.exists())

    def test_cleanup_never_touches_a_stage_path_or_hook_that_isnt_ours(self):
        self.assertEqual(self.call('enable').returncode, 0)
        stage = Path(str(self.hook) + '.stage')
        stage.write_text('#!/bin/sh\n# belongs to someone else\n')
        self.assertEqual(self.boot({'TEST_PM_MODE': 'gone'}).returncode, 0)
        self.assertIn('someone else', stage.read_text())
        self.assertFalse(self.hook.exists())

    def test_a_leftover_stage_copy_running_alone_spares_another_owners_hook(self):
        self.assertEqual(self.call('enable').returncode, 0)
        stage = Path(str(self.hook) + '.stage')
        stage.write_bytes(self.hook.read_bytes())
        self.hook.write_text('#!/bin/sh\n# belongs to another module\n')
        self.assertEqual(self.run_file(stage, {'TEST_PM_MODE': 'gone'}).returncode, 0)
        self.assertIn('another module', self.hook.read_text())
        self.assertFalse(stage.exists())
        self.assertFalse(self.store.exists())

    def test_cleanup_doesnt_write_through_a_symlinked_data_directory(self):
        target = self.root / 'other'
        target.mkdir()
        (target / 'boot.enabled').write_text('someone else')
        self.service_dir.joinpath('placeholder').unlink(missing_ok=True)
        self.hook.write_bytes((self.app / 'boot-service').read_bytes())
        self.store.symlink_to(target)
        self.assertEqual(self.boot({'TEST_PM_MODE': 'gone'}).returncode, 0)
        self.assertEqual((target / 'boot.enabled').read_text(), 'someone else')
        self.assertTrue(self.store.is_symlink())

    def test_off_removes_a_leftover_stage_hook(self):
        for content in (None, ''):
            with self.subTest(empty=content == ''):
                self.state.write_text('ACTIVE\n')
                self.assertEqual(self.call('enable').returncode, 0)
                stage = Path(str(self.hook) + '.stage')
                if content is None:
                    stage.write_bytes(self.hook.read_bytes())
                else:
                    stage.write_text(content)
                self.assertEqual(self.call('disable').returncode, 0)
                self.assertFalse(stage.exists())

    def residue(self):
        result = self.call('residue')
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split('=', 1) for line in result.stdout.splitlines())

    def test_purge_removes_everything_of_ours_and_nothing_else(self):
        other = self.service_dir / 'someone_else.sh'
        other.write_text('leave me alone')
        self.assertEqual(self.call('enable').returncode, 0)
        Path(str(self.hook) + '.stage').write_bytes(self.hook.read_bytes())
        (self.store / '.vpn-probe.stage').write_text('partial')
        self.assertEqual(self.residue(), {'boot_left': 'boot_hook,boot_hook_stage,boot_data', 'boot_kept': ''})
        self.assertEqual(self.call('purge').returncode, 0)
        self.assertEqual(self.residue(), {'boot_left': '', 'boot_kept': ''})
        self.assertEqual(sorted(p.name for p in self.service_dir.iterdir()), ['someone_else.sh'])
        self.assertEqual(other.read_text(), 'leave me alone')
        self.assertEqual(self.call('purge').returncode, 0)

    def test_purge_clears_our_files_when_another_owner_holds_the_hook_path(self):
        self.assertEqual(self.call('enable').returncode, 0)
        self.hook.write_text('#!/bin/sh\n# belongs to another module\n')
        self.assertEqual(self.call('purge').returncode, 0)
        self.assertIn('another module', self.hook.read_text())
        self.assertFalse(self.store.exists())
        self.assertEqual(self.residue(), {'boot_left': '', 'boot_kept': 'boot_hook'})

    def test_purge_never_deletes_a_file_it_didnt_install(self):
        self.assertEqual(self.call('enable').returncode, 0)
        stranger = self.store / 'not-ours'
        stranger.write_text('keep')
        self.assertEqual(self.call('purge').returncode, 0)
        self.assertEqual(stranger.read_text(), 'keep')
        self.assertFalse((self.store / 'pocketufw').exists())
        self.assertEqual(self.residue(), {'boot_left': 'boot_data', 'boot_kept': ''})

    def test_purge_follows_no_symlink(self):
        target = self.root / 'other'
        target.mkdir()
        (target / 'pocketufw').write_text('keep')
        self.store.symlink_to(target)
        hook_target = self.root / 'other-hook'
        hook_target.write_text('# PocketUFW boot hook v1\n')
        self.hook.symlink_to(hook_target)
        self.assertEqual(self.call('purge').returncode, 0)
        self.assertEqual((target / 'pocketufw').read_text(), 'keep')
        self.assertTrue(hook_target.exists())
        self.assertTrue(self.hook.is_symlink())
        self.assertEqual(self.residue(), {'boot_left': '', 'boot_kept': 'boot_hook,boot_data'})

    def test_a_symlink_inside_the_data_directory_is_removed_without_following_it(self):
        self.assertEqual(self.call('enable').returncode, 0)
        target = self.root / 'other-file'
        target.write_text('keep')
        (self.store / 'pocketufw').unlink()
        (self.store / 'pocketufw').symlink_to(target)
        self.assertEqual(self.call('purge').returncode, 0)
        self.assertEqual(target.read_text(), 'keep')
        self.assertFalse(self.store.exists())

    def test_purge_reports_a_file_it_could_not_remove(self):
        self.assertEqual(self.call('enable').returncode, 0)
        (self.store / 'pocketufw').unlink()
        (self.store / 'pocketufw').mkdir()
        self.assertNotEqual(self.call('purge').returncode, 0)
        self.assertEqual(self.residue()['boot_left'], 'boot_data')

    def test_residue_changes_nothing(self):
        self.assertEqual(self.call('enable').returncode, 0)
        before = sorted(str(p) for p in self.root.rglob('*'))
        self.residue()
        self.assertEqual(sorted(str(p) for p in self.root.rglob('*')), before)

    def test_symlink_data_directory_is_refused(self):
        self.store.symlink_to(self.root / "other")
        result = self.call("enable")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.hook.exists())


if __name__ == "__main__":
    unittest.main()
