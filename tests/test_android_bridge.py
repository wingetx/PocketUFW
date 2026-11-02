"""The GUI bridge batches privileged work into one root session.

These tests use fake engine commands in a temporary directory and never
touch actual iptables, /data/adb, or device privileges.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class AndroidBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pufw-ui-bridge-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.engine = self.root / "engine"
        self.engine.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.state.write_text("ACTIVE\n")
        self.boot_state = self.root / "bootstate"
        self.boot_state.write_text("ENABLED\n")
        self.log = self.root / "calls"
        self.config_dir = self.root / "device-protected"
        self.config_dir.mkdir()
        self.env = dict(os.environ,
                        POCKETUFW_CONFIG_DIR=str(self.config_dir),
                        PATH=str(self.bin) + ":/usr/bin:/bin",
                        TEST_ENGINE_STATE=str(self.state),
                        TEST_BOOT_STATE=str(self.boot_state),
                        TEST_BRIDGE_LOG=str(self.log))
        fake_id = self.bin / "id"
        fake_id.write_text(
            "#!/bin/sh\n"
            "[ \"$1\" = '-u' ] && { echo 0; exit 0; }\n"
            "exec /usr/bin/id \"$@\"\n"
        )
        fake_id.chmod(0o755)

        (self.engine / "pocketufw").write_text(
            "#!/bin/sh\n"
            "echo \"engine:$1\" >> \"$TEST_BRIDGE_LOG\"\n"
            "case \"$1\" in\n"
            "verify) cat \"$TEST_ENGINE_STATE\"; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "activity) [ \"$TEST_ENGINE_ACTIVITY_FAIL\" = 1 ] && exit 9; "
            "current=$(cat \"$TEST_ENGINE_STATE\"); echo \"state=$current\"; "
            "[ \"$current\" = ACTIVE ] || exit 4; "
            "echo ipv4_blocked=41; echo ipv6_blocked=8; "
            "echo ipv4_blocked_bytes=3200; echo ipv6_blocked_bytes=600; "
            "echo ipv4_established_replies=900; echo ipv6_established_replies=25 ;;\n"
            "enable) [ \"$TEST_ENGINE_FAIL_ENABLE\" = 1 ] && exit 7; "
            "if [ \"$TEST_ENGINE_BAD_ENABLE\" = 1 ]; "
            "then echo DEGRADED > \"$TEST_ENGINE_STATE\"; "
            "else echo ACTIVE > \"$TEST_ENGINE_STATE\"; fi ;;\n"
            "disable) echo INACTIVE > \"$TEST_ENGINE_STATE\" ;;\n"
            "get-ports) [ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] || exit 4; "
            "echo udp4=none; echo udp6=none ;;\n"
            "refresh) [ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "set-ports) [ \"$TEST_ENGINE_FAIL_MANUAL\" = 1 ] && exit 7; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "*) exit 8 ;;\n"
            "esac\n"
        )
        (self.engine / "bootctl").write_text(
            "#!/bin/sh\n"
            "echo \"boot:$1\" >> \"$TEST_BRIDGE_LOG\"\n"
            "case \"$1\" in\n"
            "status) echo \"boot=$(cat \"$TEST_BOOT_STATE\")\" ;;\n"
            "enable) [ \"$TEST_BOOT_CANNOT_ENABLE\" = 1 ] && exit 7; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] || exit 5; "
            "echo ENABLED > \"$TEST_BOOT_STATE\" ;;\n"
            "disable) [ \"$TEST_BOOT_CANNOT_DISABLE\" = 1 ] && exit 7; "
            "echo DISABLED > \"$TEST_BOOT_STATE\" ;;\n"
            "*) exit 8 ;;\n"
            "esac\n"
        )
        (self.engine / "rules-report").write_text(
            "#!/bin/sh\n"
            "[ \"$TEST_RULE_REPORT_FAIL\" = 1 ] && exit 9\n"
            "echo input_policy4=ACCEPT\n"
            "echo hook4_01=-A\\ INPUT\\ -i\\ wlan+\\ -j\\ POCKETUFW_IN\n"
            "echo main4_01=-A\\ POCKETUFW_IN\\ -j\\ DROP\n"
            "echo input_policy6=ACCEPT\n"
            "echo hook6_01=-A\\ INPUT\\ -i\\ wlan+\\ -j\\ POCKETUFW_IN\n"
            "echo main6_01=-A\\ POCKETUFW_IN\\ -j\\ DROP\n"
            "echo rules_report=READY\n"
        )
        (self.engine / "udp-config").write_text((PROJECT / "udp-config").read_text())
        (self.engine / "android-bridge").write_text(
            (PROJECT / "android-bridge").read_text()
        )

    def run_bridge(self, action, extra=None, args=()):
        p = subprocess.run(
            ["/bin/sh", str(self.engine / "android-bridge"), action, *args],
            capture_output=True, text=True,
            env={**self.env, "TEST_BOOT_CANNOT_DISABLE": "0",
                 "TEST_ENGINE_FAIL_ENABLE": "0", "TEST_ENGINE_BAD_ENABLE": "0",
                 "TEST_BOOT_CANNOT_ENABLE": "0", "TEST_ENGINE_FAIL_MANUAL": "0",
                 "TEST_ENGINE_ACTIVITY_FAIL": "0",
                 "TEST_RULE_REPORT_FAIL": "0",
                 **(extra or {})},
            timeout=9,
        )
        values = dict(
            line.split("=", 1) for line in p.stdout.splitlines() if "=" in line
        )
        return p, values

    def log_lines(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_inspection_reads_state_boot_and_counters_in_one_call(self):
        result, values = self.run_bridge("inspect")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values["root"], "GRANTED")
        self.assertEqual(values["operation"], "NONE")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["boot"], "ENABLED")
        self.assertEqual(values["ipv4_blocked"], "41")
        self.assertEqual(values["ipv6_blocked"], "8")
        self.assertEqual(self.log_lines(),
                         ["engine:activity", "boot:status"])

    def test_one_inspection_includes_read_only_kernel_policy(self):
        result, values = self.run_bridge("inspect")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values["rules_report"], "READY")
        self.assertEqual(values["input_policy4"], "ACCEPT")
        self.assertIn("-j DROP", values["main4_01"])
        self.assertIn("-i wlan+", values["hook6_01"])

    def test_incomplete_rule_report_not_presented_as_verified(self):
        result, values = self.run_bridge(
            "inspect", {"TEST_RULE_REPORT_FAIL": "1"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["rules_report"], "UNAVAILABLE")
        self.assertNotIn("main4_01", values)

    def test_inactive_does_not_claim_zero_counters(self):
        self.state.write_text("INACTIVE\n")
        result, values = self.run_bridge("inspect")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["state"], "INACTIVE")
        self.assertNotIn("ipv4_blocked", values)
        self.assertEqual(self.log_lines(), ["engine:activity", "boot:status"])

    def test_enable_verifies_once_and_reads_counters(self):
        self.state.write_text("INACTIVE\n")
        result, values = self.run_bridge("enable")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["operation"], "SUCCESS")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(self.log_lines(), [
            "engine:enable", "engine:activity", "boot:status"
        ])

    def test_disable_disarms_boot_before_disabling_firewall(self):
        result, values = self.run_bridge("disable")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["operation"], "SUCCESS")
        self.assertEqual(values["state"], "INACTIVE")
        self.assertEqual(values["boot"], "DISABLED")
        self.assertEqual(values["previous_boot"], "ENABLED")
        self.assertEqual(self.log_lines(), [
            "boot:status", "boot:disable", "engine:disable", "engine:activity", "boot:status"
        ])

    def test_failed_disarm_never_disables_live_rules(self):
        result, values = self.run_bridge(
            "disable", {"TEST_BOOT_CANNOT_DISABLE": "1"}
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["operation"], "FAILED")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(self.log_lines(), [
            "boot:status", "boot:disable", "engine:activity", "boot:status"
        ])

    def test_home_enable_can_restore_previous_boot_preference(self):
        self.state.write_text("INACTIVE\n")
        self.boot_state.write_text("DISABLED\n")
        _, values = self.run_bridge("enable-restore")
        self.assertEqual(values["operation"], "SUCCESS")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["boot"], "ENABLED")
        self.assertIn("boot:enable", self.log_lines())

    def test_rearm_failure_does_not_claim_full_success(self):
        self.state.write_text("INACTIVE\n")
        self.boot_state.write_text("DISABLED\n")
        _, values = self.run_bridge("enable-restore", {"TEST_BOOT_CANNOT_ENABLE": "1"})
        self.assertEqual(values["operation"], "FAILED")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["boot"], "DISABLED")
        self.assertIn("could not be rearmed", values["message"])

    def test_tile_toggle_off_disarms_boot_and_reports_previous_opt_in(self):
        result, values = self.run_bridge("toggle")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values["operation"], "SUCCESS")
        self.assertEqual(values["previous_boot"], "ENABLED")
        self.assertEqual(values["state"], "INACTIVE")
        self.assertEqual(values["boot"], "DISABLED")
        self.assertEqual(self.log_lines(), [
            "engine:verify", "boot:status", "boot:disable", "engine:disable",
            "engine:activity", "boot:status"
        ])

    def test_tile_toggle_on_without_opt_in_leaves_boot_disabled(self):
        self.state.write_text("INACTIVE\n")
        self.boot_state.write_text("DISABLED\n")
        _, values = self.run_bridge("toggle")
        self.assertEqual(values["operation"], "SUCCESS")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["boot"], "DISABLED")
        self.assertNotIn("boot:enable", self.log_lines())

    def test_tile_toggle_on_restores_prior_boot_opt_in(self):
        self.state.write_text("INACTIVE\n")
        self.boot_state.write_text("DISABLED\n")
        _, values = self.run_bridge("toggle-restore")
        self.assertEqual(values["operation"], "SUCCESS")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["boot"], "ENABLED")
        self.assertEqual(self.log_lines()[:3], ["engine:verify", "engine:enable", "boot:enable"])

    def test_toggle_refuses_ambiguous_or_degraded_state(self):
        for state in ("DEGRADED", "UNEXPECTED"):
            with self.subTest(state=state):
                self.log.unlink(missing_ok=True)
                self.state.write_text(state + "\n")
                _, values = self.run_bridge("toggle")
                self.assertEqual(values["operation"], "FAILED")
                self.assertIn("live firewall state", values["message"])
                self.assertNotIn("engine:enable", self.log_lines())
                self.assertNotIn("engine:disable", self.log_lines())

    def test_failed_disarm_from_tile_preserves_live_firewall(self):
        _, values = self.run_bridge("toggle", {"TEST_BOOT_CANNOT_DISABLE": "1"})
        self.assertEqual(values["operation"], "FAILED")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertNotIn("engine:disable", self.log_lines())

    def test_toggle_postcondition_failure_rolls_back_partial_install(self):
        self.state.write_text("INACTIVE\n")
        _, values = self.run_bridge("toggle", {"TEST_ENGINE_BAD_ENABLE": "1"})
        self.assertEqual(values["operation"], "FAILED")
        self.assertEqual(values["state"], "INACTIVE")
        self.assertIn("engine:disable", self.log_lines())

    def test_boot_toggles_and_refresh_share_one_session(self):
        for action, expected in (("boot-disable", "DISABLED"),
                                 ("boot-enable", "ENABLED"),
                                 ("vpn-refresh", "ENABLED")):
            result, values = self.run_bridge(action)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(values["operation"], "SUCCESS")
            self.assertEqual(values["boot"], expected)
            self.assertEqual(values["state"], "ACTIVE")

    def test_unavailable_counters_fall_back_to_rule_verification(self):
        result, values = self.run_bridge("inspect",
                                         {"TEST_ENGINE_ACTIVITY_FAIL": "1"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["root"], "GRANTED")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["boot"], "ENABLED")
        self.assertNotIn("ipv4_blocked", values)
        self.assertEqual(self.log_lines(), [
            "engine:activity", "engine:verify", "boot:status"
        ])

    def test_unknown_state_is_not_called_active(self):
        self.state.write_text("DEGRADED\n")
        result, values = self.run_bridge("inspect")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["state"], "DEGRADED")
        self.assertNotIn("ipv4_blocked", values)

    def test_enable_postcondition_mismatch_rolls_back_its_own_rules(self):
        self.state.write_text("INACTIVE\n")
        result, values = self.run_bridge("enable",
                                         {"TEST_ENGINE_BAD_ENABLE": "1"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["operation"], "FAILED")
        self.assertEqual(values["state"], "INACTIVE")
        self.assertEqual(self.log_lines(), [
            "engine:enable", "engine:activity", "boot:status",
            "engine:disable", "engine:verify"
        ])

    def test_failed_enable_never_removes_preexisting_rules(self):
        self.state.write_text("DEGRADED\n")
        result, values = self.run_bridge("enable",
                                         {"TEST_ENGINE_FAIL_ENABLE": "1"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(values["operation"], "FAILED")
        self.assertEqual(values["state"], "DEGRADED")
        self.assertNotIn("engine:disable", self.log_lines())
        self.assertEqual(self.state.read_text().strip(), "DEGRADED")

    def test_manual_exception_update_uses_one_verified_session(self):
        result, values = self.run_bridge('set-ports', args=('45678', 'none', 'experimental'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertIn('Experimental', values['message'])
        self.assertEqual(values['config_mode'], 'AUTOMATIC')
        self.assertEqual(self.log_lines(), ['engine:get-ports', 'engine:set-ports', 'engine:activity', 'boot:status'])

    def test_manual_exception_update_fails_closed_when_engine_refuses(self):
        result, values = self.run_bridge('set-ports', {'TEST_ENGINE_FAIL_MANUAL': '1'},
                                         args=('45678', '45679', 'experimental'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertNotIn('boot:disable', self.log_lines())

    def test_manual_exception_update_rejects_bad_ports_before_root(self):
        for args in (('0', 'none', 'experimental'), ('1',),
                     ('none', '65536', 'experimental'), ('abc', 'none', 'committed'),
                     ('00080', 'none', 'experimental'), ('1; echo pwned', 'none', 'committed'),
                     ('41476', 'none', 'invalid')):
            with self.subTest(args=args):
                result, values = self.run_bridge('set-ports', args=args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('root', values)
                self.assertEqual(self.log_lines(), [])

    def test_committed_udp_ports_survive_firewall_toggle_and_block_refresh(self):
        _, values = self.run_bridge('set-ports', args=('41476', '45567', 'committed'))
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['config_mode'], 'COMMITTED')
        self.assertEqual(values['committed_udp4'], '41476')
        self.assertEqual(values['committed_udp6'], '45567')
        self.assertTrue((self.config_dir / 'udp-committed.conf').exists())
        self.log.unlink(missing_ok=True)
        _, refreshed = self.run_bridge('vpn-refresh')
        self.assertEqual(refreshed['operation'], 'FAILED')
        self.assertNotIn('engine:refresh', self.log_lines())
        self.log.unlink(missing_ok=True)
        _, disabled = self.run_bridge('disable')
        self.assertEqual(disabled['operation'], 'SUCCESS')
        _, enabled = self.run_bridge('enable-restore')
        self.assertEqual(enabled['operation'], 'SUCCESS')
        self.assertEqual(enabled['config_mode'], 'COMMITTED')
        self.assertIn('engine:enable', self.log_lines())

    def test_experimental_udp_leaves_existing_committed_config_unchanged(self):
        _, committed = self.run_bridge('set-ports', args=('41476', '45567', 'committed'))
        self.assertEqual(committed['operation'], 'SUCCESS')
        original = (self.config_dir / 'udp-committed.conf').read_text()
        _, experiment = self.run_bridge('set-ports', args=('45678', '45679', 'experimental'))
        self.assertEqual(experiment['operation'], 'SUCCESS')
        self.assertEqual((self.config_dir / 'udp-committed.conf').read_text(), original)
        self.assertEqual(experiment['config_mode'], 'COMMITTED')

    def test_invalid_saved_config_is_reported_and_reset_safely(self):
        config = self.config_dir / 'udp-committed.conf'
        config.write_text('udp4=41476\nudp6=$(echo invalid)\n')
        _, inspection = self.run_bridge('inspect')
        self.assertEqual(inspection['state'], 'ACTIVE')
        self.assertEqual(inspection['config_mode'], 'DEGRADED')
        self.state.write_text('INACTIVE\n')
        _, blocked_enable = self.run_bridge('enable')
        self.assertEqual(blocked_enable['operation'], 'FAILED')
        self.assertEqual(blocked_enable['state'], 'INACTIVE')
        self.assertNotIn('engine:enable', self.log_lines())
        self.state.write_text('ACTIVE\n')
        _, fixed = self.run_bridge('use-auto')
        self.assertEqual(fixed['operation'], 'SUCCESS')
        self.assertEqual(fixed['config_mode'], 'AUTOMATIC')
        self.assertFalse(config.exists())

    def test_reset_after_experimental_update_works_without_committed_file(self):
        _, experimental = self.run_bridge('set-ports',
                                          args=('45678', '45679', 'experimental'))
        self.assertEqual(experimental['operation'], 'SUCCESS')
        self.assertEqual(experimental['config_mode'], 'AUTOMATIC')
        self.assertFalse((self.config_dir / 'udp-committed.conf').exists())
        self.log.unlink(missing_ok=True)
        _, result = self.run_bridge('use-auto')
        self.assertEqual(result['operation'], 'SUCCESS')
        self.assertEqual(result['config_mode'], 'AUTOMATIC')
        self.assertIn('engine:refresh', self.log_lines())
        self.assertFalse((self.config_dir / 'udp-committed.conf').exists())

    def test_use_auto_clears_committed_mode_after_verified_refresh(self):
        _, saved = self.run_bridge('set-ports', args=('41476', '45567', 'committed'))
        self.assertEqual(saved['config_mode'], 'COMMITTED')
        _, automatic = self.run_bridge('use-auto')
        self.assertEqual(automatic['operation'], 'SUCCESS')
        self.assertEqual(automatic['config_mode'], 'AUTOMATIC')
        self.assertFalse((self.config_dir / 'udp-committed.conf').exists())

    def test_rejects_unrecognized_commands(self):
        result, values = self.run_bridge("erase-everything")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("root", values)


if __name__ == "__main__":
    unittest.main()
