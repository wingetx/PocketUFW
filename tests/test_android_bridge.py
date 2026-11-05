"""The GUI bridge batches privileged work into one root session.

These tests use fake engine commands in a temporary directory and never
touch actual iptables, /data/adb, or device privileges.
"""
import os
from pathlib import Path
import shutil
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
        self.env['TEST_BRIDGE_RESET'] = str(self.root / 'reset-confirmation')
        self.args_log = self.root / 'engine-args'
        self.env['TEST_ENGINE_ARGS'] = str(self.args_log)
        fake_id = self.bin / "id"
        fake_id.write_text(
            "#!/bin/sh\n"
            "[ \"$1\" = '-u' ] && { echo 0; exit 0; }\n"
            "exec /usr/bin/id \"$@\"\n"
        )
        fake_id.chmod(0o755)
        # Android 15-style connected VPN owner records. Stubbed for every test
        # so host ADB or actual VPN apps can never affect regression outcomes.
        fake_dumpsys = self.bin / "dumpsys"
        fake_dumpsys.write_text(
            "#!/bin/sh\n"
            "[ \"$1\" = connectivity ] || exit 2\n"
            "for owner in $(printf '%s' \"${TEST_VPN_OWNERS:-}\" | tr , ' '); do\n"
            "  printf 'NetworkAgentInfo{network{104} ni{VPN CONNECTED extra: VPN:%s} created=x}\\n' \"$owner\"\n"
            "done\n"
            "printf '%s' \"${TEST_DUMPSYS_TEXT:-}\"\n"
        )
        fake_dumpsys.chmod(0o755)
        # Stubbed so the host's own interfaces can never affect outcomes.
        fake_ip = self.bin / "ip"
        fake_ip.write_text(
            "#!/bin/sh\n"
            "[ \"$1\" = -o ] || exit 2\n"
            "[ \"${TEST_IP_FAIL:-0}\" = 0 ] || exit 1\n"
            "case \"$2\" in\n"
            "  link) printf '%s' \"${TEST_IP_LINK:-}\" ;;\n"
            "  addr) printf '%s' \"${TEST_IP_ADDR:-}\" ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n"
        )
        fake_ip.chmod(0o755)

        (self.engine / "pocketufw").write_text(
            "#!/bin/sh\n"
            "echo \"engine:$1\" >> \"$TEST_BRIDGE_LOG\"\n"
            "echo \"$*\" >> \"$TEST_ENGINE_ARGS\"\n"
            "trap '[ \"${TEST_ENGINE_BREAK_AFTER:-}\" != \"$1\" ] || echo DEGRADED > \"$TEST_ENGINE_STATE\"' 0\n"
            "case \"$1\" in\n"
            "verify) cat \"$TEST_ENGINE_STATE\"; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "activity) [ \"$TEST_ENGINE_ACTIVITY_FAIL\" = 1 ] && exit 9; "
            "current=$(cat \"$TEST_ENGINE_STATE\"); echo \"state=$current\"; "
            "[ \"${TEST_ENGINE_ACTIVITY_LEAK:-0}\" != 1 ] || echo ipv4_blocked=41; "
            "[ \"$current\" = ACTIVE ] || exit 4; "
            "echo ipv4_blocked=41; echo ipv6_blocked=8; "
            "echo ipv4_blocked_bytes=3200; echo ipv6_blocked_bytes=600; "
            "echo ipv4_established_replies=900; echo ipv6_established_replies=25 ;;\n"
            "enable) [ \"$TEST_ENGINE_FAIL_ENABLE\" = 1 ] && exit 7; "
            "if [ \"$TEST_ENGINE_BAD_ENABLE\" = 1 ]; "
            "then echo DEGRADED > \"$TEST_ENGINE_STATE\"; "
            "else echo ACTIVE > \"$TEST_ENGINE_STATE\"; fi; "
            "if [ \"${TEST_ENGINE_PROBE_FAILED:-0}\" = 1 ]; then "
            "echo 'PocketUFW: enabled.'; echo tailscale_probe=FAILED; echo 'NOTE: probe failed'; fi ;;\n"
            "disable) [ \"${TEST_ENGINE_FAIL_DISABLE:-0}\" = 1 ] && exit 9; "
            "[ \"${TEST_ENGINE_BAD_DISABLE:-0}\" = 1 ] || echo INACTIVE > \"$TEST_ENGINE_STATE\" ;;\n"
            "get-ports) [ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] || exit 4; "
            "echo \"udp4=${TEST_LIVE_UDP4:-none}\"; echo \"udp6=${TEST_LIVE_UDP6:-none}\" ;;\n"
            "refresh) [ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] || exit 9; "
            "[ \"$TEST_ENGINE_REFRESH_FAIL\" = 1 ] && exit 7; "
            "printf 'refresh_result=%s\\n' \"${TEST_ENGINE_REFRESH_RESULT:-UNCHANGED}\" ;;\n"
            "reset-counters) [ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] || exit 6; "
            "[ \"$TEST_ENGINE_FAIL_RESET\" = 1 ] && exit 9; "
            "echo yes > \"$TEST_BRIDGE_RESET\" ;;\n"
            "set-ports) [ \"$TEST_ENGINE_FAIL_MANUAL\" = 1 ] && exit 7; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] ;;\n"
            "*) exit 8 ;;\n"
            "esac\n"
        )
        (self.engine / "bootctl").write_text(
            "#!/bin/sh\n"
            "echo \"boot:$1\" >> \"$TEST_BRIDGE_LOG\"\n"
            "case \"$1\" in\n"
            "status) [ \"${TEST_BOOT_STATUS_FAIL:-0}\" = 1 ] && exit 3; "
            "echo \"boot=$(cat \"$TEST_BOOT_STATE\")\" ;;\n"
            "enable) [ \"$TEST_BOOT_CANNOT_ENABLE\" = 1 ] && exit 7; "
            "[ \"$(cat \"$TEST_ENGINE_STATE\")\" = ACTIVE ] || exit 5; "
            "echo \"${TEST_BOOT_ENABLE_RESULT:-ENABLED}\" > \"$TEST_BOOT_STATE\"; "
            "[ \"${TEST_BOOT_ENABLE_BREAKS_ENGINE:-0}\" = 1 ] && echo DEGRADED > \"$TEST_ENGINE_STATE\"; : ;;\n"
            "disable) [ \"$TEST_BOOT_CANNOT_DISABLE\" = 1 ] && exit 7; "
            "echo \"${TEST_BOOT_DISABLE_RESULT:-DISABLED}\" > \"$TEST_BOOT_STATE\" ;;\n"
            "*) exit 8 ;;\n"
            "esac\n"
        )
        (self.engine / "rules-report").write_text(
            "#!/bin/sh\n"
            "[ \"$TEST_RULE_REPORT_FAIL\" = 1 ] && exit 9\n"
            "echo input_policy4=ACCEPT\n"
            "[ \"${TEST_RULE_REPORT_PARTIAL:-0}\" = 1 ] && exit 0\n"
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

    def test_android_vpn_owner_is_read_in_existing_root_inspection(self):
        result, values = self.run_bridge('inspect', {
            'TEST_VPN_OWNERS': 'ch.protonvpn.android'
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values.get('vpn_owner'), 'ch.protonvpn.android')
        self.assertEqual(self.log_lines(), ['engine:activity', 'boot:status'])

    def test_tailscale_is_identified_by_its_vpn_owner_not_exit_node(self):
        _, values = self.run_bridge('inspect', {
            'TEST_VPN_OWNERS': 'com.tailscale.ipn'
        })
        self.assertEqual(values.get('vpn_owner'), 'com.tailscale.ipn')

    def test_vpn_owner_is_not_guessed_if_multiple_tunnels_are_reported(self):
        _, values = self.run_bridge('inspect', {
            'TEST_VPN_OWNERS': 'com.tailscale.ipn,ch.protonvpn.android'
        })
        self.assertEqual(values.get('vpn_owner'), '')

    def test_vpn_owner_absent_does_not_fake_an_installed_provider(self):
        _, values = self.run_bridge('inspect')
        self.assertEqual(values.get('vpn_owner'), '')

    def test_counter_refresh_does_not_query_vpn_identity(self):
        result, values = self.run_bridge('counters', {
            'TEST_VPN_OWNERS': 'ch.protonvpn.android'
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('vpn_owner', values)
        self.assertEqual(self.log_lines(), ['engine:activity'])

    def test_counter_refresh_is_read_only_and_skips_heavy_dashboard_work(self):
        result, values = self.run_bridge("counters")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values["root"], "GRANTED")
        self.assertEqual(values["state"], "ACTIVE")
        self.assertEqual(values["ipv4_blocked"], "41")
        self.assertEqual(values["ipv6_blocked"], "8")
        self.assertEqual(values["ipv4_established_replies"], "900")
        self.assertEqual(values["ipv6_established_replies"], "25")
        self.assertNotIn("boot", values)
        self.assertNotIn("rules_report", values)
        self.assertNotIn("operation", values)
        self.assertEqual(self.log_lines(), ["engine:activity"])

    def test_counter_refresh_fails_without_synthetic_counts_when_unavailable(self):
        result, values = self.run_bridge("counters",
                                         {"TEST_ENGINE_ACTIVITY_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", values)
        self.assertNotIn("ipv4_blocked", values)
        self.assertNotIn("root", values)
        self.assertEqual(self.log_lines(), ["engine:activity"])

    def test_counter_refresh_inactive_fails_closed_without_mutating_rules(self):
        self.state.write_text("INACTIVE\n")
        result, values = self.run_bridge("counters")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", values)
        self.assertNotIn("ipv6_blocked", values)
        self.assertEqual(self.log_lines(), ["engine:activity"])
        self.assertEqual(self.state.read_text(), "INACTIVE\n")

    def test_counter_refresh_rejects_arguments_before_root(self):
        result, values = self.run_bridge("counters", args=("disable",))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log_lines(), [])
        self.assertNotIn("root", values)

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

    def test_degraded_firewall_still_shows_the_rules_it_really_has(self):
        self.state.write_text("DEGRADED\n")
        _, values = self.run_bridge("inspect")
        self.assertEqual(values["state"], "DEGRADED")
        self.assertEqual(values["rules_report"], "READY")
        self.assertIn("-j DROP", values["main4_01"])

    def test_inactive_firewall_has_no_rule_report(self):
        self.state.write_text("INACTIVE\n")
        _, values = self.run_bridge("inspect")
        self.assertNotIn("rules_report", values)
        self.assertNotIn("main4_01", values)

    def test_counters_are_shown_only_for_an_active_firewall(self):
        for state in ("DEGRADED", "INACTIVE"):
            with self.subTest(state=state):
                self.state.write_text(state + "\n")
                _, values = self.run_bridge("inspect", {"TEST_ENGINE_ACTIVITY_LEAK": "1"})
                self.assertEqual(values["state"], state)
                self.assertNotIn("ipv4_blocked", values)

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

    def test_disable_succeeds_without_magisk_boot_support(self):
        # On KernelSU or APatch there is no hook, so status stays UNSUPPORTED.
        self.boot_state.write_text("UNSUPPORTED\n")
        (self.engine / "bootctl").write_text(
            "#!/bin/sh\n"
            "case \"$1\" in status) echo boot=UNSUPPORTED ;; disable) : ;; *) exit 8 ;; esac\n"
        )
        _, values = self.run_bridge("disable")
        self.assertEqual(values.get("operation"), "SUCCESS")
        self.assertEqual(values.get("state"), "INACTIVE")

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

    def test_vpn_refresh_reports_no_change_when_listeners_match(self):
        result, values = self.run_bridge('vpn-refresh',
                                         {'TEST_ENGINE_REFRESH_RESULT': 'UNCHANGED'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertIn('already up to date', values['message'])
        self.assertIn('No changes needed', values['message'])
        self.assertEqual(self.log_lines(), ['engine:refresh', 'engine:activity', 'boot:status'])

    def test_vpn_refresh_reports_an_actual_update(self):
        result, values = self.run_bridge('vpn-refresh',
                                         {'TEST_ENGINE_REFRESH_RESULT': 'UPDATED'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertIn('exceptions updated', values['message'])
        self.assertNotIn('No changes needed', values['message'])

    def test_vpn_refresh_unknown_result_never_claims_success(self):
        _, values = self.run_bridge('vpn-refresh',
                                     {'TEST_ENGINE_REFRESH_RESULT': 'AMBIGUOUS'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('could not be verified', values['message'])

    def test_vpn_refresh_failed_engine_never_claims_success(self):
        _, values = self.run_bridge('vpn-refresh', {'TEST_ENGINE_REFRESH_FAIL': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('could not be refreshed', values['message'])

    def test_reset_counters_uses_one_verified_root_action(self):
        result, values = self.run_bridge('reset-counters')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values.get('operation'), 'SUCCESS')
        self.assertEqual(values.get('state'), 'ACTIVE')
        self.assertEqual(values.get('boot'), 'ENABLED')
        self.assertIn('counters reset', values.get('message', '').lower())
        self.assertTrue((self.root/'reset-confirmation').exists())
        self.assertIn('engine:reset-counters', self.log.read_text())

    def test_reset_counters_failure_keeps_firewall_active(self):
        result, values = self.run_bridge('reset-counters',
                                         {'TEST_ENGINE_FAIL_RESET': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values.get('operation'), 'FAILED')
        self.assertEqual(values.get('state'), 'ACTIVE')
        self.assertFalse((self.root/'reset-confirmation').exists())

    def test_reset_counters_refuses_inactive(self):
        self.state.write_text('INACTIVE\n')
        result, values = self.run_bridge('reset-counters')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values.get('operation'), 'FAILED')
        self.assertEqual(values.get('state'), 'INACTIVE')
        self.assertFalse((self.root/'reset-confirmation').exists())

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
        self.args_log.unlink(missing_ok=True)
        _, enabled = self.run_bridge('enable')
        self.assertEqual(enabled['operation'], 'SUCCESS')
        self.assertEqual(enabled['state'], 'ACTIVE')
        self.assertEqual(enabled['config_mode'], 'DEGRADED')
        self.assertEqual(enabled['message'], self.UNREADABLE_POLICY)
        self.assertEqual(self.engine_args('enable'), ['enable'])
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

    UNREADABLE_POLICY = 'Firewall enabled without saved UDP exceptions because the saved settings could not be read.'
    PROBE_FAILED = ('Firewall enabled. Tailscale ports could not be verified, so no VPN exception was added. '
                    'Use Refresh Tailscale ports later.')
    ALREADY_ON = 'Firewall is already on.'
    NOT_TOGGLED = 'Firewall state had changed, so nothing was toggled. Status updated.'
    NOT_REMOVED = 'Firewall state had changed, so nothing was removed. Status updated.'
    CONFLICT_OFF = 'Firewall disabled. Another module owns the boot hook path, so it was left alone.'
    POSTCONDITION = 'Operation postcondition not verified; inspect firewall state.'

    def engine_args(self, command=None):
        lines = self.args_log.read_text().splitlines() if self.args_log.exists() else []
        return [line for line in lines if command is None or line.split()[0] == command]

    def corrupt_saved_config(self):
        (self.config_dir / 'udp-committed.conf').write_text('udp4=41476\nudp6=$(echo invalid)\n')

    def fail_config_command(self, command):
        """Keep the real udp-config except for one failing subcommand."""
        real = self.engine / 'udp-config.real'
        shutil.copy(self.engine / 'udp-config', real)
        (self.engine / 'udp-config').write_text(
            f'#!/bin/sh\n[ "$1" = {command} ] && exit 7\nexec sh "{real}" "$@"\n')

    # --- Enabling never depends on Tailscale or on saved ports. ---

    def test_invalid_saved_policy_still_enables_without_exceptions(self):
        for action, boot in (('enable', 'DISABLED'), ('toggle', 'DISABLED'),
                             ('enable-restore', 'ENABLED'), ('toggle-restore', 'ENABLED')):
            with self.subTest(action=action):
                self.state.write_text('INACTIVE\n')
                self.boot_state.write_text('DISABLED\n')
                self.corrupt_saved_config()
                self.args_log.unlink(missing_ok=True)
                _, values = self.run_bridge(action)
                self.assertEqual(values['operation'], 'SUCCESS')
                self.assertEqual(values['message'], self.UNREADABLE_POLICY)
                self.assertEqual(values['state'], 'ACTIVE')
                self.assertEqual(values['boot'], boot)
                self.assertEqual(values['config_mode'], 'DEGRADED')
                self.assertEqual(self.engine_args('enable'), ['enable'])

    def test_unavailable_saved_config_directory_still_enables(self):
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable', {'POCKETUFW_CONFIG_DIR': str(self.root / 'missing')})
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['message'], self.UNREADABLE_POLICY)
        self.assertEqual(self.engine_args('enable'), ['enable'])

    def test_probe_failure_is_explained_and_counts_as_success(self):
        for action, boot in (('enable', 'DISABLED'), ('toggle', 'DISABLED'),
                             ('enable-restore', 'ENABLED'), ('toggle-restore', 'ENABLED')):
            with self.subTest(action=action):
                self.state.write_text('INACTIVE\n')
                self.boot_state.write_text('DISABLED\n')
                self.args_log.unlink(missing_ok=True)
                _, values = self.run_bridge(action, {'TEST_ENGINE_PROBE_FAILED': '1'})
                self.assertEqual(values['operation'], 'SUCCESS')
                self.assertEqual(values['message'], self.PROBE_FAILED)
                self.assertEqual(values['state'], 'ACTIVE')
                self.assertEqual(values['boot'], boot)
                self.assertEqual(self.engine_args('enable'), ['enable --auto-tailscale'])

    def test_plain_enable_messages_are_unchanged(self):
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable')
        self.assertEqual(values['message'], 'Firewall enabled.')
        self.assertEqual(self.engine_args('enable'), ['enable --auto-tailscale'])
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable-restore')
        self.assertEqual(values['message'], 'Firewall enabled; boot restoration resumed.')

    def test_committed_policy_passes_only_the_saved_ports(self):
        for saved, expected in ((('41476', '45567'), 'enable --tailscale-udp4 41476 --tailscale-udp6 45567'),
                                (('41476', 'none'), 'enable --tailscale-udp4 41476'),
                                (('none', '45567'), 'enable --tailscale-udp6 45567'),
                                (('none', 'none'), 'enable')):
            with self.subTest(saved=saved):
                (self.config_dir / 'udp-committed.conf').write_text(f'udp4={saved[0]}\nudp6={saved[1]}\n')
                self.state.write_text('INACTIVE\n')
                self.args_log.unlink(missing_ok=True)
                _, values = self.run_bridge('enable')
                self.assertEqual(values['operation'], 'SUCCESS')
                self.assertEqual(values['message'], 'Firewall enabled.')
                self.assertEqual(self.engine_args('enable'), [expected])

    def test_losing_a_concurrent_enable_is_success_not_failure(self):
        # The engine refuses because another request already installed the rules.
        _, values = self.run_bridge('enable', {'TEST_ENGINE_FAIL_ENABLE': '1'})
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['message'], self.ALREADY_ON)
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertNotIn('engine:disable', self.log_lines())

    def test_losing_a_concurrent_enable_never_tears_the_winner_down(self):
        # It did not create those rules, so even a failed postcondition must not remove them.
        self.boot_state.write_text('DISABLED\n')
        _, values = self.run_bridge('enable', {'TEST_ENGINE_FAIL_ENABLE': '1', 'TEST_ENGINE_BREAK_AFTER': 'verify'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertNotIn('engine:disable', self.log_lines())

    def test_losing_a_concurrent_enable_restore_still_rearms_boot(self):
        self.boot_state.write_text('DISABLED\n')
        _, values = self.run_bridge('enable-restore', {'TEST_ENGINE_FAIL_ENABLE': '1'})
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['boot'], 'ENABLED')
        self.assertEqual(values['message'], self.ALREADY_ON)

    def test_losing_a_concurrent_enable_restore_reports_a_failed_rearm(self):
        self.boot_state.write_text('DISABLED\n')
        _, values = self.run_bridge('enable-restore', {'TEST_ENGINE_FAIL_ENABLE': '1',
                                                       'TEST_BOOT_CANNOT_ENABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('could not be rearmed', values['message'])

    def test_enable_failure_is_a_failure_when_nothing_else_won(self):
        for state in ('INACTIVE', 'DEGRADED', 'UNEXPECTED'):
            with self.subTest(state=state):
                self.state.write_text(state + '\n')
                _, values = self.run_bridge('enable', {'TEST_ENGINE_FAIL_ENABLE': '1'})
                self.assertEqual(values['operation'], 'FAILED')
                self.assertIn('Cannot enable firewall', values['message'])

    # --- The tile states what it showed. ---

    def test_toggle_state_argument_is_validated_before_root(self):
        for action in ('toggle', 'toggle-restore'):
            for bad in ('active', 'DEGRADED', '', 'ACTIVE ', 'ACTIVE;id', 'UNKNOWN'):
                with self.subTest(action=action, argument=bad):
                    result, values = self.run_bridge(action, args=(bad,))
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn('root', values)
            result, values = self.run_bridge(action, args=('ACTIVE', 'INACTIVE'))
            self.assertEqual(result.returncode, 2)
        self.assertEqual(self.log_lines(), [])

    def test_only_toggles_accept_a_state_argument(self):
        for action in ('inspect', 'enable', 'disable', 'enable-restore', 'remove-partial', 'counters'):
            with self.subTest(action=action):
                result, values = self.run_bridge(action, args=('ACTIVE',))
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('root', values)
        self.assertEqual(self.log_lines(), [])

    def test_toggle_with_matching_state_toggles_in_both_directions(self):
        for action in ('toggle', 'toggle-restore'):
            with self.subTest(action=action):
                self.state.write_text('ACTIVE\n')
                _, values = self.run_bridge(action, args=('ACTIVE',))
                self.assertEqual(values['operation'], 'SUCCESS')
                self.assertEqual(values['state'], 'INACTIVE')
                _, values = self.run_bridge(action, args=('INACTIVE',))
                self.assertEqual(values['operation'], 'SUCCESS')
                self.assertEqual(values['state'], 'ACTIVE')

    def test_toggle_with_stale_tile_state_changes_nothing(self):
        cases = (('ACTIVE', 'INACTIVE'), ('INACTIVE', 'ACTIVE'), ('ACTIVE', 'DEGRADED'),
                 ('INACTIVE', 'DEGRADED'), ('ACTIVE', 'UNEXPECTED'))
        for action in ('toggle', 'toggle-restore'):
            for shown, live in cases:
                with self.subTest(action=action, shown=shown, live=live):
                    self.state.write_text(live + '\n')
                    self.log.unlink(missing_ok=True)
                    _, values = self.run_bridge(action, args=(shown,))
                    self.assertEqual(values['operation'], 'FAILED')
                    self.assertEqual(values['message'], self.NOT_TOGGLED)
                    self.assertEqual(self.state.read_text().strip(), live)
                    for call in ('engine:enable', 'engine:disable', 'boot:enable', 'boot:disable'):
                        self.assertNotIn(call, self.log_lines())
                    # It still reports the state it found.
                    self.assertEqual(values['state'], live if live != 'UNEXPECTED' else 'UNKNOWN')

    # --- Remove partial: only ever on a firewall that is partial right now. ---

    def test_remove_partial_runs_the_disable_path_on_degraded(self):
        self.state.write_text('DEGRADED\n')
        result, values = self.run_bridge('remove-partial')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['state'], 'INACTIVE')
        self.assertEqual(values['boot'], 'DISABLED')
        self.assertEqual(values['previous_boot'], 'ENABLED')
        self.assertEqual(self.log_lines(), [
            'engine:verify', 'boot:status', 'boot:disable', 'engine:disable', 'engine:activity', 'boot:status'
        ])

    def test_remove_partial_changes_nothing_on_any_other_state(self):
        for live, reported in (('ACTIVE', 'ACTIVE'), ('INACTIVE', 'INACTIVE'), ('UNEXPECTED', 'UNKNOWN')):
            with self.subTest(live=live):
                self.state.write_text(live + '\n')
                self.log.unlink(missing_ok=True)
                _, values = self.run_bridge('remove-partial')
                self.assertEqual(values['operation'], 'FAILED')
                self.assertEqual(values['message'], self.NOT_REMOVED)
                self.assertEqual(values['state'], reported)
                self.assertNotIn('engine:disable', self.log_lines())
                self.assertNotIn('boot:disable', self.log_lines())
                self.assertEqual(self.state.read_text().strip(), live)

    def test_remove_partial_keeps_the_firewall_if_disarm_fails(self):
        self.state.write_text('DEGRADED\n')
        _, values = self.run_bridge('remove-partial', {'TEST_BOOT_CANNOT_DISABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'DEGRADED')
        self.assertNotIn('engine:disable', self.log_lines())

    def test_remove_partial_takes_no_arguments(self):
        result, values = self.run_bridge('remove-partial', args=('DEGRADED',))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('root', values)

    # --- STALE boot copies stay inside the bridge. ---

    def test_inspect_refreshes_stale_copies_once_when_active(self):
        self.boot_state.write_text('STALE\n')
        result, values = self.run_bridge('inspect')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['boot'], 'ENABLED')
        self.assertEqual(values['operation'], 'NONE')
        self.assertNotIn('STALE', result.stdout)
        self.assertEqual(self.log_lines(), ['engine:activity', 'boot:status', 'boot:enable', 'boot:status'])

    def test_stale_copies_are_not_refreshed_unless_active(self):
        for state in ('INACTIVE', 'DEGRADED'):
            with self.subTest(state=state):
                self.state.write_text(state + '\n')
                self.boot_state.write_text('STALE\n')
                self.log.unlink(missing_ok=True)
                result, values = self.run_bridge('inspect')
                self.assertEqual(values['boot'], 'ENABLED')
                self.assertNotIn('STALE', result.stdout)
                self.assertNotIn('boot:enable', self.log_lines())

    def test_failed_refresh_of_stale_copies_is_degraded_not_stale(self):
        self.boot_state.write_text('STALE\n')
        result, values = self.run_bridge('inspect', {'TEST_BOOT_CANNOT_ENABLE': '1'})
        self.assertEqual(values['boot'], 'DEGRADED')
        self.assertNotIn('STALE', result.stdout)
        self.assertEqual(self.log_lines().count('boot:enable'), 1)

    def test_refresh_that_leaves_copies_stale_is_degraded_and_not_retried(self):
        self.boot_state.write_text('STALE\n')
        result, values = self.run_bridge('inspect', {'TEST_BOOT_ENABLE_RESULT': 'STALE'})
        self.assertEqual(values['boot'], 'DEGRADED')
        self.assertNotIn('STALE', result.stdout)
        self.assertEqual(self.log_lines().count('boot:enable'), 1)

    def test_stale_refresh_touches_only_boot_files(self):
        self.boot_state.write_text('STALE\n')
        self.run_bridge('inspect')
        self.assertEqual(self.engine_args(), ['activity'])

    def test_no_action_ever_prints_stale(self):
        actions = (('inspect', ()), ('enable', ()), ('enable-restore', ()), ('disable', ()), ('toggle', ()),
                   ('toggle-restore', ()), ('boot-enable', ()), ('boot-disable', ()), ('vpn-refresh', ()),
                   ('reset-counters', ()), ('use-auto', ()), ('remove-partial', ()),
                   ('set-ports', ('45678', 'none', 'experimental')),
                   ('set-ports', ('45678', 'none', 'committed')))
        for action, args in actions:
            for state in ('ACTIVE', 'INACTIVE', 'DEGRADED'):
                with self.subTest(action=action, args=args, state=state):
                    self.state.write_text(state + '\n')
                    self.boot_state.write_text('STALE\n')
                    (self.config_dir / 'udp-committed.conf').unlink(missing_ok=True)
                    result, values = self.run_bridge(action, args=args)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn('STALE', result.stdout)
                    self.assertIn(values['previous_boot'], ('UNKNOWN', 'ENABLED'))

    def test_disable_remembers_stale_as_enabled_opt_in(self):
        self.boot_state.write_text('STALE\n')
        _, values = self.run_bridge('disable')
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['previous_boot'], 'ENABLED')
        self.assertEqual(values['boot'], 'DISABLED')
        self.assertEqual(values['state'], 'INACTIVE')

    def test_committed_ports_treat_stale_as_enabled_and_refresh_the_snapshot(self):
        self.boot_state.write_text('STALE\n')
        _, values = self.run_bridge('set-ports', args=('41476', '45567', 'committed'))
        self.assertEqual(values['operation'], 'SUCCESS')
        self.assertEqual(values['boot'], 'ENABLED')
        self.assertIn('boot:enable', self.log_lines())

    # --- Off switch with someone else's boot hook. ---

    def test_off_switch_works_when_another_module_owns_the_hook(self):
        for action in ('disable', 'toggle'):
            with self.subTest(action=action):
                self.state.write_text('ACTIVE\n')
                self.boot_state.write_text('CONFLICT\n')
                self.log.unlink(missing_ok=True)
                # A real bootctl disable refuses here, and must not be what decides.
                _, values = self.run_bridge(action, {'TEST_BOOT_CANNOT_DISABLE': '1'})
                self.assertEqual(values['operation'], 'SUCCESS')
                self.assertEqual(values['message'], self.CONFLICT_OFF)
                self.assertEqual(values['state'], 'INACTIVE')
                self.assertEqual(values['boot'], 'CONFLICT')
                self.assertEqual(values['previous_boot'], 'CONFLICT')
                self.assertIn('engine:disable', self.log_lines())
                self.assertNotIn('boot:disable', self.log_lines())

    def test_conflict_off_switch_reports_engine_failure(self):
        self.boot_state.write_text('CONFLICT\n')
        _, values = self.run_bridge('disable', {'TEST_ENGINE_FAIL_DISABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'ACTIVE')

    def test_conflict_off_switch_verifies_the_firewall_is_really_gone(self):
        self.boot_state.write_text('CONFLICT\n')
        _, values = self.run_bridge('disable', {'TEST_ENGINE_BAD_DISABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['message'], self.POSTCONDITION)

    def test_conflict_postcondition_requires_conflict_to_still_stand(self):
        # bootctl status answered CONFLICT, then something else by the final read.
        (self.engine / 'bootctl').write_text(
            '#!/bin/sh\n'
            'echo "boot:$1" >> "$TEST_BRIDGE_LOG"\n'
            'if [ "$(grep -c boot:status "$TEST_BRIDGE_LOG")" -le 1 ]; then echo boot=CONFLICT; else echo boot=DEGRADED; fi\n')
        _, values = self.run_bridge('disable')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['message'], self.POSTCONDITION)
        self.assertEqual(values['boot'], 'DEGRADED')

    def test_other_disarm_failures_leave_the_firewall_on(self):
        for boot in ('ENABLED', 'DEGRADED', 'DISABLED', 'UNSUPPORTED'):
            with self.subTest(boot=boot):
                self.state.write_text('ACTIVE\n')
                self.boot_state.write_text(boot + '\n')
                self.log.unlink(missing_ok=True)
                _, values = self.run_bridge('disable', {'TEST_BOOT_CANNOT_DISABLE': '1'})
                self.assertEqual(values['operation'], 'FAILED')
                self.assertIn('firewall left unchanged', values['message'])
                self.assertEqual(values['state'], 'ACTIVE')
                self.assertNotIn('engine:disable', self.log_lines())

    def test_unknown_boot_status_still_tries_to_disarm_first(self):
        _, values = self.run_bridge('disable', {'TEST_BOOT_STATUS_FAIL': '1'})
        self.assertEqual(values['previous_boot'], 'UNKNOWN')
        self.assertLess(self.log_lines().index('boot:disable'), self.log_lines().index('engine:disable'))

    # --- Wording. ---

    def test_committed_refusal_names_the_editor_the_app_really_has(self):
        (self.config_dir / 'udp-committed.conf').write_text('udp4=41476\nudp6=none\n')
        _, values = self.run_bridge('vpn-refresh')
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Use the VPN UDP exceptions editor', values['message'])
        self.assertNotIn('Status editor', values['message'])
        self.assertNotIn('Status editor', (PROJECT / 'android-bridge').read_text())

    # --- Interfaces PocketUFW's hooks do not cover. ---

    IP_LINK = (
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n'
        '2: dummy0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/ether 0a:01:02:03:04:05 brd ff:ff:ff:ff:ff:ff\n'
        '13: rmnet_data0@rmnet_ipa0: <UP,LOWER_UP> mtu 1500 qdisc mq state UNKNOWN mode DEFAULT group default qlen 1000\\    link/[519]\n'
        '25: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc pfifo_fast state UNKNOWN mode DEFAULT group default qlen 500\\    link/none\n'
        '31: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DORMANT group default qlen 3000\\    link/ether 0a:01:02:03:04:06 brd ff:ff:ff:ff:ff:ff\n'
        '33: v4-rmnet_data0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 500\\    link/none\n'
        '40: rndis0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\\    link/ether 0a:01:02:03:04:07 brd ff:ff:ff:ff:ff:ff\n'
        '41: ccmni0@ccci: <UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/[519]\n'
        '42: usb0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default qlen 1000\\    link/ether 0a:01:02:03:04:08 brd ff:ff:ff:ff:ff:ff\n'
        '43: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether 0a:01:02:03:04:09 brd ff:ff:ff:ff:ff:ff\n'
        '44: p2p0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether 0a:01:02:03:04:0a brd ff:ff:ff:ff:ff:ff\n'
    )
    IP_ADDR = (
        '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n'
        '1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever\n'
        '2: dummy0    inet 192.0.2.9/32 scope global dummy0\\       valid_lft forever preferred_lft forever\n'
        '13: rmnet_data0    inet6 2001:db8::1/64 scope global dynamic mngtmpaddr noprefixroute \\       valid_lft 7000sec preferred_lft 7000sec\n'
        '25: tun0    inet 100.64.0.1/32 scope global tun0\\       valid_lft forever preferred_lft forever\n'
        '31: wlan0    inet 192.168.1.5/24 brd 192.168.1.255 scope global wlan0\\       valid_lft forever preferred_lft forever\n'
        '33: v4-rmnet_data0    inet 192.0.0.4/32 scope global v4-rmnet_data0\\       valid_lft forever preferred_lft forever\n'
        '40: rndis0    inet 192.168.42.129/24 brd 192.168.42.255 scope global rndis0\\       valid_lft forever preferred_lft forever\n'
        '40: rndis0    inet6 2001:db8:2::1/64 scope global \\       valid_lft forever preferred_lft forever\n'
        '41: ccmni0    inet6 2001:db8:3::1/64 scope global \\       valid_lft forever preferred_lft forever\n'
        '42: usb0    inet 192.168.50.1/24 scope global usb0\\       valid_lft forever preferred_lft forever\n'
        '43: eth0    inet 192.168.60.1/24 scope global eth0\\       valid_lft forever preferred_lft forever\n'
        '44: p2p0    inet6 fe80::1/64 scope link \\       valid_lft forever preferred_lft forever\n'
    )

    def test_uncovered_interfaces_are_listed_from_real_phone_output(self):
        result, values = self.run_bridge('inspect', {'TEST_IP_LINK': self.IP_LINK, 'TEST_IP_ADDR': self.IP_ADDR})
        self.assertEqual(result.returncode, 0, result.stderr)
        # usb0 has NO-CARRIER but is administratively UP; eth0 is down; p2p0 has
        # only a link-local address; the rest are hooked or excluded by name.
        self.assertEqual(values['uncovered_ifaces'].split(','), ['rndis0', 'ccmni0', 'usb0'])

    def test_covered_interfaces_are_not_listed(self):
        link = ''.join(line for line in self.IP_LINK.splitlines(True)
                       if line.split()[1].split('@')[0].rstrip(':') in
                       ('lo', 'dummy0', 'rmnet_data0', 'tun0', 'wlan0', 'v4-rmnet_data0'))
        _, values = self.run_bridge('inspect', {'TEST_IP_LINK': link, 'TEST_IP_ADDR': self.IP_ADDR})
        self.assertEqual(values['uncovered_ifaces'], '')

    def test_names_merely_containing_a_hooked_prefix_are_uncovered(self):
        link = ('5: swlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\\    link/ether 0a:01:02:03:04:0b\n'
                '6: lo0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\\    link/ether 0a:01:02:03:04:0c\n')
        addr = ('5: swlan0    inet 192.168.43.1/24 scope global swlan0\\       valid_lft forever\n'
                '6: lo0    inet 192.168.44.1/24 scope global lo0\\       valid_lft forever\n')
        _, values = self.run_bridge('inspect', {'TEST_IP_LINK': link, 'TEST_IP_ADDR': addr})
        self.assertEqual(values['uncovered_ifaces'], 'swlan0,lo0')

    def test_uncovered_interfaces_are_read_in_every_full_report(self):
        for action in ('inspect', 'enable', 'disable', 'boot-enable', 'vpn-refresh'):
            with self.subTest(action=action):
                _, values = self.run_bridge(action, {'TEST_IP_LINK': self.IP_LINK, 'TEST_IP_ADDR': self.IP_ADDR})
                self.assertEqual(values['uncovered_ifaces'].split(','), ['rndis0', 'ccmni0', 'usb0'])

    def test_counter_refresh_does_not_query_interfaces(self):
        result, values = self.run_bridge('counters', {'TEST_IP_LINK': self.IP_LINK, 'TEST_IP_ADDR': self.IP_ADDR})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('uncovered_ifaces', values)

    def test_uncovered_interfaces_are_empty_when_ip_fails(self):
        result, values = self.run_bridge('inspect', {'TEST_IP_FAIL': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['uncovered_ifaces'], '')
        self.assertEqual(values['state'], 'ACTIVE')

    def test_uncovered_interfaces_are_empty_when_ip_is_missing(self):
        tools = self.root / 'tools'
        tools.mkdir()
        for tool in ('dirname', 'sed', 'sort', 'tail', 'grep', 'awk', 'cat', 'tr', 'timeout', 'sh', 'wc', 'rm', 'mv', 'chmod'):
            (tools / tool).symlink_to(shutil.which(tool))
        (tools / 'id').symlink_to(self.bin / 'id')
        p = subprocess.run(['/bin/sh', str(self.engine / 'android-bridge'), 'inspect'], capture_output=True, text=True,
                           env={**self.env, 'PATH': str(tools), 'TEST_ENGINE_ACTIVITY_FAIL': '0'}, timeout=9)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('uncovered_ifaces=\n', p.stdout)
        self.assertIn('state=ACTIVE\n', p.stdout)

    # --- Postconditions: every SUCCESS must be proven by the final read. ---

    def assert_postcondition_failed(self, values):
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['message'], self.POSTCONDITION)

    def test_enable_postcondition(self):
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable', {'TEST_ENGINE_BAD_ENABLE': '1'})
        self.assert_postcondition_failed(values)

    def test_enable_restore_postcondition_requires_firewall(self):
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable-restore', {'TEST_BOOT_ENABLE_BREAKS_ENGINE': '1'})
        self.assert_postcondition_failed(values)
        self.assertEqual(values['state'], 'DEGRADED')

    def test_enable_restore_postcondition_requires_boot(self):
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable-restore', {'TEST_BOOT_ENABLE_RESULT': 'DEGRADED'})
        self.assert_postcondition_failed(values)
        self.assertEqual(values['state'], 'ACTIVE')

    def test_disable_postcondition_requires_firewall_gone(self):
        _, values = self.run_bridge('disable', {'TEST_ENGINE_BAD_DISABLE': '1'})
        self.assert_postcondition_failed(values)
        self.assertEqual(values['state'], 'ACTIVE')

    def test_disable_postcondition_requires_boot_disarmed(self):
        _, values = self.run_bridge('disable', {'TEST_BOOT_DISABLE_RESULT': 'DEGRADED'})
        self.assert_postcondition_failed(values)

    def test_boot_enable_postcondition(self):
        self.boot_state.write_text('DISABLED\n')
        _, values = self.run_bridge('boot-enable', {'TEST_BOOT_ENABLE_RESULT': 'DEGRADED'})
        self.assert_postcondition_failed(values)

    def test_boot_disable_postcondition(self):
        _, values = self.run_bridge('boot-disable', {'TEST_BOOT_DISABLE_RESULT': 'DEGRADED'})
        self.assert_postcondition_failed(values)

    def test_firewall_changes_postcondition_requires_active(self):
        cases = (('vpn-refresh', (), 'refresh'),
                 ('use-auto', (), 'refresh'),
                 ('set-ports', ('45678', 'none', 'experimental'), 'set-ports'),
                 ('reset-counters', (), 'reset-counters'))
        for action, args, engine_command in cases:
            with self.subTest(action=action):
                self.state.write_text('ACTIVE\n')
                _, values = self.run_bridge(action, {'TEST_ENGINE_BREAK_AFTER': engine_command}, args=args)
                self.assert_postcondition_failed(values)
                self.assertEqual(values['state'], 'DEGRADED')

    def test_failed_engine_disable_is_reported(self):
        _, values = self.run_bridge('disable', {'TEST_ENGINE_FAIL_DISABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Could not remove all firewall rules', values['message'])

    def test_boot_action_failures_are_reported(self):
        _, values = self.run_bridge('boot-enable', {'TEST_BOOT_CANNOT_ENABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Cannot enable boot restoration', values['message'])
        _, values = self.run_bridge('boot-disable', {'TEST_BOOT_CANNOT_DISABLE': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Could not remove the boot hook', values['message'])

    def test_partial_rule_report_with_success_exit_is_not_presented(self):
        result, values = self.run_bridge('inspect', {'TEST_RULE_REPORT_PARTIAL': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(values['rules_report'], 'UNAVAILABLE')
        self.assertNotIn('input_policy4', values)

    # --- Rollback: a saved change that could not finish restores the live ports. ---

    LIVE = {'TEST_LIVE_UDP4': '50000', 'TEST_LIVE_UDP6': 'none'}

    def test_commit_save_failure_restores_previous_live_ports(self):
        self.fail_config_command('write')
        _, values = self.run_bridge('set-ports', self.LIVE, args=('41476', '45567', 'committed'))
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Could not save committed', values['message'])
        self.assertEqual(self.engine_args('set-ports'), [
            'set-ports --udp4 41476 --udp6 45567',
            'set-ports --udp4 50000 --udp6 none',
        ])
        self.assertFalse((self.config_dir / 'udp-committed.conf').exists())
        self.assertEqual(values['config_mode'], 'AUTOMATIC')

    def test_use_auto_clear_failure_restores_previous_live_ports(self):
        saved = 'udp4=41476\nudp6=none\n'
        (self.config_dir / 'udp-committed.conf').write_text(saved)
        self.fail_config_command('clear')
        _, values = self.run_bridge('use-auto', self.LIVE)
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('Could not clear committed', values['message'])
        self.assertEqual(self.log_lines(), [
            'engine:get-ports', 'engine:refresh', 'engine:set-ports', 'engine:activity', 'boot:status'
        ])
        self.assertEqual(self.engine_args('set-ports'), ['set-ports --udp4 50000 --udp6 none'])
        self.assertEqual((self.config_dir / 'udp-committed.conf').read_text(), saved)

    def test_use_auto_refresh_failure_keeps_saved_settings(self):
        saved = 'udp4=41476\nudp6=none\n'
        (self.config_dir / 'udp-committed.conf').write_text(saved)
        _, values = self.run_bridge('use-auto', {'TEST_ENGINE_REFRESH_FAIL': '1'})
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual((self.config_dir / 'udp-committed.conf').read_text(), saved)
        self.assertEqual(self.engine_args('set-ports'), [])

    def test_unverifiable_boot_state_rolls_commit_back(self):
        for boot in ('CONFLICT', 'DEGRADED'):
            with self.subTest(boot=boot):
                self.boot_state.write_text(boot + '\n')
                self.args_log.unlink(missing_ok=True)
                (self.config_dir / 'udp-committed.conf').write_text('udp4=1000\nudp6=none\n')
                _, values = self.run_bridge('set-ports', self.LIVE, args=('41476', '45567', 'committed'))
                self.assertEqual(values['operation'], 'FAILED')
                self.assertIn('rolled back', values['message'])
                self.assertEqual((self.config_dir / 'udp-committed.conf').read_text(), 'udp4=1000\nudp6=none\n')
                self.assertEqual(self.engine_args('set-ports')[-1], 'set-ports --udp4 50000 --udp6 none')

    def test_unreadable_boot_status_rolls_commit_back(self):
        _, values = self.run_bridge('set-ports', {**self.LIVE, 'TEST_BOOT_STATUS_FAIL': '1'},
                                    args=('41476', '45567', 'committed'))
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('rolled back', values['message'])
        self.assertEqual(values['boot'], 'UNKNOWN')
        self.assertFalse((self.config_dir / 'udp-committed.conf').exists())
        self.assertEqual(self.engine_args('set-ports')[-1], 'set-ports --udp4 50000 --udp6 none')

    def test_failed_boot_snapshot_rolls_commit_back(self):
        _, values = self.run_bridge('set-ports', {**self.LIVE, 'TEST_BOOT_CANNOT_ENABLE': '1'},
                                    args=('41476', '45567', 'committed'))
        self.assertEqual(values['operation'], 'FAILED')
        self.assertIn('rollback attempted', values['message'])
        self.assertFalse((self.config_dir / 'udp-committed.conf').exists())
        self.assertEqual(self.engine_args('set-ports')[-1], 'set-ports --udp4 50000 --udp6 none')

    def test_set_ports_refuses_when_live_or_saved_state_is_unverifiable(self):
        self.state.write_text('DEGRADED\n')
        _, values = self.run_bridge('set-ports', args=('41476', 'none', 'experimental'))
        self.assertEqual(values['operation'], 'FAILED')
        self.assertNotIn('engine:set-ports', self.log_lines())
        self.state.write_text('ACTIVE\n')
        self.log.unlink(missing_ok=True)
        self.corrupt_saved_config()
        _, values = self.run_bridge('set-ports', args=('41476', 'none', 'experimental'))
        self.assertEqual(values['operation'], 'FAILED')
        self.assertNotIn('engine:set-ports', self.log_lines())

    def test_rollback_after_bad_enable_restores_only_what_it_created(self):
        self.state.write_text('INACTIVE\n')
        _, values = self.run_bridge('enable', {'TEST_ENGINE_BAD_ENABLE': '1'})
        self.assertEqual(values['state'], 'INACTIVE')
        self.assertIn('engine:disable', self.log_lines())

    # --- VPN owner: name only what Android calls connected. ---

    @staticmethod
    def agent(state, owner):
        return f'NetworkAgentInfo{{network{{104}} ni{{VPN {state} extra: VPN:{owner}}} created=x}}\n'

    def test_duplicate_owner_lines_resolve_to_one_owner(self):
        _, values = self.run_bridge('inspect', {'TEST_VPN_OWNERS': 'com.tailscale.ipn,com.tailscale.ipn'})
        self.assertEqual(values['vpn_owner'], 'com.tailscale.ipn')

    def test_vpn_that_is_not_connected_is_not_named(self):
        for state in ('SUSPENDED', 'CONNECTING', 'DISCONNECTED'):
            with self.subTest(state=state):
                _, values = self.run_bridge('inspect', {'TEST_DUMPSYS_TEXT': self.agent(state, 'ch.protonvpn.android')})
                self.assertEqual(values['vpn_owner'], '')

    def test_only_the_connected_vpn_is_named_beside_a_suspended_one(self):
        text = self.agent('SUSPENDED', 'ch.protonvpn.android') + self.agent('CONNECTED', 'com.tailscale.ipn')
        _, values = self.run_bridge('inspect', {'TEST_DUMPSYS_TEXT': text})
        self.assertEqual(values['vpn_owner'], 'com.tailscale.ipn')

    def test_owner_name_with_unexpected_characters_is_not_trusted(self):
        for owner in ('com.tailscale.ipn;id', 'com tailscale', 'com/tailscale'):
            with self.subTest(owner=owner):
                _, values = self.run_bridge('inspect', {'TEST_DUMPSYS_TEXT': self.agent('CONNECTED', owner)})
                self.assertEqual(values['vpn_owner'], '')

    def test_rejects_unrecognized_commands(self):
        result, values = self.run_bridge("erase-everything")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("root", values)


if __name__ == "__main__":
    unittest.main()
