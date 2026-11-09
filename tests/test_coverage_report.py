"""Completeness metadata must distinguish empty evidence from unavailable evidence."""
import unittest
from test_android_bridge import AndroidBridgeTests
from test_rules_report import RuleReportTests


class ReportCounts(RuleReportTests):
    def test_every_section_has_a_count_including_empty_sections(self):
        result = self.run_report()
        values = dict(line.split('=', 1) for line in result.stdout.splitlines())
        for fam in (4, 6):
            for kind, count in (('hook', 4), ('main', 5), ('vpn', 1), ('tunnel', 0), ('bypass', 0)):
                self.assertEqual(values.get(f'report_{kind}{fam}_count'), str(count))
        self.assertEqual(result.stdout.splitlines()[-1], 'rules_report=READY')


class InterfaceEvidence(AndroidBridgeTests):
    def test_failed_or_empty_or_malformed_ip_reads_do_not_claim_known_coverage(self):
        for env in ({'TEST_IP_FAIL': '1'}, {}, {'TEST_IP_LINK': 'not an interface record\n'}):
            with self.subTest(env=env):
                result, values = self.run_bridge('inspect', env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(values.get('interface_report'), 'UNAVAILABLE')
                self.assertEqual(values['state'], 'ACTIVE')

    def test_successful_inventory_can_distinguish_none_from_known_gaps(self):
        for name, expected in (('v4-wlan0', ''), ('eth0', 'eth0')):
            _, values = self.run_bridge('inspect', {
                'TEST_IP_LINK': f'7: {name}: <UP,LOWER_UP> mtu 1500\n',
                'TEST_IP_ADDR': f'7: {name} inet 192.0.0.4/32 scope global {name}\n'})
            self.assertEqual(values.get('interface_report'), 'READY')
            self.assertEqual(values['uncovered_ifaces'], expected)

    def test_address_read_failure_is_not_masked_by_successful_link_read(self):
        (self.bin / 'ip').write_text('#!/bin/sh\n[ "$2" = link ] || exit 9\n'
                                   'echo "1: lo: <LOOPBACK,UP> mtu 65536"\n')
        _, values = self.run_bridge('inspect')
        self.assertEqual(values.get('interface_report'), 'UNAVAILABLE')

    def test_malformed_or_racing_address_rows_cannot_claim_complete_inventory(self):
        for address in ('7: eth0 inet6 missing-address\n',
                        '7: eth0 inet 192.0.0.4/32\n',
                        '8: appeared0 inet 192.0.0.4/32 scope global appeared0\n'):
            with self.subTest(address=address):
                _, values = self.run_bridge('inspect', {
                    'TEST_IP_LINK': '7: eth0: <UP,LOWER_UP> mtu 1500\n',
                    'TEST_IP_ADDR': address})
                self.assertEqual(values.get('interface_report'), 'UNAVAILABLE')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(c(n) for c in (ReportCounts, InterfaceEvidence)
                             for n in c.__dict__ if n.startswith('test_'))
