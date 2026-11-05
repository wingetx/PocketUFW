"""A disposable "device" for tests that run the real scripts together.

The scripts are the project's own. Only bootctl and boot-service have their
fixed /data/adb paths rewritten, the same technique as test_bootctl.py. Android
commands that have no host equivalent are small fakes, driven by environment
variables. Nothing here touches /data/adb, a phone, or the host firewall.
"""
from pathlib import Path
import shutil

PROJECT = Path(__file__).resolve().parents[1]
BRIDGE_SCRIPTS = ('pocketufw', 'vpn-probe', 'android-bridge', 'rules-report', 'udp-config')

FAKES = {
    'magisk': '#!/bin/sh\nexit 0\n',
    'getprop': '#!/bin/sh\necho "${TEST_BOOT_COMPLETED:-1}"\n',
    'pm': (
        '#!/bin/sh\n'
        'case "${TEST_PM_MODE:-ok}" in\n'
        "  ok) [ \"$1\" = path ] && echo 'package:/data/app/placeholder/base.apk' ;;\n"
        "  transient) echo 'cmd: Failure calling service package: Broken pipe (32)' >&2; exit 224 ;;\n"
        '  gone) exit 1 ;;\n'
        'esac\n'
    ),
    'dumpsys': (
        '#!/bin/sh\n'
        "[ -z \"${TEST_VPN_OWNER:-}\" ] || "
        "printf 'NetworkAgentInfo{network{104} ni{VPN CONNECTED extra: VPN:%s} created=x}\\n' \"$TEST_VPN_OWNER\"\n"
    ),
}


class Device:
    def __init__(self, root, path_tail):
        self.root = Path(root)
        self.engine = self.root / 'engine'
        self.bin = self.root / 'bin'
        self.store = self.root / 'adb-pocketufw'
        self.service_dir = self.root / 'service.d'
        self.hook = self.service_dir / 'pocketufw.sh'
        self.config_dir = self.root / 'device-protected'
        self.config_file = self.config_dir / 'udp-committed.conf'
        self.app_data = self.root / 'app-data'  # Android removes it on uninstall.
        self.lock = self.root / 'pocketufw.lock'
        for directory in (self.engine, self.bin, self.service_dir, self.config_dir, self.app_data):
            directory.mkdir(parents=True)
        for name in BRIDGE_SCRIPTS:
            shutil.copy(PROJECT / name, self.engine / name)
        (self.engine / 'bootctl').write_text(self._rewrite(
            (PROJECT / 'bootctl').read_text().replace(
                '[ -d /data/adb/service.d ]', f"[ -d '{self.service_dir}' ]")))
        (self.engine / 'boot-service').write_text(self._rewrite(
            (PROJECT / 'boot-service').read_text().replace(
                'PATH=/system/bin:/system/xbin:/vendor/bin', f'PATH={self.bin}:{path_tail}')))
        for name, source in FAKES.items():
            self.add_command(name, source)
        self.path = f'{self.bin}:{path_tail}'

    def _rewrite(self, source):
        return (source
                .replace("STORE='/data/adb/pocketufw'", f"STORE='{self.store}'")
                .replace("HOOK='/data/adb/service.d/pocketufw.sh'", f"HOOK='{self.hook}'"))

    def add_command(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    def env(self, base):
        return {**base, 'PATH': self.path,
                'POCKETUFW_CONFIG_DIR': str(self.config_dir),
                'POCKETUFW_APP_DATA_DIR': str(self.app_data),
                'POCKETUFW_LOCK': str(self.lock)}
