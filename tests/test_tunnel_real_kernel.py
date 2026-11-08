"""The tunnel filter on real netfilter, real tun devices and real kernel WireGuard.

A tun here is what it is on Android: a process holds /dev/net/tun, and every packet it
writes enters the kernel as received from that interface. The kernel WireGuard really
decrypts what its peer sent. Fresh user, network, mount and PID namespaces keep all of
it away from the host, whose firewall and interfaces these tests can't reach. They
skip when the host can't provide that, and nothing here touches a phone.
"""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_sandbox import Device
from test_real_kernel import NET, PATH_TAIL, PRELUDE

PROJECT = Path(__file__).resolve().parents[1]
SHELL = ['unshare', '-Urnm', '--pid', '--fork', '--mount-proc', 'bash']

PREFLIGHT = r'''
set -e
mount -t sysfs sysfs /sys
python3 -I -c "
import fcntl, os, struct
fd = os.open('/dev/net/tun', os.O_RDWR)
name = fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', b'', 0x1001))[:16].rstrip(b'\0').decode()
assert 'iff:' in open(f'/proc/self/fdinfo/{fd}').read()
assert os.path.exists(f'/sys/class/net/{name}/tun_flags')
"
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
iptables -w -N PUFW_TRY
iptables -w -A PUFW_TRY -s 100.64.0.2/32 -d 100.64.0.1/32 -i tun0 -p tcp --dport 22 -j ACCEPT
ip6tables -w -N PUFW_TRY
'''
WG_PREFLIGHT = r'''
set -e
mount -t sysfs sysfs /sys
ip link add wgtry type wireguard
grep -qx DEVTYPE=wireguard /sys/class/net/wgtry/uevent
wg genkey >/dev/null
'''


def namespace_check(script):
    try:
        probe = subprocess.run([*SHELL, '-c', script], capture_output=True, text=True, timeout=30,
                               env={**os.environ, 'PATH': PATH_TAIL})
    except (OSError, subprocess.SubprocessError) as error:
        return str(error)
    return None if probe.returncode == 0 else probe.stderr.strip()[:200]


def unusable_reason():
    for tool in ('unshare', 'nsenter', 'ip', 'iptables', 'ip6tables', 'flock', 'setsid'):
        if shutil.which(tool, path=PATH_TAIL) is None:
            return f'missing {tool}'
    return namespace_check(PREFLIGHT)


UNUSABLE = unusable_reason()
NO_WIREGUARD = 'missing wg' if shutil.which('wg', path=PATH_TAIL) is None else (
    None if UNUSABLE else namespace_check(WG_PREFLIGHT))

# Runs inside the namespaces only. stdlib-only; python3 -I keeps it isolated.
TUN = r'''
import ctypes, fcntl, os, select, socket, struct, sys, time

def family(name):
    return socket.AF_INET6 if name == '6' else socket.AF_INET

def tunapp(comm, name, mine, theirs, ready, stop):
    """A VPN app. Holds the tun; carries its packets to the far side over a Unix socket."""
    ctypes.CDLL(None).prctl(15, comm.encode(), 0, 0, 0)  # PR_SET_NAME
    fd = os.open('/dev/net/tun', os.O_RDWR)
    fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x1001))  # TUNSETIFF, TUN + NO_PI
    if os.path.exists(mine):
        os.unlink(mine)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(mine)
    open(ready, 'w').close()
    while not os.path.exists(stop):
        for source in select.select([fd, sock], [], [], 0.02)[0]:
            if source is sock:
                try:
                    os.write(fd, sock.recv(65535))
                except OSError:
                    pass  # Not up yet, or a family it has no address for.
            else:
                packet = os.read(fd, 65535)
                try:
                    sock.sendto(packet, theirs)
                except OSError:
                    pass  # Nobody on the far side.

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff

def inject(sock_path, fam, src, dst, port, count):
    """What a VPN app's write does: this packet arrives on that tun, whatever it claims."""
    payload = b'x' * 20
    udp_len = 8 + len(payload)
    if fam == '6':
        s, d = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
        pseudo = s + d + struct.pack('!I3xB', udp_len, 17)
        head = struct.pack('!HHHH', 40001, int(port), udp_len, 0)
        head = head[:6] + struct.pack('!H', checksum(pseudo + head + payload))
        packet = struct.pack('!IHBB', 6 << 28, udp_len, 17, 64) + s + d + head + payload
    else:
        s, d = socket.inet_aton(src), socket.inet_aton(dst)
        pseudo = s + d + struct.pack('!BBH', 0, 17, udp_len)
        head = struct.pack('!HHHH', 40001, int(port), udp_len, 0)
        head = head[:6] + struct.pack('!H', checksum(pseudo + head + payload))
        ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + udp_len, 1, 0, 64, 17, 0) + s + d
        packet = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:] + head + payload
    out = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    for _ in range(int(count)):
        out.sendto(packet, sock_path)
        time.sleep(0.002)

def send_from(fam, src, dst, port, count):
    s = socket.socket(family(fam), socket.SOCK_DGRAM)
    s.bind((src, 0))
    for _ in range(int(count)):
        s.sendto(b'x' * 20, (dst, int(port)))
        time.sleep(0.002)

def connect_from(fam, src, dst, port, seconds):
    s = socket.socket(family(fam), socket.SOCK_STREAM)
    s.bind((src, 0))
    s.settimeout(float(seconds))
    try:
        s.connect((dst, int(port)))
        print('CONNECTED')
    except socket.timeout:
        print('TIMEOUT')
    except ConnectionRefusedError:
        print('REFUSED')

def loopback_service(port, ready, stop):
    """sshd as the phone runs it: bound to loopback and nothing else."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', int(port)))
    s.listen(8)
    s.settimeout(0.05)
    open(ready, 'w').close()
    while not os.path.exists(stop):
        try:
            conn, _ = s.accept()
        except socket.timeout:
            continue
        conn.sendall(b'SSH-2.0-loopback\n')
        conn.close()

def service(fam, addr, port, ready, stop):
    """Something that really listens on the tailnet address: Syncthing, or Taildrop's peer API."""
    s = socket.socket(family(fam), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(8)
    s.settimeout(0.05)
    open(ready, 'w').close()
    while not os.path.exists(stop):
        try:
            conn, _ = s.accept()
        except socket.timeout:
            continue
        conn.close()

def bridge_phone(fam, host, port, local_port, ready):
    """The phone dials out, like ssh -R, and serves the far side's requests from loopback."""
    out = socket.socket(family(fam), socket.SOCK_STREAM)
    out.settimeout(25)
    out.connect((host, int(port)))
    open(ready, 'w').close()
    while True:
        try:
            line = out.recv(16)
        except (socket.timeout, OSError):
            return
        if not line:
            return
        local = socket.create_connection(('127.0.0.1', int(local_port)), timeout=5)
        out.sendall(local.recv(64))
        local.close()

def bridge_far(fam, bind, port, ready, go, result):
    """The far host: asks through the phone's connection once, again after go, then reports."""
    s = socket.socket(family(fam), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, int(port)))
    s.listen(1)
    open(ready, 'w').close()
    s.settimeout(20)
    conn, _ = s.accept()
    conn.settimeout(4)
    answers = []
    def ask():
        try:
            conn.sendall(b'open\n')
            answers.append(conn.recv(64).decode().strip() or 'CLOSED')
        except OSError as error:
            answers.append(type(error).__name__)
    ask()
    open(result + '.first', 'w').close()
    deadline = time.time() + 15
    while not os.path.exists(go) and time.time() < deadline:
        time.sleep(0.01)
    ask()
    open(result, 'w').write(' '.join(answers))
    conn.close()

{'tunapp': tunapp, 'inject': inject, 'send_from': send_from, 'connect_from': connect_from,
 'loopback_service': loopback_service, 'service': service, 'bridge_phone': bridge_phone,
 'bridge_far': bridge_far}[sys.argv[1]](*sys.argv[2:])
'''

SETUP = r'''
mount -t sysfs sysfs /sys || exit 89
# Each scenario is a new namespace, whatever an earlier subtest left in the shared folder.
rm -f "$WORK"/farside.* "$WORK"/*.stop "$WORK"/*.ready
# As measured on a Pixel 9a. New interfaces take the default, which here comes from the host.
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
peer sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter'
T="python3 -I $WORK/tun.py"
ROLLBACK="$DEVICE/tunnel-rollback"
PHONE4=100.64.0.1; PHONE6=fd7a:115c:a1e0::1
FAR4=100.64.0.2;   FAR6=fd7a:115c:a1e0::2
OTHER4=100.64.0.3; OTHER6=fd7a:115c:a1e0::3
phone_addr() { if [ "$1" = 4 ]; then echo "$PHONE4"; else echo "$PHONE6"; fi; }
far_addr() { if [ "$1" = 4 ]; then echo "$FAR4"; else echo "$FAR6"; fi; }
other_addr() { if [ "$1" = 4 ]; then echo "$OTHER4"; else echo "$OTHER6"; fi; }

# near_tun NAME TAG COMM: an app on this side holding a tun.
near_tun() {
  rm -f "$WORK/$2.stop" "$WORK/$2.ready"
  $T tunapp "$3" "$1" "$WORK/$2.near" "$WORK/$2.far" "$WORK/$2.ready" "$WORK/$2.stop" &
  wait_for "$WORK/$2.ready"
}
# stop_tun TAG: the app lets go, and Android's tun disappears with it.
stop_tun() {
  : > "$WORK/$1.stop"
  while ip -o link show "$2" >/dev/null 2>&1; do sleep 0.01; done
}
tailnet_on() {
  ip addr add "$PHONE4/32" dev "$1"
  ip -6 addr add "$PHONE6/128" dev "$1" nodad
  ip link set "$1" up
  ip route add 100.64.0.0/10 dev "$1"
  ip -6 route add fd7a:115c:a1e0::/48 dev "$1"
}
# tailscale NAME: a proven Tailscale tunnel with a real peer behind it, as Android records it.
tailscale() {
  near_tun "$1" ts com.tailscale.ipn
  tailnet_on "$1"
  export TEST_VPN_OWNER=com.tailscale.ipn TEST_VPN_IFACE="$1"
  peer_up
}
peer_up() {
  rm -f "$WORK/farside.ready"
  [ -e "$WORK/farside.pid" ] && return 0
  peer $T tunapp farapp far0 "$WORK/ts.far" "$WORK/ts.near" "$WORK/farside.ready" "$WORK/farside.stop" &
  wait_for "$WORK/farside.ready"
  : > "$WORK/farside.pid"
  peer ip addr add "$FAR4/32" dev far0
  peer ip addr add "$OTHER4/32" dev far0
  peer ip -6 addr add "$FAR6/128" dev far0 nodad
  peer ip -6 addr add "$OTHER6/128" dev far0 nodad
  peer ip link set far0 up
  peer ip route add 100.64.0.0/10 dev far0
  peer ip -6 route add fd7a:115c:a1e0::/48 dev far0
}
# other_vpn NAME: a VPN that isn't Tailscale, shaped like Proton: ordinary addresses, a server behind.
other_vpn() {
  near_tun "$1" ts ch.protonvpn.android
  ip addr add 10.2.0.2/32 dev "$1"
  ip -6 addr add fd00:2::2/128 dev "$1" nodad
  ip link set "$1" up
  ip route add 10.2.0.1/32 dev "$1"
  ip -6 route add fd00:2::1/128 dev "$1"
  export TEST_VPN_OWNER=ch.protonvpn.android TEST_VPN_IFACE="$1"
  peer_up
  peer ip addr add 10.2.0.1/32 dev far0
  peer ip -6 addr add fd00:2::1/128 dev far0 nodad
  # Its own address as the source, not the first one this end happens to hold.
  peer ip route add 10.2.0.2/32 dev far0 src 10.2.0.1
  peer ip -6 route add fd00:2::2/128 dev far0 src fd00:2::1
}
# Verified node for tests whose packet path is a different VPN or kernel WG.
# It remains separate from that path; packet-delivery assertions still use the latter.
authorization_tun() {
  near_tun tun-auth auth com.tailscale.ipn
  ip addr add "$PHONE4/32" dev tun-auth
  ip -6 addr add "$PHONE6/128" dev tun-auth nodad
  ip link set tun-auth up
  export TEST_VPN_OWNER=com.tailscale.ipn TEST_VPN_IFACE=tun-auth
}
# to_phone FAM SRC DST PORT COUNT: datagrams from the far side that reach a listener on the phone.
to_phone() {
  local mark="$WORK/mark.$RANDOM$RANDOM"
  $N recv "$1" "$4" "$5" "$mark.ready" "$mark.stop" > "$mark.out" &
  local listener=$!
  wait_for "$mark.ready"
  peer $T send_from "$1" "$2" "$3" "$4" "$5"
  : > "$mark.stop"
  wait "$listener"
  cat "$mark.out"
}
from_far() { to_phone "$1" "$2" "$(phone_addr "$1")" "$3" "$4"; }
tailnet_status() { sh "$ENG" tunnel-status | sed -n 's/^tailnet=//p' | tr '\n' ';'; }
# written FAM TAG SRC DST PORT COUNT: packets an app wrote to its tun that reach a listener.
written() {
  local mark="$WORK/mark.$RANDOM$RANDOM"
  $N recv "$1" "$5" "$6" "$mark.ready" "$mark.stop" > "$mark.out" &
  local listener=$!
  wait_for "$mark.ready"
  $T inject "$WORK/$2.near" "$1" "$3" "$4" "$5" "$6"
  sleep 0.05
  : > "$mark.stop"
  wait "$listener"
  cat "$mark.out"
}
input_physical() { iptables -w -S INPUT | grep -- '-j POCKETUFW_IN$'; ip6tables -w -S INPUT | grep -- '-j POCKETUFW_IN$'; }
policy_print() {
  iptables -w -S POCKETUFW_IN; iptables -w -S POCKETUFW_TS
  ip6tables -w -S POCKETUFW_IN; ip6tables -w -S POCKETUFW_TS
  input_physical
}
'''


@unittest.skipIf(UNUSABLE, UNUSABLE)
class TunnelKernelTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pufw-tunnel-kernel-')
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        (self.work / 'net.py').write_text(NET)
        (self.work / 'tun.py').write_text(TUN)
        self.device = Device(self.work / 'device', PATH_TAIL)
        shutil.copy(PROJECT / 'tools' / 'tunnel-rollback', self.device.root / 'tunnel-rollback')
        # Inside the namespace this process is mapped to UID 0, app ID 0.
        self.packages = self.work / 'packages.list'
        self.packages.write_text('com.tailscale.ipn 0 0\nch.protonvpn.android 0 0\n')

    def namespace(self, body, timeout=90, **extra):
        script = self.work / 'scenario.sh'
        script.write_text(PRELUDE + SETUP + body)
        env = {**self.device.env(dict(os.environ)), 'WORK': str(self.work), 'DEVICE': str(self.device.root),
               'POCKETUFW_PACKAGES_LIST': str(self.packages),
               'POCKETUFW_ROLLBACK_STATE': str(self.work / 'rollback-state'), **extra}
        process = subprocess.Popen([*SHELL, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            self.fail(f'scenario hung\n{stdout}\n{stderr}')
        self.assertEqual(process.returncode, 0, f'scenario failed\n{stdout}\n{stderr}')
        return dict(line.split('=', 1) for line in stdout.splitlines() if '=' in line)

    def test_off_by_default_tunnel_traffic_still_arrives_with_the_firewall_on(self):
        values = self.namespace(r'''
        link wlan0 9
        tailscale tun0
        sh "$ENG" enable >/dev/null || exit 91
        say verify "$(sh "$ENG" verify)"
        say filter "$(kv tunnel_filter)"
        say tun4 "$(from_far 4 $FAR4 47931 10)"
        say tun6 "$(from_far 6 $FAR6 47931 10)"
        say wifi4 "$(deliver 4 9 47931 10)"
        ''')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['filter'], 'OFF')
        self.assertEqual(values['tun4'], '10')
        self.assertEqual(values['tun6'], '10')
        self.assertEqual(values['wifi4'], '0')

    def test_deny_only_filters_proton_without_authorizing_tailscale_then_stays_closed(self):
        values = self.namespace(r'''
        other_vpn tun7
        sh "$ENG" enable >/dev/null || exit 91
        say before "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        sh "$ENG" tunnel-on --deny-only >/dev/null || exit 92
        say verify "$(sh "$ENG" verify)"
        say ordinary4 "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        say ordinary6 "$(to_phone 6 fd00:2::1 fd00:2::2 47931 5)"
        authorization_tun
        sh "$ENG" tunnel-refresh >/dev/null || exit 93
        say trust "$(kv tailnet_trust)"
        say tailnet4 "$(written 4 ts 100.64.0.20 "$PHONE4" 47932 5)"
        say tailnet6 "$(written 6 ts fd7a:115c:a1e0::20 "$PHONE6" 47932 5)"
        ''')
        self.assertEqual(values['before'], '5')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['trust'], 'DENY_ONLY')
        for name in ('ordinary4', 'ordinary6', 'tailnet4', 'tailnet6'):
            self.assertEqual(values[name], '0', name)

    def test_another_vpn_delivers_nothing_unsolicited_and_it_is_counted_separately(self):
        values = self.namespace(r'''
        link wlan0 9
        other_vpn tun7
        authorization_tun
        sh "$ENG" enable >/dev/null || exit 91
        say tcp_before "$(peer $T connect_from 4 10.2.0.1 10.2.0.2 47932 1)"
        say control "$(to_phone 4 10.2.0.1 10.2.0.2 47931 10)"
        sh "$ENG" tunnel-on >/dev/null || exit 92
        say verify "$(sh "$ENG" verify)"
        say tun4 "$(to_phone 4 10.2.0.1 10.2.0.2 47931 10)"
        say tun6 "$(to_phone 6 fd00:2::1 fd00:2::2 47931 10)"
        say tcp4 "$(peer $T connect_from 4 10.2.0.1 10.2.0.2 47932 0.4)"
        say tcp6 "$(peer $T connect_from 6 fd00:2::1 fd00:2::2 47932 0.4)"
        say tunnel_blocked4 "$(kv ipv4_tunnel_blocked)"
        say tunnel_blocked6 "$(kv ipv6_tunnel_blocked)"
        say tailnet4 "$(kv ipv4_tunnel_tailnet)"
        say physical_blocked4 "$(kv ipv4_blocked)"
        say physical_blocked6 "$(kv ipv6_blocked)"
        # What the phone started itself still gets its replies.
        peer $N echo 4 7777 "$WORK/echo" &
        wait_for "$WORK/echo"
        say replies "$($N ask 4 10.2.0.1 7777 3)"
        say established "$(kv ipv4_tunnel_established_replies)"
        say wifi4 "$(deliver 4 9 47931 5)"
        say physical_after_wifi "$(kv ipv4_blocked)"
        say tunnel_after_wifi "$(kv ipv4_tunnel_blocked)"
        sh "$ENG" tunnel-off >/dev/null || exit 93
        say verify_off "$(sh "$ENG" verify)"
        say tun4_off "$(to_phone 4 10.2.0.1 10.2.0.2 47931 10)"
        say wifi4_off "$(deliver 4 9 47931 5)"
        ''')
        self.assertEqual(values['tcp_before'], 'REFUSED')
        self.assertEqual(values['control'], '10')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['tun4'], '0')
        self.assertEqual(values['tun6'], '0')
        self.assertEqual(values['tcp4'], 'TIMEOUT')
        self.assertEqual(values['tcp6'], 'TIMEOUT')
        # At least the probes: a TCP retry may add to them, and IPv6 may add neighbour traffic.
        self.assertGreaterEqual(int(values['tunnel_blocked4']), 11)
        self.assertGreaterEqual(int(values['tunnel_blocked6']), 11)
        self.assertEqual(values['tailnet4'], '0')
        self.assertEqual(values['physical_blocked4'], '0')
        self.assertEqual(values['replies'], '3')
        self.assertGreaterEqual(int(values['established']), 3)
        self.assertEqual(values['wifi4'], '0')
        self.assertEqual(values['physical_after_wifi'], '5')
        self.assertEqual(values['tunnel_after_wifi'], values['tunnel_blocked4'])
        self.assertEqual(values['verify_off'], 'ACTIVE')
        self.assertEqual(values['tun4_off'], '10')
        self.assertEqual(values['wifi4_off'], '0')

    def test_tailnet_devices_reach_the_phone_with_no_allowance_in_both_families(self):
        for fam in ('4', '6'):
            with self.subTest(family=fam):
                values = self.namespace(rf'''
                fam={fam}
                tailscale tun1
                own=$(phone_addr $fam); far=$(far_addr $fam); other=$(other_addr $fam)
                sh "$ENG" enable >/dev/null || exit 91
                $T service $fam $own 22000 "$WORK/sync.ready" "$WORK/sync.stop" &
                $T service $fam $own 39871 "$WORK/drop.ready" "$WORK/drop.stop" &
                wait_for "$WORK/sync.ready"
                wait_for "$WORK/drop.ready"
                sh "$ENG" tunnel-on >/dev/null || exit 92
                say verify "$(sh "$ENG" verify)"
                say status "$(tailnet_status)"
                # Syncthing's TCP and QUIC, and Taildrop's peer API on the port Tailscale chose.
                say syncthing_tcp "$(peer $T connect_from $fam $far $own 22000 1)"
                say syncthing_quic "$(from_far $fam $far 22000 10)"
                say taildrop "$(peer $T connect_from $fam $other $own 39871 1)"
                say closed_port "$(peer $T connect_from $fam $far $own 47999 1)"
                say hits "$(kv ipv${{fam}}_tunnel_tailnet)"
                say blocked "$(kv ipv${{fam}}_tunnel_blocked)"
                : > "$WORK/sync.stop"; : > "$WORK/drop.stop"
                ''')
                self.assertEqual(values['verify'], 'ACTIVE')
                self.assertEqual(values['status'], 'VERIFIED iface=tun1;')
                self.assertEqual(values['syncthing_tcp'], 'CONNECTED')
                self.assertEqual(values['syncthing_quic'], '10')
                self.assertEqual(values['taildrop'], 'CONNECTED')
                # Nothing listening answers as it would with no firewall at all.
                self.assertEqual(values['closed_port'], 'REFUSED')
                self.assertGreaterEqual(int(values['hits']), 12)
                self.assertEqual(values['blocked'], '0')

    def test_only_tailnet_to_tailnet_passes_on_tailscales_own_tun(self):
        values = self.namespace(r'''
        link wlan0 9
        tailscale tun1
        sh "$ENG" enable >/dev/null || exit 91
        sh "$ENG" tunnel-on >/dev/null || exit 92
        say source4 "$(written 4 ts 198.51.100.7 $PHONE4 47000 5)"
        say source6 "$(written 6 ts 2001:db8::7 $PHONE6 47000 5)"
        # Weak host model: a tailnet source aimed at the phone's Wi-Fi address would be delivered.
        say destination4 "$(written 4 ts $FAR4 10.9.0.1 47000 5)"
        say destination6 "$(written 6 ts $FAR6 fd9::1 47000 5)"
        say blocked4 "$(kv ipv4_tunnel_blocked)"
        say blocked6 "$(kv ipv6_tunnel_blocked)"
        # A tailnet source arriving on Wi-Fi meets the physical policy, not this rule.
        peer ip route add $PHONE4/32 via 10.9.0.1 dev peer1 onlink
        say wifi_claims_tailnet "$(from_far 4 $FAR4 47000 5)"
        say wifi_blocked "$(kv ipv4_blocked)"
        ''')
        for key in ('source4', 'source6', 'destination4', 'destination6', 'wifi_claims_tailnet'):
            self.assertEqual(values[key], '0', key)
        self.assertEqual(values['blocked4'], '10')
        self.assertEqual(values['blocked6'], '10')
        self.assertEqual(values['wifi_blocked'], '5')

    def test_the_physical_policy_reads_the_same_before_during_and_after(self):
        values = self.namespace(r'''
        link wlan0 9
        tailscale tun0
        sh "$ENG" enable --tailscale-udp4 46867 --tailscale-udp6 43504 >/dev/null || exit 91
        before=$(policy_print)
        sh "$ENG" tunnel-on >/dev/null || exit 92
        [ "$(policy_print)" = "$before" ] && say during same || say during changed
        sh "$ENG" tunnel-off >/dev/null || exit 93
        [ "$(policy_print)" = "$before" ] && say after same || say after changed
        say hooks "$(iptables -w -S INPUT | grep -c PocketUFW-VPN)"
        ''')
        self.assertEqual(values['during'], 'same')
        self.assertEqual(values['after'], 'same')
        self.assertEqual(values['hooks'], '0')

    def test_the_ssh_bridge_shape_survives_the_filter_going_on_and_reconnects(self):
        """The phone dials out through the tun; sshd is loopback-only, so nothing answers directly."""
        values = self.namespace(r'''
        tailscale tun1
        $T loopback_service 8022 "$WORK/ssh.ready" "$WORK/ssh.stop" &
        wait_for "$WORK/ssh.ready"
        sh "$ENG" enable >/dev/null || exit 91
        say direct_before "$(peer $T connect_from 4 $FAR4 $PHONE4 8022 1)"
        peer $T bridge_far 4 $FAR4 2222 "$WORK/far.ready" "$WORK/far.go" "$WORK/far.result" &
        wait_for "$WORK/far.ready"
        $T bridge_phone 4 $FAR4 2222 8022 "$WORK/phone.ready" &
        wait_for "$WORK/phone.ready"
        wait_for "$WORK/far.result.first"
        # The session exists. Now the filter goes on.
        sh "$ENG" tunnel-on >/dev/null || exit 92
        say verify "$(sh "$ENG" verify)"
        : > "$WORK/far.go"
        wait_for "$WORK/far.result"
        say session "$(cat "$WORK/far.result")"
        say hits "$(kv ipv4_tunnel_tailnet)"
        say direct_during "$(peer $T connect_from 4 $FAR4 $PHONE4 8022 1)"
        # autossh reconnecting while the filter is on.
        peer $T bridge_far 4 $FAR4 2223 "$WORK/far2.ready" "$WORK/far2.go" "$WORK/far2.result" &
        wait_for "$WORK/far2.ready"
        : > "$WORK/far2.go"
        $T bridge_phone 4 $FAR4 2223 8022 "$WORK/phone2.ready" &
        wait_for "$WORK/phone2.ready"
        wait_for "$WORK/far2.result"
        say reconnect "$(cat "$WORK/far2.result")"
        : > "$WORK/ssh.stop"
        ''')
        self.assertEqual(values['direct_before'], 'REFUSED')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['session'], 'SSH-2.0-loopback SSH-2.0-loopback')
        self.assertGreater(int(values['hits']), 0)
        # Trusted now, and still no listener there: the same answer as with no filter.
        self.assertEqual(values['direct_during'], 'REFUSED')
        self.assertEqual(values['reconnect'], 'SSH-2.0-loopback SSH-2.0-loopback')

    def test_ownership_comes_from_the_kernels_view_and_never_decides_connectivity(self):
        values = self.namespace(r'''
        tailscale tun3
        sh "$ENG" enable >/dev/null || exit 91
        sh "$ENG" tunnel-on >/dev/null || exit 92
        say proven "$(sh "$DEVICE/engine/vpn-probe" tunnels | grep '^tunnel=')"
        say proven_status "$(tailnet_status)"
        # Same process name and same Android record, but another app ID: not proven.
        cp "$POCKETUFW_PACKAGES_LIST" "$WORK/saved.list"
        echo 'com.tailscale.ipn 12345 0' > "$POCKETUFW_PACKAGES_LIST"
        say impostor "$(sh "$DEVICE/engine/vpn-probe" tunnels | grep '^tunnel=')"
        say impostor_status "$(tailnet_status)"
        cp "$WORK/saved.list" "$POCKETUFW_PACKAGES_LIST"
        # Android says it's Proton's: real, proven, and not Tailscale's.
        export TEST_VPN_OWNER=ch.protonvpn.android
        say proton_status "$(tailnet_status)"
        # No record at all, as when dumpsys is slow. Proof fails; the tailnet must not.
        unset TEST_VPN_OWNER TEST_VPN_IFACE
        say unknown "$(sh "$DEVICE/engine/vpn-probe" tunnels | grep '^tunnel=')"
        say unknown_status "$(tailnet_status)"
        say unknown_delivered "$(from_far 4 $FAR4 47931 5)"
        ''')
        self.assertEqual(values['proven'], 'tunnel=tun3 kind=tun owner=com.tailscale.ipn proof=verified')
        self.assertEqual(values['proven_status'], 'VERIFIED iface=tun3;')
        self.assertEqual(values['impostor'], 'tunnel=tun3 kind=tun owner=com.tailscale.ipn proof=android-only')
        self.assertEqual(values['impostor_status'], 'UNVERIFIED iface=tun3 owner=com.tailscale.ipn proof=android-only;')
        self.assertEqual(values['proton_status'], 'UNVERIFIED iface=tun3 owner=ch.protonvpn.android proof=verified;')
        self.assertEqual(values['unknown'], 'tunnel=tun3 kind=tun owner=unknown proof=none')
        self.assertEqual(values['unknown_status'], 'UNVERIFIED iface=tun3 owner=unknown proof=none;')
        self.assertEqual(values['unknown_delivered'], '5')

    def test_when_tailscale_changes_tun_nothing_has_to_watch(self):
        values = self.namespace(r'''
        tailscale tun0
        $T loopback_service 8022 "$WORK/ssh.ready" "$WORK/ssh.stop" &
        wait_for "$WORK/ssh.ready"
        sh "$ENG" enable >/dev/null || exit 91
        sh "$ENG" tunnel-on >/dev/null || exit 92
        peer $T bridge_far 4 $FAR4 2222 "$WORK/far.ready" "$WORK/far.go" "$WORK/far.result" &
        wait_for "$WORK/far.ready"
        $T bridge_phone 4 $FAR4 2222 8022 "$WORK/phone.ready" &
        wait_for "$WORK/phone.ready"
        wait_for "$WORK/far.result.first"
        say before4 "$(from_far 4 $FAR4 47000 5)"
        rules=$(iptables -w -S; ip6tables -w -S)

        # Android re-establishes the VPN: a new tun, the same addresses. Nothing runs here.
        stop_tun ts tun0
        near_tun tun1 ts com.tailscale.ipn
        tailnet_on tun1
        export TEST_VPN_IFACE=tun1
        [ "$(iptables -w -S; ip6tables -w -S)" = "$rules" ] && say rules same || say rules changed
        say verify "$(sh "$ENG" verify)"
        say status "$(tailnet_status)"
        say new_tun4 "$(from_far 4 $OTHER4 47000 5)"
        say new_tun6 "$(from_far 6 $OTHER6 47000 5)"
        say off_tailnet "$(written 4 ts 198.51.100.7 $PHONE4 47000 5)"
        # The existing connection isn't tied to the interface it started on.
        : > "$WORK/far.go"
        wait_for "$WORK/far.result"
        say session "$(cat "$WORK/far.result")"

        # Tailscale goes away, and another VPN's new tun happens to get its old name.
        stop_tun ts tun1
        near_tun tun1 ts ch.protonvpn.android
        ip addr add 10.2.0.2/32 dev tun1
        ip link set tun1 up
        export TEST_VPN_OWNER=ch.protonvpn.android
        say status_after "$(tailnet_status)"
        before=$(kv ipv4_tunnel_tailnet)
        # That address isn't local any more, so the packet can't reach the filter at all.
        say forged "$(written 4 ts $FAR4 $PHONE4 47000 5)"
        say hits_unchanged "$([ "$(kv ipv4_tunnel_tailnet)" = "$before" ] && echo yes || echo no)"
        say its_own_inbound "$(written 4 ts 198.51.100.7 10.2.0.2 47000 5)"
        : > "$WORK/ssh.stop"
        ''')
        self.assertEqual(values['before4'], '5')
        self.assertEqual(values['rules'], 'same')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['status'], 'VERIFIED iface=tun1;')
        self.assertEqual(values['new_tun4'], '5')
        self.assertEqual(values['new_tun6'], '5')
        self.assertEqual(values['off_tailnet'], '0')
        self.assertEqual(values['session'], 'SSH-2.0-loopback SSH-2.0-loopback')
        self.assertEqual(values['status_after'], 'DOWN;')
        self.assertEqual(values['forged'], '0')
        self.assertEqual(values['hits_unchanged'], 'yes')
        self.assertEqual(values['its_own_inbound'], '0')

    def test_pins_close_cgnat_trust_but_not_injection_to_the_node(self):
        '''A deliberate injector still reaches the pin; another VPN address is blocked.'''
        values = self.namespace(r'''
        tailscale tun1
        near_tun tun9 other ch.protonvpn.android
        ip link set tun9 up
        sh "$ENG" enable >/dev/null || exit 91
        sh "$ENG" tunnel-on >/dev/null || exit 92
        # A second tun alongside Tailscale can claim tailnet addresses. The kernel can't tell
        # them apart: no owner match, and no addrtype on the phone's kernel.
        say second_tun "$(written 4 other $FAR4 $PHONE4 47000 5)"
        say second_tun_off_tailnet "$(written 4 other 198.51.100.7 $PHONE4 47000 5)"
        # Another VPN whose own address is in Tailscale's range. Reported, since it's visible.
        ip addr add 100.70.0.9/32 dev tun9
        say status "$(tailnet_status)"
        say cgnat_peer "$(written 4 other 100.70.0.1 100.70.0.9 47000 5)"
        say cgnat_vpn_internet "$(written 4 other 198.51.100.7 100.70.0.9 47000 5)"
        ''')
        self.assertEqual(values['second_tun'], '5')
        self.assertEqual(values['second_tun_off_tailnet'], '0')
        self.assertEqual(values['status'], 'VERIFIED iface=tun1;UNVERIFIED iface=tun9 owner=unknown proof=none;')
        self.assertEqual(values['cgnat_peer'], '0')
        self.assertEqual(values['cgnat_vpn_internet'], '0')

    @unittest.skipIf(NO_WIREGUARD, NO_WIREGUARD)
    def test_kernel_wireguard_is_filtered_inside_while_its_own_udp_keeps_working(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$ENG" enable >/dev/null || exit 91
        authorization_tun
        umask 077
        wg genkey > "$WORK/a.key"; wg genkey > "$WORK/b.key"
        a_pub=$(wg pubkey < "$WORK/a.key"); b_pub=$(wg pubkey < "$WORK/b.key")
        # Named after its server, as on a real phone: nothing in the name says WireGuard.
        ip link add US-TEST-1 type wireguard
        wg set US-TEST-1 private-key "$WORK/a.key" listen-port 51820 peer "$b_pub" allowed-ips 0.0.0.0/0,::/0 endpoint 10.9.0.2:51821
        ip addr add 10.2.0.2/32 dev US-TEST-1
        ip -6 addr add fd00:2::2/128 dev US-TEST-1 nodad
        ip link set US-TEST-1 up
        ip route add 10.2.0.1/32 dev US-TEST-1
        ip -6 route add fd00:2::1/128 dev US-TEST-1
        peer ip link add far-wg type wireguard
        peer wg set far-wg private-key "$WORK/b.key" listen-port 51821 peer "$a_pub" allowed-ips 10.2.0.2/32,fd00:2::2/128 endpoint 10.9.0.1:51820
        peer ip addr add 10.2.0.1/32 dev far-wg
        peer ip -6 addr add fd00:2::1/128 dev far-wg nodad
        peer ip link set far-wg up
        peer ip route add 10.2.0.2/32 dev far-wg
        peer ip -6 route add fd00:2::2/128 dev far-wg
        # What a wg setup leaves on the phone, ahead of PocketUFW's hooks.
        iptables -w -I INPUT 1 -p udp --dport 51820 -m comment --comment "wireguard rule US-TEST-1" -j ACCEPT
        inner() { # FAM DST PORT COUNT
          local mark="$WORK/mark.$RANDOM$RANDOM"
          $N recv "$1" "$3" "$4" "$mark.ready" "$mark.stop" > "$mark.out" &
          local listener=$!
          wait_for "$mark.ready"
          peer $N send "$1" "$2" "$3" "$4"
          sleep 0.2
          : > "$mark.stop"
          wait "$listener"
          cat "$mark.out"
        }
        # WireGuard needs a handshake first; the phone's own traffic makes one.
        peer $N echo 4 7777 "$WORK/echo4a" &
        wait_for "$WORK/echo4a"
        say replies_off "$($N ask 4 10.2.0.1 7777 3)"
        say kernel_type "$(sh "$DEVICE/engine/vpn-probe" tunnels | grep '^tunnel=US-TEST-1 ')"
        say control4 "$(inner 4 10.2.0.2 47931 5)"
        say control6 "$(inner 6 fd00:2::2 47931 5)"
        sh "$ENG" tunnel-on >/dev/null || exit 92
        say verify "$(sh "$ENG" verify)"
        say hooks "$(kv tunnel_hooks)"
        say inner4 "$(inner 4 10.2.0.2 47931 5)"
        say inner6 "$(inner 6 fd00:2::2 47931 5)"
        say blocked4 "$(kv ipv4_tunnel_blocked)"
        say blocked6 "$(kv ipv6_tunnel_blocked)"
        # The tailnet rule reaches tuns only, so a WireGuard peer can't use those addresses.
        ip addr add 100.64.0.1/32 dev US-TEST-1
        peer ip addr add 100.64.0.2/32 dev far-wg
        peer wg set far-wg peer "$a_pub" allowed-ips 10.2.0.2/32,fd00:2::2/128,100.64.0.1/32
        peer ip route add 100.64.0.1/32 dev far-wg src 100.64.0.2
        say claims_tailnet "$(inner 4 100.64.0.1 47931 5)"
        say tailnet_hits "$(kv ipv4_tunnel_tailnet)"
        # A later rename crosses the wildcard boundary. It cannot be authenticated
        # by static rules: detect and disclose the conflict instead of claiming ACTIVE.
        ip link set US-TEST-1 down
        ip link set US-TEST-1 name tun5
        ip link set tun5 up
        ip route replace 10.2.0.1/32 dev tun5
        peer $N echo 4 7779 "$WORK/echo-renamed" &
        wait_for "$WORK/echo-renamed"
        say renamed_replies "$($N ask 4 10.2.0.1 7779 3)"
        say renamed_state "$(sh "$ENG" verify)"
        say renamed_conflict "$(sh "$ENG" tunnel-status | sed -n 's/^tailnet_wireguard=//p')"
        say renamed_pinned_injection "$(inner 4 100.64.0.1 47932 5)"
        sh "$ENG" tunnel-off >/dev/null || exit 94
        sh "$ENG" tunnel-on --deny-only >/dev/null || exit 95
        say deny_wg_state "$(sh "$ENG" verify)"
        say deny_wg_pin "$(inner 4 100.64.0.1 47932 5)"
        ip link set tun5 down
        ip link set tun5 name US-TEST-1
        ip link set US-TEST-1 up
        ip route replace 10.2.0.1/32 dev US-TEST-1
        ip -6 route replace fd00:2::1/128 dev US-TEST-1
        sh "$ENG" tunnel-refresh >/dev/null || exit 96
        # Replies to what the phone started pass, so the encrypted path still runs too.
        sleep 1.6
        peer $N echo 4 7778 "$WORK/echo4b" &
        wait_for "$WORK/echo4b"
        say replies_on "$($N ask 4 10.2.0.1 7778 3)"
        # Its own rule, like everyone else's, is left exactly as it was.
        say foreign_rule "$(iptables -w -S INPUT | grep -c 'wireguard rule US-TEST-1')"
        sh "$ENG" disable >/dev/null || exit 93
        say foreign_rule_after "$(iptables -w -S INPUT | grep -c 'wireguard rule US-TEST-1')"
        say residue "$(iptables -w -S | grep -ci pocketufw)"
        ''')
        self.assertEqual(values['replies_off'], '3')
        self.assertEqual(values['kernel_type'], 'tunnel=US-TEST-1 kind=wireguard owner=kernel proof=kernel-type')
        self.assertEqual(values['control4'], '5')
        self.assertEqual(values['control6'], '5')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['hooks'], 'tun+,US-TEST-1')
        self.assertEqual(values['inner4'], '0')
        self.assertEqual(values['inner6'], '0')
        self.assertEqual(values['blocked4'], '5')
        self.assertGreaterEqual(int(values['blocked6']), 5)
        self.assertEqual(values['claims_tailnet'], '0')
        self.assertEqual(values['tailnet_hits'], '0')
        self.assertEqual(values['renamed_state'], 'DEGRADED')
        self.assertEqual(values['renamed_conflict'], 'CONFLICT')
        self.assertEqual(values['renamed_replies'], '3')
        self.assertEqual(values['renamed_pinned_injection'], '5', values)
        self.assertEqual(values['deny_wg_state'], 'ACTIVE')
        self.assertEqual(values['deny_wg_pin'], '0')
        self.assertEqual(values['replies_on'], '3')
        self.assertEqual(values['foreign_rule'], '1')
        self.assertEqual(values['foreign_rule_after'], '1')
        self.assertEqual(values['residue'], '0')

    def test_one_ui_reset_clears_physical_and_tunnel_counts_and_keeps_enforcement(self):
        values = self.namespace(r'''
        link wlan0 9
        other_vpn tun7
        authorization_tun
        sh "$BRIDGE" enable >/dev/null || exit 91
        sh "$BRIDGE" tunnel-on PINNED >/dev/null || exit 92
        say wifi4 "$(deliver 4 9 47931 5)"
        say wifi6 "$(deliver 6 9 47931 5)"
        say tun4 "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        say tun6 "$(to_phone 6 fd00:2::1 fd00:2::2 47931 5)"
        peer $N echo 4 7777 "$WORK/echo" &
        wait_for "$WORK/echo"
        say replies "$($N ask 4 10.2.0.1 7777 3)"
        for key in ipv4_blocked ipv6_blocked ipv4_tunnel_blocked ipv6_tunnel_blocked ipv4_tunnel_established_replies; do
          say "before_$key" "$(kv "$key")"
        done
        before4=$(iptables -w -S); before6=$(ip6tables -w -S)
        say reset "$(bridge_value reset-counters operation)"
        [ "$(iptables -w -S)" = "$before4" ] && say same4 yes
        [ "$(ip6tables -w -S)" = "$before6" ] && say same6 yes
        snapshot=$(sh "$BRIDGE" counters)
        say after "$(printf '%s\n' "$snapshot" | grep -E '^ipv[46]_(tunnel_)?(blocked|blocked_bytes|established_replies|tailnet)=' | cut -d= -f2 | tr '\n' ' ')"
        say wifi_after "$(deliver 4 9 47933 5)"
        say tunnel_after "$(to_phone 6 fd00:2::1 fd00:2::2 47933 5)"
        say physical_count_after "$(kv ipv4_blocked)"
        say tunnel_count_after "$(kv ipv6_tunnel_blocked)"
        say verified "$(sh "$ENG" verify)"
        ''')
        for path in ('wifi4', 'wifi6', 'tun4', 'tun6', 'wifi_after', 'tunnel_after'):
            self.assertEqual(values[path], '0', path)
        self.assertEqual(values['replies'], '3')
        for key in ('ipv4_blocked', 'ipv6_blocked', 'ipv4_tunnel_blocked', 'ipv6_tunnel_blocked'):
            self.assertGreaterEqual(int(values['before_' + key]), 5)
        self.assertGreaterEqual(int(values['before_ipv4_tunnel_established_replies']), 3)
        self.assertEqual(values['after'].split(), ['0'] * 14)
        self.assertEqual(values['reset'], 'SUCCESS')
        self.assertEqual((values['same4'], values['same6']), ('yes', 'yes'))
        self.assertEqual(values['verified'], 'ACTIVE')
        self.assertGreaterEqual(int(values['physical_count_after']), 5)
        self.assertGreaterEqual(int(values['tunnel_count_after']), 5)

    def test_the_bridge_reports_what_is_filtered_and_removal_leaves_nothing(self):
        values = self.namespace(r'''
        link wlan0 9
        tailscale tun0
        baseline4=$(iptables -w -S); baseline6=$(ip6tables -w -S)
        sh "$BRIDGE" enable >/dev/null
        say uncovered_off "$(bridge_value inspect uncovered_ifaces)"
        sh "$ENG" tunnel-on >/dev/null || exit 92
        report=$(sh "$BRIDGE" inspect 2>/dev/null)
        field() { printf '%s\n' "$report" | sed -n "s/^$1=//p"; }
        say state "$(field state)"
        say uncovered_on "$(field uncovered_ifaces)"
        say report "$(field rules_report)"
        say hook4 "$(field hook4_04)"
        say main4 "$(field main4_12)"
        say filter "$(field tunnel_filter)"
        say blocked "$(field ipv4_tunnel_blocked)"
        counters=$(sh "$BRIDGE" counters 2>/dev/null)
        say counters "$(printf '%s\n' "$counters" | grep -c '^ipv6_tunnel_blocked=')"
        say reset "$(bridge_value reset-counters operation)"
        # An unsupported tunnel stays named as not filtered.
        ip link add gre9 type ipip local 10.9.0.1 remote 10.9.0.2 2>/dev/null ||
          ip link add gre9 type dummy
        ip addr add 192.0.2.1/32 dev gre9
        ip link set gre9 up
        say uncovered_other "$(bridge_value inspect uncovered_ifaces)"
        ip link del gre9
        # Off the same way the app's Off does it.
        say disable "$(bridge_value disable operation)"
        say verify_off "$(sh "$ENG" verify)"
        sh "$BRIDGE" enable >/dev/null
        sh "$ENG" tunnel-on >/dev/null || exit 93
        removal=$(sh "$BRIDGE" prepare-uninstall 2>/dev/null)
        say removal "$(printf '%s\n' "$removal" | sed -n 's/^removal=//p')"
        say left "$(printf '%s\n' "$removal" | sed -n 's/^removal_left=//p')"
        [ "$(iptables -w -S)" = "$baseline4" ] && say table4 baseline || say table4 changed
        [ "$(ip6tables -w -S)" = "$baseline6" ] && say table6 baseline || say table6 changed
        say delivered "$(from_far 4 $FAR4 47931 5)"
        ''')
        self.assertEqual(values['uncovered_off'], 'tun0')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['uncovered_on'], '')
        self.assertEqual(values['report'], 'READY')
        self.assertIn('-i tun+ -m comment --comment PocketUFW-VPN -j POCKETUFW_VPN', values['hook4'])
        self.assertEqual(values['main4'], '-A POCKETUFW_VPN -j DROP')
        self.assertEqual(values['filter'], 'ON')
        self.assertEqual(values['blocked'], '0')
        self.assertEqual(values['counters'], '1')
        self.assertEqual(values['reset'], 'SUCCESS')
        self.assertEqual(values['uncovered_other'], 'gre9')
        self.assertEqual(values['disable'], 'SUCCESS')
        self.assertEqual(values['verify_off'], 'INACTIVE')
        self.assertEqual(values['removal'], 'CLEAN')
        self.assertEqual(values['left'], '')
        self.assertEqual(values['table4'], 'baseline')
        self.assertEqual(values['table6'], 'baseline')
        self.assertEqual(values['delivered'], '5')

    def test_a_new_kernel_wireguard_is_named_as_not_filtered_until_refresh(self):
        if NO_WIREGUARD:
            self.skipTest(NO_WIREGUARD)
        values = self.namespace(r'''
        link wlan0 9
        authorization_tun
        sh "$ENG" enable >/dev/null || exit 91
        sh "$ENG" tunnel-on >/dev/null || exit 92
        ip link add US-TEST-2 type wireguard
        ip addr add 10.2.0.2/32 dev US-TEST-2
        ip link set US-TEST-2 up
        say before "$(bridge_value inspect uncovered_ifaces)"
        sh "$ENG" tunnel-refresh >/dev/null || exit 93
        say after "$(bridge_value inspect uncovered_ifaces)"
        ip link del US-TEST-2
        sh "$ENG" tunnel-refresh >/dev/null || exit 94
        say hooks "$(kv tunnel_hooks)"
        ''')
        self.assertEqual(values['before'], 'US-TEST-2')
        self.assertEqual(values['after'], '')
        self.assertEqual(values['hooks'], 'tun+')

    def test_the_readmes_manual_cleanup_removes_everything_with_or_without_the_filter(self):
        readme = (PROJECT / 'README.md').read_text()
        section = readme[readme.index('To clear the rules without restarting'):]
        commands = section[section.index('```sh\n') + 6:section.index('\n```', section.index('```sh\n'))]
        (self.work / 'cleanup.sh').write_text(commands + '\n')
        for tunnel in ('sh "$ENG" tunnel-on >/dev/null || exit 92', ':'):
            with self.subTest(tunnel=tunnel):
                values = self.namespace(rf'''
                tailscale tun0
                baseline4=$(iptables -w -S); baseline6=$(ip6tables -w -S)
                sh "$ENG" enable >/dev/null || exit 91
                {tunnel}
                sh "$WORK/cleanup.sh" >/dev/null 2>&1
                say residue "$(sh "$ENG" residue | tr '\n' ' ')"
                [ "$(iptables -w -S)" = "$baseline4" ] && say table4 baseline || say table4 changed
                [ "$(ip6tables -w -S)" = "$baseline6" ] && say table6 baseline || say table6 changed
                say verify "$(sh "$ENG" verify)"
                ''')
                self.assertEqual(values['residue'], 'residue_ipv4=0 residue_ipv6=0 ')
                self.assertEqual(values['table4'], 'baseline')
                self.assertEqual(values['table6'], 'baseline')
                self.assertEqual(values['verify'], 'INACTIVE')

    def test_a_restart_never_brings_the_tunnel_filter_back(self):
        values = self.namespace(r'''
        link wlan0 9
        tailscale tun0
        sh "$BRIDGE" enable >/dev/null
        sh "$ENG" tunnel-on >/dev/null || exit 92
        say arm "$(bridge_value boot-enable operation)"
        # A restart empties the kernel's tables and leaves the boot files.
        sh "$ENG" disable >/dev/null || exit 93
        sh "$DEVICE/service.d/pocketufw.sh" >/dev/null 2>&1; say hook_status "$?"
        say verify "$(sh "$ENG" verify)"
        say filter "$(kv tunnel_filter)"
        say chains "$(iptables -w -S | grep -c POCKETUFW_VPN)"
        ''')
        self.assertEqual(values['arm'], 'SUCCESS')
        self.assertEqual(values['hook_status'], '0')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['filter'], 'OFF')
        self.assertEqual(values['chains'], '0')

    def test_rollback_reopens_the_tunnel_and_leaves_the_firewall_on(self):
        values = self.namespace(r'''
        link wlan0 9
        other_vpn tun0
        authorization_tun
        sh "$ENG" enable >/dev/null || exit 91
        say armed "$(sh "$ROLLBACK" on 1 "$ENG" | sed -n 's/^rollback=\(ARMED\).*/\1/p')"
        say during "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        tries=0
        until [ "$(sh "$ROLLBACK" status)" = rollback=FIRED ]; do
          tries=$((tries + 1)); [ "$tries" -lt 80 ] || exit 94; sleep 0.1
        done
        say filter "$(kv tunnel_filter)"
        say verify "$(sh "$ENG" verify)"
        say after "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        say wifi "$(deliver 4 9 47931 5)"
        ''')
        self.assertEqual(values['armed'], 'ARMED')
        self.assertEqual(values['during'], '0')
        self.assertEqual(values['filter'], 'OFF')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['after'], '5')
        self.assertEqual(values['wifi'], '0')

    def test_confirm_keeps_the_filter_past_the_deadline(self):
        values = self.namespace(r'''
        other_vpn tun0
        authorization_tun
        sh "$ENG" enable >/dev/null || exit 91
        sh "$ROLLBACK" on 1 "$ENG" >/dev/null || exit 92
        say confirm "$(sh "$ROLLBACK" confirm)"
        sleep 1.6
        say filter "$(kv tunnel_filter)"
        say delivered "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        ''')
        self.assertEqual(values['confirm'], 'rollback=CONFIRMED')
        self.assertEqual(values['filter'], 'ON')
        self.assertEqual(values['delivered'], '0')

    def test_a_partial_install_with_failed_cleanup_keeps_the_timer_on_real_rules(self):
        values = self.namespace(r'''
        link wlan0 9
        other_vpn tun0
        authorization_tun
        sh "$ENG" enable >/dev/null || exit 91
        # Real tables, with chosen commands failing for as long as a marker exists.
        for t in iptables ip6tables; do
          cat > "$WORK/$t-shim" <<SHIM
#!/bin/sh
if [ -e "$WORK/broken" ]; then
  case " \$* " in
    *" -A INPUT -i tun+ "*) [ "$t" != ip6tables ] || exit 7 ;;
    *" -D INPUT -i tun+ "*|*" -F POCKETUFW_VPN "*|*" -X POCKETUFW_VPN "*) exit 7 ;;
  esac
fi
exec $t "\$@"
SHIM
          chmod +x "$WORK/$t-shim"
        done
        export POCKETUFW_IPTABLES4="$WORK/iptables-shim" POCKETUFW_IPTABLES6="$WORK/ip6tables-shim"
        export POCKETUFW_ROLLBACK_RETRY_SECONDS=1
        : > "$WORK/broken"
        sh "$ROLLBACK" on 120 "$ENG" >/dev/null 2>&1; say exit "$?"
        status_now=$(sh "$ROLLBACK" status)
        say status "${status_now%% *}"
        say hook4 "$(iptables -w -S INPUT | grep -c PocketUFW-VPN)"
        say hook6 "$(ip6tables -w -S INPUT | grep -c PocketUFW-VPN)"
        say verify_partial "$(sh "$ENG" verify)"
        # Half a filter really is in the kernel, on IPv4 only.
        say partial4 "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        say partial6 "$(to_phone 6 fd00:2::1 fd00:2::2 47931 5)"
        sh "$ROLLBACK" confirm >/dev/null 2>&1; say confirm "$?"
        rm "$WORK/broken"
        tries=0
        until [ "$(sh "$ROLLBACK" status)" = rollback=FIRED ]; do
          tries=$((tries + 1)); [ "$tries" -lt 100 ] || exit 94; sleep 0.1
        done
        say residue "$(iptables -w -S | grep -c -E 'POCKETUFW_VPN|PocketUFW-VPN')/$(ip6tables -w -S | grep -c -E 'POCKETUFW_VPN|PocketUFW-VPN')"
        say verify "$(sh "$ENG" verify)"
        say after4 "$(to_phone 4 10.2.0.1 10.2.0.2 47931 5)"
        say wifi "$(deliver 4 9 47931 5)"
        ''', timeout=120)
        self.assertEqual(values['exit'], '1')
        self.assertEqual(values['status'], 'rollback=UNCLEAN')
        self.assertEqual(values['hook4'], '1')
        self.assertEqual(values['hook6'], '0')
        self.assertEqual(values['verify_partial'], 'DEGRADED')
        self.assertEqual(values['partial4'], '0')
        self.assertEqual(values['partial6'], '5')
        self.assertEqual(values['confirm'], '1')
        self.assertEqual(values['residue'], '0/0')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['after4'], '5')
        self.assertEqual(values['wifi'], '0')

    def test_physical_rollback_removes_the_whole_firewall(self):
        values = self.namespace(r'''
        link wlan0 9
        baseline4=$(iptables -w -S); baseline6=$(ip6tables -w -S)
        say armed "$(sh "$ROLLBACK" physical 1 "$ENG" | sed -n 's/^rollback=\(ARMED\).*/\1/p')"
        say verify_on "$(sh "$ENG" verify)"
        say during "$(deliver 4 9 47931 5)"
        tries=0
        until [ "$(sh "$ROLLBACK" status)" = rollback=FIRED ]; do
          tries=$((tries + 1)); [ "$tries" -lt 80 ] || exit 94; sleep 0.1
        done
        say verify_off "$(sh "$ENG" verify)"
        [ "$(iptables -w -S)" = "$baseline4" ] && say table4 baseline || say table4 changed
        [ "$(ip6tables -w -S)" = "$baseline6" ] && say table6 baseline || say table6 changed
        say after "$(deliver 4 9 47931 5)"
        ''')
        self.assertEqual(values['armed'], 'ARMED')
        self.assertEqual(values['verify_on'], 'ACTIVE')
        self.assertEqual(values['during'], '0')
        self.assertEqual(values['verify_off'], 'INACTIVE')
        self.assertEqual(values['table4'], 'baseline')
        self.assertEqual(values['table6'], 'baseline')
        self.assertEqual(values['after'], '5')


if __name__ == '__main__':
    unittest.main()
