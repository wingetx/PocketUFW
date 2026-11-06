"""The real scripts on real netfilter, judged by real packets.

The mock iptables can only say whether a rule's text matches. This suite asks
the only question that matters: does the packet arrive? Each test runs in its own
unprivileged user and network namespace, so the host's firewall and interfaces are
out of reach. It skips when the host cannot provide that.
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

# Everything the namespaced scripts may need, whichever way a distro lays out sbin.
PATH_TAIL = os.pathsep.join(dict.fromkeys(os.environ.get('PATH', '').split(os.pathsep) + ['/usr/sbin', '/sbin', '/usr/bin', '/bin']))
REQUIRED = ('unshare', 'nsenter', 'ip', 'iptables', 'ip6tables', 'ss', 'flock', 'bash', 'awk', 'stat')

PREFLIGHT = r'''
set -e
ip link set lo up
ip link add probe0 type veth peer name probe1
for ipt in iptables ip6tables; do
  "$ipt" -w -N POCKETUFW_PREFLIGHT
  "$ipt" -w -A POCKETUFW_PREFLIGHT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  "$ipt" -w -A POCKETUFW_PREFLIGHT -m conntrack --ctstate INVALID -j DROP
  "$ipt" -w -A POCKETUFW_PREFLIGHT -p udp --sport 67 --dport 68 -j ACCEPT
  "$ipt" -w -A INPUT -i wlan+ -m comment --comment Preflight -j POCKETUFW_PREFLIGHT
  "$ipt" -w -L POCKETUFW_PREFLIGHT -n -v -x >/dev/null
done
unshare -n true
'''


def unusable_reason():
    missing = [tool for tool in REQUIRED if shutil.which(tool, path=PATH_TAIL) is None]
    if missing:
        return 'missing ' + ', '.join(missing)
    try:
        probe = subprocess.run(['unshare', '-Urn', 'bash', '-c', PREFLIGHT], capture_output=True, text=True,
                               timeout=30, env={**os.environ, 'PATH': PATH_TAIL})
    except (OSError, subprocess.SubprocessError) as error:
        return f'unshare -Urn failed: {error}'
    if probe.returncode != 0:
        return f'unprivileged namespace with netfilter not usable: {probe.stderr.strip()[:200]}'
    return None


UNUSABLE = unusable_reason()

# Runs inside the namespaces only. stdlib-only; python3 -I keeps it isolated.
NET = r'''
import os, select, socket, struct, sys, time

def family(name):
    return socket.AF_INET6 if name == '6' else socket.AF_INET

def recv(fam, port, expected, ready, stop):
    """Count datagrams until the expected number came, or the sender has been done a while."""
    s = socket.socket(family(fam), socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == '6':
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(('::' if fam == '6' else '0.0.0.0', int(port)))
    open(ready, 'w').close()
    count, done_at, deadline = 0, None, time.time() + 20
    while time.time() < deadline and count < int(expected):
        if select.select([s], [], [], 0.02)[0]:
            s.recv(2048)
            count += 1
        if done_at is None and os.path.exists(stop):
            done_at = time.time()
        if done_at is not None and time.time() - done_at > 0.25:
            break
    print(count)

def send(fam, host, port, count, size='20'):
    s = socket.socket(family(fam), socket.SOCK_DGRAM)
    for _ in range(int(count)):
        s.sendto(b'x' * int(size), (host, int(port)))
        time.sleep(0.002)

def tcp(fam, host, port, seconds):
    s = socket.socket(family(fam), socket.SOCK_STREAM)
    s.settimeout(float(seconds))
    try:
        s.connect((host, int(port)))
        print('CONNECTED')
    except socket.timeout:
        print('TIMEOUT')
    except ConnectionRefusedError:
        print('REFUSED')

def echo(fam, port, ready):
    """Answer datagrams until told to stop by a quiet socket."""
    s = socket.socket(family(fam), socket.SOCK_DGRAM)
    if fam == '6':
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(('::' if fam == '6' else '0.0.0.0', int(port)))
    s.settimeout(1.5)
    open(ready, 'w').close()
    try:
        while True:
            data, peer = s.recvfrom(2048)
            s.sendto(data, peer)
    except socket.timeout:
        pass

def ask(fam, host, port, count):
    """The phone starts the conversation; count the replies."""
    s = socket.socket(family(fam), socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect((host, int(port)))
    got = 0
    for _ in range(int(count)):
        s.send(b'ping')
        try:
            s.recv(64)
            got += 1
        except socket.timeout:
            pass
    print(got)

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff

def invalid_tcp(fam, source, target, count):
    """SYN+FIN with a correct checksum: conntrack calls this INVALID."""
    source_port, target_port, flags = 40000, 47000, 0x03
    header = struct.pack('!HHIIBBHHH', source_port, target_port, 1, 0, 5 << 4, flags, 1024, 0, 0)
    if fam == '6':
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_RAW, 7, 16)  # IPV6_CHECKSUM at the TCP checksum offset.
        s.bind((source, 0))
        destination = (target, 0)
        packet = header
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.bind((source, 0))
        destination = (target, 0)
        pseudo = socket.inet_aton(source) + socket.inet_aton(target) + struct.pack('!BBH', 0, 6, len(header))
        packet = header[:16] + struct.pack('!H', checksum(pseudo + header)) + header[18:]
    for _ in range(int(count)):
        s.sendto(packet, destination)
        time.sleep(0.002)

def fakeapp(name, ports, ready, stop):
    """An ordinary process claiming a name; argv[0] comes from whoever ran it."""
    import ctypes
    ctypes.CDLL(None).prctl(15, name.encode(), 0, 0, 0)  # PR_SET_NAME
    sockets = []
    for item in ports.split(','):
        fam, port = item.split(':')
        s = socket.socket(family(fam), socket.SOCK_DGRAM)
        if fam == '6':
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind(('::' if fam == '6' else '0.0.0.0', int(port)))
        sockets.append(s)
    open(ready, 'w').close()
    count, deadline = 0, time.time() + 30
    while time.time() < deadline and not os.path.exists(stop):
        for s in select.select(sockets, [], [], 0.02)[0]:
            s.recv(2048)
            count += 1
    print(count)

{'recv': recv, 'send': send, 'tcp': tcp, 'echo': echo, 'ask': ask,
 'invalid_tcp': invalid_tcp, 'fakeapp': fakeapp}[sys.argv[1]](*sys.argv[2:])
'''

PRELUDE = r'''
set -u
ENG="$DEVICE/engine/pocketufw"
BRIDGE="$DEVICE/engine/android-bridge"
N="python3 -I $WORK/net.py"
LINKS=0
ip link set lo up
unshare -n sleep 300 >/dev/null 2>&1 &
PEER=$!
trap 'kill "$PEER" 2>/dev/null' EXIT
while [ "$(readlink /proc/$PEER/ns/net 2>/dev/null)" = "$(readlink /proc/$$/ns/net)" ]; do sleep 0.01; done
peer() { nsenter -t "$PEER" -n --preserve-credentials "$@"; }
peer ip link set lo up

say() { printf '%s=%s\n' "$1" "$2"; }
# A helper that could not start must fail the scenario, not hang it.
wait_for() {
  local tries=0
  while [ ! -e "$1" ]; do
    tries=$((tries + 1))
    [ "$tries" -lt 1000 ] || { echo "gave up waiting for $1" >&2; exit 93; }
    sleep 0.01
  done
}
# link IFNAME SUBNET: an interface here, wired to the peer, addressed in both families.
link() {
  LINKS=$((LINKS + 1))
  local far="peer$LINKS"
  ip link add "$1" type veth peer name "$far" || exit 90
  ip link set "$far" netns "$PEER"
  ip addr add "10.$2.0.1/24" dev "$1"
  ip -6 addr add "fd$2::1/64" dev "$1" nodad
  ip link set "$1" up
  peer ip addr add "10.$2.0.2/24" dev "$far"
  peer ip -6 addr add "fd$2::2/64" dev "$far" nodad
  peer ip link set "$far" up
  # Addresses and carrier come up asynchronously.
  while ! peer ip -o link show "$far" | grep -q LOWER_UP; do sleep 0.01; done
}
addr_of() { if [ "$1" = 4 ]; then echo "10.$2.0.1"; else echo "fd$2::1"; fi; }
# deliver FAM SUBNET PORT COUNT: datagrams from the peer that really reach a listener here.
deliver() {
  local mark="$WORK/mark.$RANDOM$RANDOM"
  $N recv "$1" "$3" "$4" "$mark.ready" "$mark.stop" > "$mark.out" &
  local listener=$!
  wait_for "$mark.ready"
  peer $N send "$1" "$(addr_of "$1" "$2")" "$3" "$4"
  : > "$mark.stop"
  wait "$listener"
  cat "$mark.out"
}
kv() { sh "$ENG" activity 2>/dev/null | sed -n "s/^$1=//p"; }
bridge_value() { sh "$BRIDGE" "$1" 2>/dev/null | sed -n "s/^$2=//p"; }
clean() { sh "$ENG" disable >/dev/null 2>&1; }
'''


@unittest.skipIf(UNUSABLE, UNUSABLE)
class RealKernelTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pufw-kernel-')
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        (self.work / 'net.py').write_text(NET)
        self.device = Device(self.work / 'device', PATH_TAIL)
        self.ts_data = self.work / 'tailscale-data'
        self.ts_data.mkdir()
        # Inside the namespace this process is mapped to UID 0.
        self.packages = self.work / 'packages.list'
        self.packages.write_text('com.tailscale.ipn 0 0\n')

    def namespace(self, body, timeout=90):
        """Run a scenario in fresh namespaces. It reports through key=value lines."""
        script = self.work / 'scenario.sh'
        script.write_text(PRELUDE + body)
        env = {**self.device.env(dict(os.environ)), 'WORK': str(self.work), 'DEVICE': str(self.device.root),
               'POCKETUFW_PACKAGES_LIST': str(self.packages)}
        # Its own session, so that a hang cannot leave namespace helpers behind.
        process = subprocess.Popen(['unshare', '-Urn', 'bash', str(script)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            self.fail(f'scenario hung\n{stdout}\n{stderr}')
        self.assertEqual(process.returncode, 0, f'scenario failed\n{stdout}\n{stderr}')
        return dict(line.split('=', 1) for line in stdout.splitlines() if '=' in line)

    def test_hooked_interfaces_deliver_nothing_unsolicited(self):
        values = self.namespace(r'''
        link wlan0 9
        link rmnet_data0 10
        link v4-rmnet_data0 11
        for subnet in 9 10 11; do
          say "before4_$subnet" "$(deliver 4 "$subnet" 47931 10)"
          say "before6_$subnet" "$(deliver 6 "$subnet" 47931 10)"
        done
        say tcp_before "$(peer $N tcp 4 10.9.0.1 47932 1)"
        sh "$ENG" enable >/dev/null || exit 91
        say verify "$(sh "$ENG" verify)"
        for subnet in 9 10 11; do
          say "after4_$subnet" "$(deliver 4 "$subnet" 47931 10)"
          say "after6_$subnet" "$(deliver 6 "$subnet" 47931 10)"
        done
        say tcp_after "$(peer $N tcp 4 10.9.0.1 47932 0.4)"
        ''')
        self.assertEqual(values['verify'], 'ACTIVE')
        for subnet in ('9', '10', '11'):
            # The control proves the listener and the path work; only the firewall changed.
            self.assertEqual(values[f'before4_{subnet}'], '10')
            self.assertEqual(values[f'before6_{subnet}'], '10')
            self.assertEqual(values[f'after4_{subnet}'], '0')
            self.assertEqual(values[f'after6_{subnet}'], '0')
        self.assertEqual(values['tcp_before'], 'REFUSED')
        self.assertEqual(values['tcp_after'], 'TIMEOUT')

    def test_replies_to_what_the_phone_started_pass_and_are_counted(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$ENG" enable >/dev/null || exit 91
        peer $N echo 4 7777 "$WORK/echo4" &
        peer $N echo 6 7777 "$WORK/echo6" &
        wait_for "$WORK/echo4"
        wait_for "$WORK/echo6"
        say replies4 "$($N ask 4 10.9.0.2 7777 7)"
        say replies6 "$($N ask 6 fd9::2 7777 5)"
        say established4 "$(kv ipv4_established_replies)"
        say established6 "$(kv ipv6_established_replies)"
        say blocked4 "$(kv ipv4_blocked)"
        say blocked6 "$(kv ipv6_blocked)"
        # The same peer, unsolicited, on another port, is still refused.
        say unsolicited "$(deliver 4 9 47931 5)"
        say blocked4_after "$(kv ipv4_blocked)"
        ''')
        self.assertEqual(values['replies4'], '7')
        self.assertEqual(values['replies6'], '5')
        self.assertEqual(values['established4'], '7')
        self.assertEqual(values['established6'], '5')
        self.assertEqual(values['blocked4'], '0')
        self.assertEqual(values['blocked6'], '0')
        self.assertEqual(values['unsolicited'], '0')
        self.assertEqual(values['blocked4_after'], '5')

    def test_counters_are_exact_and_cover_both_drop_rules(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$ENG" enable >/dev/null || exit 91
        peer $N send 4 10.9.0.1 47931 13 20
        peer $N send 6 fd9::1 47931 9 30
        peer $N invalid_tcp 4 10.9.0.2 10.9.0.1 4
        peer $N invalid_tcp 6 fd9::2 fd9::1 3
        sh "$ENG" activity
        iptables -w -L POCKETUFW_IN -n -v -x
        ip6tables -w -L POCKETUFW_IN -n -v -x
        say invalid4 "$(iptables -w -L POCKETUFW_IN -n -v -x | awk '$3 == "DROP" && /INVALID/ { print $1 }')"
        say invalid6 "$(ip6tables -w -L POCKETUFW_IN -n -v -x | awk '$3 == "DROP" && /INVALID/ { print $1 }')"
        sh "$ENG" reset-counters >/dev/null || exit 92
        say after_reset "$(sh "$ENG" activity | grep -E 'blocked|replies' | cut -d= -f2 | tr '\n' ' ')"
        say verify "$(sh "$ENG" verify)"
        ''')
        # IPv4: 13 x (20 IP + 8 UDP + 20) + 4 x (20 IP + 20 TCP).
        # IPv6: 9 x (40 IP + 8 UDP + 30) + 3 x (40 IP + 20 TCP).
        self.assertEqual(values['invalid4'], '4')
        self.assertEqual(values['invalid6'], '3')
        self.assertEqual(values['ipv4_blocked'], '17')
        self.assertEqual(values['ipv4_blocked_bytes'], str(13 * 48 + 4 * 40))
        self.assertEqual(values['ipv6_blocked'], '12')
        self.assertEqual(values['ipv6_blocked_bytes'], str(9 * 78 + 3 * 60))
        self.assertEqual(values['after_reset'].split(), ['0'] * 6)
        self.assertEqual(values['verify'], 'ACTIVE')

    def test_allow_all_engine_passes_verify_and_is_caught_by_delivery(self):
        # The class of mutant no text comparison of its own output can see: installer
        # and verifier agree on a rule that lets everything in. This is the proof
        # that the delivery counts in this suite would notice.
        engine = self.device.engine / 'pocketufw'
        source = engine.read_text()
        for old, new in (('fw4 -A "$CHAIN" -p esp -j ACCEPT', 'fw4 -A "$CHAIN" -j ACCEPT'),
                         ('fw6 -A "$CHAIN" -p esp -j ACCEPT', 'fw6 -A "$CHAIN" -j ACCEPT'),
                         ('"$bin" -w -C "$CHAIN" -p esp -j ACCEPT', '"$bin" -w -C "$CHAIN" -j ACCEPT')):
            self.assertIn(old, source)
            source = source.replace(old, new)
        engine.write_text(source)
        values = self.namespace(r'''
        link wlan0 9
        sh "$ENG" enable >/dev/null || exit 91
        say verify "$(sh "$ENG" verify)"
        say delivered4 "$(deliver 4 9 47931 10)"
        say delivered6 "$(deliver 6 9 47931 10)"
        ''')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['delivered4'], '10')
        self.assertEqual(values['delivered6'], '10')

    def test_two_simultaneous_enables_end_active(self):
        values = self.namespace(r'''
        link wlan0 9
        active=0 one_success=0
        for round in $(seq 12); do
          clean
          sh "$ENG" enable >/dev/null 2>&1 & first=$!
          sh "$ENG" enable >/dev/null 2>&1 & second=$!
          wait "$first"; a=$?
          wait "$second"; b=$?
          [ "$(sh "$ENG" verify)" = ACTIVE ] && active=$((active + 1))
          [ $(( (a == 0) + (b == 0) )) = 1 ] && one_success=$((one_success + 1))
        done
        say active "$active"
        say one_success "$one_success"
        say delivered "$(deliver 4 9 47931 5)"
        ''')
        self.assertEqual(values['active'], '12')
        self.assertEqual(values['one_success'], '12')
        self.assertEqual(values['delivered'], '0')

    def test_a_concurrent_read_never_sees_a_half_installed_firewall(self):
        values = self.namespace(r'''
        link wlan0 9
        : > "$WORK/seen"
        for round in $(seq 8); do
          clean
          sh "$ENG" enable >/dev/null 2>&1 & enabling=$!
          for read in 1 2 3 4; do sh "$ENG" verify >> "$WORK/seen" 2>/dev/null; done
          wait "$enabling"
        done
        say degraded "$(grep -c DEGRADED "$WORK/seen")"
        say reads "$(wc -l < "$WORK/seen")"
        ''')
        self.assertEqual(values['reads'].strip(), '32')
        self.assertEqual(values['degraded'], '0')

    def test_enable_racing_disable_never_leaves_a_partial_firewall(self):
        values = self.namespace(r'''
        link wlan0 9
        : > "$WORK/final"
        for round in $(seq 10); do
          clean
          sh "$ENG" enable >/dev/null 2>&1 & a=$!
          sh "$ENG" disable >/dev/null 2>&1 & b=$!
          wait "$a"; wait "$b"
          sh "$ENG" verify >> "$WORK/final"
        done
        say degraded "$(grep -c DEGRADED "$WORK/final")"
        ''')
        self.assertEqual(values['degraded'], '0')

    def test_two_bridges_enabling_at_once_both_succeed(self):
        values = self.namespace(r'''
        link wlan0 9
        ok=0
        for round in $(seq 5); do
          clean
          sh "$BRIDGE" enable > "$WORK/one" 2>&1 & a=$!
          sh "$BRIDGE" enable > "$WORK/two" 2>&1 & b=$!
          wait "$a"; wait "$b"
          grep -q '^operation=SUCCESS$' "$WORK/one" && grep -q '^operation=SUCCESS$' "$WORK/two" && ok=$((ok + 1))
        done
        say ok "$ok"
        say verify "$(sh "$ENG" verify)"
        ''')
        self.assertEqual(values['ok'], '5')
        self.assertEqual(values['verify'], 'ACTIVE')

    def test_uncovered_interface_is_listed_and_really_is_uncovered(self):
        values = self.namespace(r'''
        link wlan0 9
        link eth0 12
        link rndis0 13
        link tun0 14
        link rmnet_data0 15
        ip link add usb0 type veth peer name usb0far
        ip addr add 10.16.0.1/24 dev usb0
        ip link add p2p0 type veth peer name p2p0far
        ip link set p2p0 up
        ip link set p2p0far up
        sh "$ENG" enable >/dev/null || exit 91
        say listed "$(bridge_value inspect uncovered_ifaces)"
        say state "$(bridge_value inspect state)"
        say hooked "$(deliver 4 9 47931 5)"
        say uncovered "$(deliver 4 12 47931 5)"
        say vpn_inner "$(deliver 4 14 47931 5)"
        ''')
        self.assertEqual(values['state'], 'ACTIVE')
        # usb0 is down and p2p0 has only a link-local address. tun0 is listed, and this
        # delivery shows why: traffic inside a VPN tunnel really isn't filtered.
        self.assertEqual(sorted(values['listed'].split(',')), ['eth0', 'rndis0', 'tun0'])
        self.assertEqual(values['hooked'], '0')
        self.assertEqual(values['uncovered'], '5')
        self.assertEqual(values['vpn_inner'], '5')

    def test_real_kernel_listing_of_rules_passes_verify_and_tampering_does_not(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$ENG" enable --tailscale-udp4 41641 --tailscale-udp6 41642 >/dev/null || exit 91
        say verify "$(sh "$ENG" verify)"
        say ports "$(sh "$ENG" get-ports | tr '\n' ' ')"
        say report "$(sh "$DEVICE/engine/rules-report" | tail -1)"
        tamper() { # family rule_number replacement...
          local ipt="$1" number="$2"; shift 2
          local saved
          saved=$("$ipt" -S POCKETUFW_IN | sed -n "$((number + 1))p")
          "$ipt" -w -R POCKETUFW_IN "$number" "$@" || echo "cannot tamper $*" >&2
          say "tampered_${ipt}_$number" "$(sh "$ENG" verify)"
          # shellcheck disable=SC2086
          "$ipt" -w -R POCKETUFW_IN "$number" ${saved#-A POCKETUFW_IN }
        }
        for ipt in iptables ip6tables; do
          tamper "$ipt" 1 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
          tamper "$ipt" 3 -p tcp -m conntrack --ctstate INVALID -j DROP
          tamper "$ipt" 5 -p udp --dport 5353 -j ACCEPT
          tamper "$ipt" 6 -j ACCEPT
          tamper "$ipt" 7 -p tcp -j POCKETUFW_TS
          tamper "$ipt" 8 -p tcp -j DROP
        done
        tamper iptables 2 -j ACCEPT
        tamper ip6tables 2 -j ACCEPT
        tamper iptables 4 -p udp --dport 68 -j ACCEPT
        tamper ip6tables 4 -p udp --dport 546 -j ACCEPT
        say restored "$(sh "$ENG" verify)"
        iptables -w -D INPUT -i rmnet+ -m comment --comment PocketUFW -j POCKETUFW_IN
        say hook_lost "$(sh "$ENG" verify)"
        ''')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['ports'].split(), ['udp4=41641', 'udp6=41642'])
        self.assertEqual(values['report'], 'rules_report=READY')
        tampered = {key: value for key, value in values.items() if key.startswith('tampered_')}
        self.assertEqual(len(tampered), 16)
        self.assertEqual(set(tampered.values()), {'DEGRADED'}, tampered)
        self.assertEqual(values['restored'], 'ACTIVE')
        self.assertEqual(values['hook_lost'], 'DEGRADED')

    def test_earlier_accept_is_reported_because_verify_cannot_see_it(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$ENG" enable >/dev/null || exit 91
        say clean_report "$(sh "$DEVICE/engine/rules-report" | grep -c '^input_bypass')"
        iptables -w -I INPUT 1 -i wlan0 -j ACCEPT
        say verify "$(sh "$ENG" verify)"
        say delivered "$(deliver 4 9 47931 5)"
        sh "$DEVICE/engine/rules-report" | grep '^input_bypass'
        ''')
        self.assertEqual(values['clean_report'], '0')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['delivered'], '5')
        self.assertEqual(values['input_bypass4_01'], '-A INPUT -i wlan0 -j ACCEPT')

    def test_only_the_verified_tailscale_port_opens(self):
        values = self.namespace(r'''
        link wlan0 9
        spawn() { # NAME PORTS MARK: a process with this argv[0] and this comm.
          bash -c 'exec -a "$0" python3 -I "$@"' "$1" "$WORK/net.py" fakeapp m.tailscale.ipn "$2" "$3.ready" "$3.stop" > "$3.out" &
          APP=$!
          wait_for "$3.ready"
        }
        sh "$ENG" enable >/dev/null || exit 91
        spawn com.tailscale.ipn 4:41641,6:41642 "$WORK/app"
        say probe "$(sh "$DEVICE/engine/vpn-probe" | tr '\n' ' ')"
        say refresh "$(sh "$ENG" refresh | sed -n 's/^refresh_result=//p')"
        say ports "$(sh "$ENG" get-ports | tr '\n' ' ')"
        peer $N send 4 10.9.0.1 41641 6
        peer $N send 6 fd9::1 41642 4
        say other_port "$(deliver 4 9 47931 5)"
        : > "$WORK/app.stop"; wait "$APP"
        say app_received "$(cat "$WORK/app.out")"
        say verify "$(sh "$ENG" verify)"
        ''')
        self.assertEqual(values['refresh'], 'UPDATED')
        self.assertEqual(values['ports'].split(), ['udp4=41641', 'udp6=41642'])
        self.assertEqual(values['app_received'], '10')
        self.assertEqual(values['other_port'], '0')
        self.assertEqual(values['verify'], 'ACTIVE')

    @unittest.skipIf(os.geteuid() == 0, 'for real root, /etc is inside the mapping this scenario relies on')
    def test_spoofed_tailscale_is_refused_its_port(self):
        # /etc's owner is a UID outside this namespace's single mapping, so listing it
        # as Tailscale's makes this process a different app.
        values = self.namespace(r'''
        link wlan0 9
        printf 'com.tailscale.ipn %s 0\n' "$(stat -c %u /etc)" > "$WORK/other.list"
        export POCKETUFW_PACKAGES_LIST="$WORK/other.list"
        say owner_uid "$(stat -c %u /etc)"
        bash -c 'exec -a "$0" python3 -I "$@"' com.tailscale.ipn "$WORK/net.py" fakeapp m.tailscale.ipn 4:31337 "$WORK/app.ready" "$WORK/app.stop" > "$WORK/app.out" &
        APP=$!
        wait_for "$WORK/app.ready"
        say process_uid "$(awk '/^Uid:/ { print $2 }' /proc/$APP/status)"
        sh "$DEVICE/engine/vpn-probe" >/dev/null 2>&1; say probe_status "$?"
        enable_output=$(sh "$ENG" enable --auto-tailscale 2>/dev/null); say enable_status "$?"
        say marker "$(printf '%s\n' "$enable_output" | grep -c '^tailscale_probe=FAILED$')"
        say verify "$(sh "$ENG" verify)"
        say ports "$(sh "$ENG" get-ports | tr '\n' ' ')"
        sh "$ENG" refresh >/dev/null 2>&1; say refresh_status "$?"
        peer $N send 4 10.9.0.1 31337 7
        sleep 0.1
        : > "$WORK/app.stop"; wait "$APP"
        say app_received "$(cat "$WORK/app.out")"
        ''')
        self.assertNotEqual(values['owner_uid'], values['process_uid'], 'scenario premise')
        self.assertNotEqual(values['probe_status'], '0')
        self.assertEqual(values['enable_status'], '0')
        self.assertEqual(values['marker'], '1')
        self.assertEqual(values['verify'], 'ACTIVE')
        self.assertEqual(values['ports'].split(), ['udp4=none', 'udp6=none'])
        self.assertNotEqual(values['refresh_status'], '0')
        self.assertEqual(values['app_received'], '0')

    def test_boot_restore_protects_after_a_reboot(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$BRIDGE" enable >/dev/null
        say arm "$(bridge_value boot-enable operation)"
        say armed_boot "$(bridge_value inspect boot)"
        sh "$ENG" disable >/dev/null   # A reboot loses the kernel's rules.
        say before_reboot_state "$(sh "$ENG" verify)"
        say before_boot "$(deliver 4 9 47931 5)"
        sh "$DEVICE/service.d/pocketufw.sh" >/dev/null 2>&1; say hook_status "$?"
        say restored_state "$(sh "$ENG" verify)"
        say after_boot "$(deliver 4 9 47931 5)"
        say bridge_off "$(bridge_value disable operation)"
        say off_state "$(sh "$ENG" verify)"
        say delivered_off "$(deliver 4 9 47931 5)"
        ''')
        self.assertEqual(values['arm'], 'SUCCESS')
        self.assertEqual(values['armed_boot'], 'ENABLED')
        self.assertEqual(values['before_reboot_state'], 'INACTIVE')
        self.assertEqual(values['before_boot'], '5')
        self.assertEqual(values['hook_status'], '0')
        self.assertEqual(values['restored_state'], 'ACTIVE')
        self.assertEqual(values['after_boot'], '0')
        self.assertEqual(values['bridge_off'], 'SUCCESS')
        self.assertEqual(values['off_state'], 'INACTIVE')
        self.assertEqual(values['delivered_off'], '5')

    def test_removal_lets_packets_through_and_restores_the_rule_baseline(self):
        values = self.namespace(r'''
        link wlan0 9
        for ipt in iptables ip6tables; do
          "$ipt" -w -N oem_in
          "$ipt" -w -A oem_in -p tcp --dport 9 -j DROP
          "$ipt" -w -A INPUT -j oem_in
        done
        before=$(iptables -S; ip6tables -S)
        sh "$BRIDGE" enable >/dev/null
        say arm "$(bridge_value boot-enable operation)"
        say firewall_on4 "$(deliver 4 9 47931 5)"
        say firewall_on6 "$(deliver 6 9 47932 5)"
        out=$(sh "$BRIDGE" prepare-uninstall 2>/dev/null)
        say removal "$(printf '%s\n' "$out" | sed -n 's/^removal=//p')"
        say state "$(printf '%s\n' "$out" | sed -n 's/^state=//p')"
        say after4 "$(deliver 4 9 47931 5)"
        say after6 "$(deliver 6 9 47932 5)"
        [ "$before" = "$(iptables -S; ip6tables -S)" ] && say identical yes || say identical no
        [ -e "$DEVICE/service.d/pocketufw.sh" ] && say hook yes || say hook no
        [ -e "$DEVICE/adb-pocketufw" ] && say store yes || say store no
        ''')
        self.assertEqual(values['arm'], 'SUCCESS')
        self.assertEqual((values['firewall_on4'], values['firewall_on6']), ('0', '0'))
        self.assertEqual(values['removal'], 'CLEAN')
        self.assertEqual(values['state'], 'INACTIVE')
        self.assertEqual((values['after4'], values['after6']), ('5', '5'))
        self.assertEqual(values['identical'], 'yes')
        self.assertEqual((values['hook'], values['store']), ('no', 'no'))

    def test_removal_wont_call_itself_clean_while_a_foreign_rule_holds_the_chain(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$BRIDGE" enable >/dev/null
        iptables -w -A INPUT -i eth9 -j POCKETUFW_IN
        out=$(sh "$BRIDGE" prepare-uninstall 2>/dev/null)
        say removal "$(printf '%s\n' "$out" | sed -n 's/^removal=//p')"
        say left "$(printf '%s\n' "$out" | sed -n 's/^removal_left=//p')"
        say kept_foreign "$(iptables -S INPUT | grep -c -- '-i eth9')"
        iptables -w -D INPUT -i eth9 -j POCKETUFW_IN
        say retry "$(bridge_value prepare-uninstall removal)"
        say residue "$( (iptables -S; ip6tables -S) | grep -ci pocketufw)"
        ''')
        self.assertEqual(values['removal'], 'INCOMPLETE')
        self.assertEqual(values['left'], 'ipv4_rules')
        self.assertEqual(values['kept_foreign'], '1')
        self.assertEqual(values['retry'], 'CLEAN')
        self.assertEqual(values['residue'], '0')

    def test_a_held_lock_never_produces_a_clean_removal(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$BRIDGE" enable >/dev/null
        exec 8>>"$POCKETUFW_LOCK"; flock -x 8
        out=$(sh "$BRIDGE" prepare-uninstall 2>/dev/null)
        flock -u 8; exec 8>&-
        say removal "$(printf '%s\n' "$out" | sed -n 's/^removal=//p')"
        say state "$(printf '%s\n' "$out" | sed -n 's/^state=//p')"
        say still_filtering "$(deliver 4 9 47931 5)"
        say retry "$(bridge_value prepare-uninstall removal)"
        say delivered "$(deliver 4 9 47931 5)"
        ''', timeout=150)
        self.assertEqual(values['removal'], 'INCOMPLETE')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['still_filtering'], '0')
        self.assertEqual(values['retry'], 'CLEAN')
        self.assertEqual(values['delivered'], '5')

    def test_off_refused_by_a_held_lock_keeps_boot_restoration(self):
        values = self.namespace(r'''
        link wlan0 9
        sh "$BRIDGE" enable >/dev/null
        sh "$BRIDGE" boot-enable >/dev/null
        exec 8>>"$POCKETUFW_LOCK"; flock -x 8
        ( sleep 17; flock -u 8 ) &
        out=$(sh "$BRIDGE" disable 2>/dev/null)
        exec 8>&-
        say operation "$(printf '%s\n' "$out" | sed -n 's/^operation=//p')"
        say message "$(printf '%s\n' "$out" | sed -n 's/^message=//p')"
        say state "$(sh "$ENG" verify)"
        say boot "$(bridge_value inspect boot)"
        ''', timeout=150)
        self.assertEqual(values['operation'], 'FAILED')
        self.assertEqual(values['state'], 'ACTIVE')
        self.assertEqual(values['boot'], 'ENABLED')
        self.assertIn('boot restoration was kept', values['message'])

    def test_disable_leaves_other_owners_rules_exactly_as_they_were(self):
        values = self.namespace(r'''
        link wlan0 9
        for ipt in iptables ip6tables; do
          "$ipt" -w -N oem_in
          "$ipt" -w -A oem_in -p tcp --dport 9 -j DROP
          "$ipt" -w -A INPUT -j oem_in
          "$ipt" -w -A OUTPUT -p tcp --dport 9 -j ACCEPT
        done
        before=$(iptables -S; ip6tables -S)
        sh "$ENG" enable >/dev/null || exit 91
        say output_unchanged "$(iptables -S OUTPUT | grep -c -- '--dport 9')"
        say first_input "$(iptables -S INPUT | sed -n 2p)"
        sh "$ENG" disable >/dev/null || exit 92
        after=$(iptables -S; ip6tables -S)
        [ "$before" = "$after" ] && say identical yes || say identical no
        ''')
        self.assertEqual(values['output_unchanged'], '1')
        self.assertEqual(values['first_input'], '-A INPUT -j oem_in')
        self.assertEqual(values['identical'], 'yes')


if __name__ == '__main__':
    unittest.main()
