#include "../android/app/src/main/cpp/insights_core.h"
#include <cassert>
#include <random>
using namespace insights;
template<class F> void rejects(F f) { bool rejected = false; try { f(); } catch (const Error&) { rejected = true; } assert(rejected); }
int main() {
    std::string tag = "PUFW_APP1:0123456789abcdef0123456789abcdef:P:I";
    char scope = 0, reason = 0; assert(parseTag(tag, scope, reason)); assert(scope == 'P' && reason == 'I');
    assert(!parseTag(tag + "x", scope, reason));
    assert(words("-A x --comment \"hello world\"") == (Words{"-A", "x", "--comment", "hello world"}));
    rejects([] { words("'unterminated"); });
    Words rule{"-A", "POCKETUFW_IN"}; auto spec = probe(4, 'I', tag); rule.insert(rule.end(), spec.begin(), spec.end());
    assert(owned(4, rule)); assert(!owned(4, {"-A", "OTHER", "-j", "DROP"}));
    auto changed = rule; changed[1] = "INPUT"; rejects([&] { owned(4, changed); });
    changed = rule; changed.back() = "2"; rejects([&] { owned(4, changed); });
    changed = rule; changed.insert(changed.end(), {"--nflog-group", "17"}); rejects([&] { owned(4, changed); });
    rejects([&] { owned(6, rule); });
    changed = rule; std::swap(changed[8], changed[10]); std::swap(changed[9], changed[11]); assert(owned(4, changed));
    Tables tables;
    for (auto& t : tables) for (int i = 0; i < 8; ++i) {
        Words row{"-A", "POCKETUFW_IN"}; auto tail = i == 2 ? drop('I') : i == 7 ? drop('F') : Words{"-j", "ACCEPT"};
        row.insert(row.end(), tail.begin(), tail.end()); t.push_back(row);
    }
    auto entries = plan(tables, "0123456789abcdef0123456789abcdef"); assert(entries.size() == 4);
    auto instrumented = tables;
    for (const auto& e : entries) { Words row{"-A", chain(e.scope)}; row.insert(row.end(), e.spec.begin(), e.spec.end());
        auto& t = instrumented[e.family == 4 ? 0 : 1]; t.insert(t.begin() + e.position - 1, row); }
    verifyProbes(instrumented, tables, entries); assert(strip(instrumented) == tables);
    rejects([&] { plan(instrumented, "0123456789abcdef0123456789abcdef"); });
    auto bad = instrumented; std::swap(bad[0][2], bad[0][3]); rejects([&] { verifyProbes(bad, tables, entries); });
    // PINNED has four tunnel rules. Its ACCEPT and reply rules stay ahead of probes.
    auto pinned = tables;
    for (auto& table : pinned) for (const auto& tail : Table{
        {"-s", "100.64.0.0/10", "-d", "100.64.0.1/32", "-j", "ACCEPT"},
        {"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, drop('I'), drop('F')}) {
        Words row{"-A", "POCKETUFW_VPN"}; row.insert(row.end(), tail.begin(), tail.end()); table.push_back(row);
    }
    auto pinnedEntries = plan(pinned, "0123456789abcdef0123456789abcdef");
    assert(pinnedEntries.size() == 8);
    auto pinnedProbes = pinned;
    for (const auto& e : pinnedEntries) {
        auto& table = pinnedProbes[e.family == 4 ? 0 : 1]; int position = 0;
        for (auto at = table.begin(); at != table.end(); ++at) if ((*at)[1] == chain(e.scope) && ++position == e.position) {
            Words row{"-A", chain(e.scope)}; row.insert(row.end(), e.spec.begin(), e.spec.end()); table.insert(at, row); break;
        }
    }
    verifyProbes(pinnedProbes, pinned, pinnedEntries); assert(strip(pinnedProbes) == pinned);
    uint8_t ipv4[24]{}; ipv4[0] = 0x45; ipv4[3] = 48; ipv4[9] = 17; ipv4[12] = 192; ipv4[13] = 168; ipv4[15] = 1;
    ipv4[20] = 7; ipv4[21] = 108; ipv4[22] = 0xc0; ipv4[23] = 1;
    Packet p; assert(decode(ipv4, 24, 4, p)); assert(p.sourcePort == 1900 && p.destinationPort == 49153);
    ipv4[6] = 0x20; p = {}; assert(decode(ipv4, 24, 4, p) && p.sourcePort == -1);
    ipv4[6] = 0; ipv4[0] = 0x46; p = {}; assert(decode(ipv4, 24, 4, p) && p.sourcePort == -1);
    uint8_t ipv6[44]{}; ipv6[0] = 0x60; ipv6[5] = 4; ipv6[6] = 17; ipv6[8] = 0xfe; ipv6[9] = 0x80; ipv6[40] = 0x14; ipv6[41] = 0xe9;
    p = {}; assert(decode(ipv6, 44, 6, p) && p.sourcePort == 5353);
    ipv6[6] = 44; p = {}; assert(decode(ipv6, 44, 6, p) && p.sourcePort == -1);
    // Frankenpixel, 30 s apart: netd's quota2 remaining bytes fell; nothing else changed.
    auto before = words("-A bw_costly_rmnet16 -m quota2 ! --name rmnet16  --quota 105720333316  -j REJECT --reject-with icmp-port-unreachable");
    auto later = words("-A bw_costly_rmnet16 -m quota2 ! --name rmnet16  --quota 105720333144  -j REJECT --reject-with icmp-port-unreachable");
    assert(before != later); maskVolatile(before); maskVolatile(later); assert(before == later);
    auto alert = words("-A bw_global_alert -m quota2 ! --name globalAlert  --quota 2097152 "), alertLater = alert;
    alertLater[8] = "1048576"; maskVolatile(alert); maskVolatile(alertLater); assert(alert == alertLater);
    // Structure still counts: a different target or name is a real change.
    auto target = words("-A bw_costly_rmnet16 -m quota2 ! --name rmnet16  --quota 1  -j ACCEPT"); maskVolatile(target); assert(target != before);
    auto name = words("-A bw_costly_rmnet16 -m quota2 ! --name other  --quota 1  -j REJECT --reject-with icmp-port-unreachable");
    maskVolatile(name); assert(name != before);
    // Only quota2 rows are masked.
    auto plain = words("-A x -m quota --quota 5 -j ACCEPT"), plainCopy = plain; maskVolatile(plain); assert(plain == plainCopy);
    std::mt19937 random(17);
    for (int i = 0; i < 10000; ++i) { std::array<uint8_t, 48> data{}; for (auto& v : data) v = random();
        p = {}; decode(data.data(), random() % 49, random() % 2 ? 4 : 6, p); }
}
