#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <arpa/inet.h>

namespace insights {
constexpr int packetLimit = 256;
constexpr int durationMs = 10000;
constexpr int group = 17;
constexpr const char* marker = "PUFW_APP1:";
using Words = std::vector<std::string>;
using Table = std::vector<Words>;
using Tables = std::array<Table, 2>;
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
inline void require(bool value, const char* message) { if (!value) throw Error(message); }

// Parse iptables -S quoting, never evaluate it as shell text. Fail on malformed input.
inline Words words(const std::string& line) {
    require(line.size() <= 4096, "Firewall rule exceeds input limit.");
    Words out; std::string word; char quote = 0; bool escaped = false, started = false;
    for (char c : line) {
        if (escaped) { word += c; escaped = false; started = true; }
        else if (c == '\\' && quote != '\'') { escaped = true; started = true; }
        else if (quote) { if (c == quote) quote = 0; else word += c; }
        else if (c == '\'' || c == '"') { quote = c; started = true; }
        else if (c == ' ' || c == '\t' || c == '\r') {
            if (started) { out.push_back(word); word.clear(); started = false; }
        } else { word += c; started = true; }
    }
    require(!quote && !escaped, "Malformed firewall listing; sampling refused.");
    if (started) out.push_back(word);
    require(out.size() <= 64, "Firewall rule exceeds token limit.");
    return out;
}
inline std::string chain(char scope) { return scope == 'P' ? "POCKETUFW_IN" : "POCKETUFW_VPN"; }
inline bool parseTag(const std::string& tag, char& scope, char& reason) {
    const size_t n = std::strlen(marker);
    if (tag.size() != n + 36 || tag.compare(0, n, marker) != 0) return false;
    for (size_t i = n; i < n + 32; ++i)
        if (!((tag[i] >= '0' && tag[i] <= '9') || (tag[i] >= 'a' && tag[i] <= 'f'))) return false;
    scope = tag[n + 33]; reason = tag[n + 35];
    return tag[n + 32] == ':' && tag[n + 34] == ':' &&
        (scope == 'P' || scope == 'T') && (reason == 'I' || reason == 'F');
}
inline Words drop(char reason) {
    return reason == 'I' ? Words{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"} : Words{"-j", "DROP"};
}
inline Words probe(int family, char reason, const std::string& tag) {
    Words row = drop(reason); row.pop_back(); row.push_back("NFLOG");
    for (auto& s : Words{"--nflog-prefix", tag, "--nflog-group", "17", "--nflog-size",
                         family == 4 ? "24" : "44", "--nflog-threshold", "1"}) row.push_back(s);
    return row;
}
inline bool reserved(const Words& row) {
    return std::any_of(row.begin(), row.end(), [](const std::string& s) { return s.find(marker) != std::string::npos; });
}
// Android's xt_quota2 (netd's bw_costly_* and bw_global_alert) lists its remaining byte count,
// which falls as traffic passes. Seen on a Pixel: two listings 30 s apart differed only there.
// That is runtime state, not policy, so snapshots mask it; every rule's structure still compares.
inline void maskVolatile(Words& row) {
    if (std::find(row.begin(), row.end(), "quota2") == row.end()) return;
    for (size_t i = 0; i + 1 < row.size(); ++i)
        if (row[i] == "--quota" && !row[i + 1].empty() &&
            std::all_of(row[i + 1].begin(), row[i + 1].end(), [](char c) { return c >= '0' && c <= '9'; }))
            row[i + 1] = "<remaining>";
}
// A reserved marker on a rule this helper cannot fully recognize. Callers must change nothing:
// no deletion, disable or rebuild. The message names the rule so a person can review it.
struct ReviewRequired : Error { using Error::Error; };
inline void review(bool value, const char* message, int family, const Words& row) {
    if (value) return;
    std::string text;
    for (const auto& w : row) { if (!text.empty()) text += ' '; text += w; }
    if (text.size() > 180) text = text.substr(0, 177) + "...";
    for (auto& c : text) if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '?';
    throw ReviewRequired(std::string(message) + " Affected IPv" + std::to_string(family) + " rule: " + text);
}
inline bool owned(int family, const Words& row) {
    if (!reserved(row)) return false;
    auto at = std::find(row.begin(), row.end(), "--nflog-prefix");
    review(at != row.end() && at + 1 != row.end(), "Unrecognized Insights residue; manual rule review needed.", family, row);
    char scope = 0, reason = 0;
    review(parseTag(*(at + 1), scope, reason), "Unrecognized Insights tag; manual rule review needed.", family, row);
    Words expected{"-A", chain(scope)};
    auto spec = probe(family, reason, *(at + 1)); expected.insert(expected.end(), spec.begin(), spec.end());
    auto target = std::find(expected.begin(), expected.end(), "-j");
    size_t split = static_cast<size_t>(target - expected.begin());
    review(row.size() == expected.size() && std::equal(expected.begin(), target + 2, row.begin()),
           "Unrecognized Insights rule; manual rule review needed.", family, row);
    std::map<std::string, std::string> opts, want;
    for (size_t i = split + 2; i < row.size(); i += 2) {
        review(opts.emplace(row[i], row[i + 1]).second, "Duplicate Insights rule option; manual rule review needed.", family, row);
        want.emplace(expected[i], expected[i + 1]);
    }
    review(opts == want, "Unrecognized Insights options; manual rule review needed.", family, row);
    return true;
}
struct Entry { int family; char scope; char reason; int position; std::string tag; Words spec; };
inline std::vector<Entry> plan(const Tables& tables, const std::string& session) {
    std::vector<Entry> entries;
    for (int f = 0; f < 2; ++f) {
        for (const auto& row : tables[f]) for (const auto& token : row)
            require(token.find(marker) == std::string::npos && token.find("PUFW_INSPECT") == std::string::npos &&
                    token.find("PUFW_INSIGHTS") == std::string::npos,
                    "Diagnostic residue detected. Use Recover Insights probes; Termux probes need pufw-inspect --recover.");
        for (char scope : {'P', 'T'}) {
            Table rules;
            for (const auto& row : tables[f]) if (row.size() >= 2 && row[0] == "-A" && row[1] == chain(scope))
                rules.emplace_back(row.begin() + 2, row.end());
            if (scope == 'T' && rules.empty()) continue;
            require(scope == 'P' ? rules.size() == 8 : (rules.size() == 3 || rules.size() == 4),
                    "Unrecognized DROP policy; sampling refused.");
            std::vector<std::pair<int, char>> drops;
            for (size_t i = 0; i < rules.size(); ++i) if (std::find(rules[i].begin(), rules[i].end(), "DROP") != rules[i].end()) {
                char reason = drops.empty() ? 'I' : 'F';
                require(drops.size() < 2 && rules[i] == drop(reason), "Unrecognized DROP match; sampling refused.");
                drops.emplace_back(static_cast<int>(i + 1), reason);
            }
            require(drops.size() == 2, "Missing DROP rules; sampling refused.");
            for (auto it = drops.rbegin(); it != drops.rend(); ++it) {
                std::string tag = std::string(marker) + session + ":" + scope + ":" + it->second;
                entries.push_back({f ? 6 : 4, scope, it->second, it->first, tag, probe(f ? 6 : 4, it->second, tag)});
            }
        }
    }
    return entries;
}
inline Tables strip(const Tables& tables) {
    Tables result;
    for (int f = 0; f < 2; ++f) for (const auto& row : tables[f]) if (!owned(f ? 6 : 4, row)) result[f].push_back(row);
    return result;
}
inline void verifyProbes(const Tables& tables, const Tables& baseline, const std::vector<Entry>& entries) {
    require(strip(tables) == baseline, "Firewall changed during setup; sample discarded.");
    for (const auto& e : entries) {
        const auto& table = tables[e.family == 4 ? 0 : 1]; int count = 0;
        for (size_t i = 0; i < table.size(); ++i) if (std::find(table[i].begin(), table[i].end(), e.tag) != table[i].end()) {
            ++count;
            Words next{"-A", chain(e.scope)}; auto match = drop(e.reason); next.insert(next.end(), match.begin(), match.end());
            require(i + 1 < table.size() && table[i + 1] == next, "Probe is not adjacent to its DROP; sample discarded.");
        }
        require(count == 1, "Missing or duplicate probe; sample discarded.");
    }
}
struct Packet {
    int family = 0, protocol = 0, sourcePort = -1, destinationPort = -1;
    char scope = 0, reason = 0;
    std::array<char, INET6_ADDRSTRLEN> source{};
};
inline unsigned be16(const uint8_t* p) { return (unsigned(p[0]) << 8) | p[1]; }
inline bool decode(const uint8_t* p, size_t size, int family, Packet& packet) {
    packet.family = family;
    size_t offset = 0; bool ports = false;
    if (family == 4) {
        if (size < 20 || p[0] >> 4 != 4 || (p[0] & 15) < 5 || be16(p + 2) < (p[0] & 15) * 4u) return false;
        inet_ntop(AF_INET, p + 12, packet.source.data(), packet.source.size());
        packet.protocol = p[9]; offset = (p[0] & 15) * 4;
        // Any fragmentation makes a category guess unsafe, including first fragments.
        ports = !(be16(p + 6) & 0x3fff) && be16(p + 2) >= offset + 4;
    } else if (family == 6) {
        if (size < 40 || p[0] >> 4 != 6) return false;
        inet_ntop(AF_INET6, p + 8, packet.source.data(), packet.source.size());
        packet.protocol = p[6]; offset = 40; ports = be16(p + 4) >= 4;
        // Never walk extension headers beyond the bounded copy.
    } else return false;
    if (ports && (packet.protocol == 6 || packet.protocol == 17) && offset + 4 <= size) {
        packet.sourcePort = static_cast<int>(be16(p + offset));
        packet.destinationPort = static_cast<int>(be16(p + offset + 2));
    }
    return true;
}
} // namespace insights
