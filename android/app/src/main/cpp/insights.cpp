#include "insights_core.h"
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>
#include <linux/random.h>
#include <poll.h>
#include <sstream>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

using namespace insights;
namespace {
volatile sig_atomic_t interrupted = 0;
void stop(int) { interrupted = 1; }
int64_t now() {
    timespec t{};
    require(clock_gettime(CLOCK_BOOTTIME, &t) == 0, "Monotonic clock unavailable; sampling refused.");
    return int64_t(t.tv_sec) * 1000 + t.tv_nsec / 1000000;
}
void checkRequest() {
    require(!interrupted, "Sampling interrupted; sample discarded.");
    pollfd input{STDIN_FILENO, POLLIN, 0};
    int ready = poll(&input, 1, 0);
    require(ready >= 0 && !input.revents, "Sampling stopped or app disconnected; sample discarded.");
}
struct Fd {
    int value = -1;
    explicit Fd(int fd = -1) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
std::string setting(const char* key, const char* fallback) {
#ifdef PUFW_HOST_TEST
    const char* value = getenv(key); if (value) return value;
#else
    (void)key;
#endif
    return fallback;
}
const std::string shell = setting("PUFW_TEST_SH", "/system/bin/sh");
const std::array<std::string, 2> binaries = {setting("POCKETUFW_IPTABLES4", "/system/bin/iptables"),
                                          setting("POCKETUFW_IPTABLES6", "/system/bin/ip6tables")};
const std::string lockPath = setting("POCKETUFW_LOCK", "/dev/.pocketufw.lock");

// One bounded argv command. Only fixed iptables verbs and the APK's verifier are used.
// Writers inherit both locks. A killed parent cannot race recovery with a late insert.
std::string command(const Words& args, bool writer = false, int timeout = 3000) {
    const int64_t deadline = now() + timeout; // Check the clock before starting any child.
    int pipes[2]; require(pipe2(pipes, O_CLOEXEC) == 0, "Could not create command pipe.");
    Fd input(pipes[0]), output(pipes[1]);
    pid_t parent = getpid(), pid = fork(); require(pid >= 0, "Could not start firewall command.");
    if (!pid) {
        setpgid(0, 0);
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent) _exit(125);
        signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGHUP, SIG_DFL);
        dup2(output.value, STDOUT_FILENO);
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) { dup2(null, STDERR_FILENO); dup2(null, STDIN_FILENO); if (null > 2) close(null); }
        // FD 8 carries the lifecycle lock into pocketufw verify. It obtains its own FD 9.
        if (fcntl(8, F_GETFD) >= 0) fcntl(8, F_SETFD, 0);
        if (writer && fcntl(9, F_GETFD) >= 0) fcntl(9, F_SETFD, 0);
        std::vector<char*> argv; for (const auto& s : args) argv.push_back(const_cast<char*>(s.c_str())); argv.push_back(nullptr);
        execv(argv[0], argv.data()); _exit(127);
    }
    setpgid(pid, pid);
    close(output.value); output.value = -1;
    fcntl(input.value, F_SETFL, O_NONBLOCK);
    std::string result; int status = 0; bool exited = false;
    try {
        while (true) {
            // The child's last bytes can land, and it can exit, between an empty read and
            // waitpid. Only a read that began after the exit was seen can prove the pipe
            // holds nothing more of the child's own output. A descendant keeping the pipe
            // open adds no wait: an empty read then is final.
            const bool exitSeen = exited;
            char buf[4096]; ssize_t size = read(input.value, buf, sizeof(buf));
            bool empty = size == 0;
            if (size > 0) {
                require(result.size() + size <= 256 * 1024, "Firewall listing exceeds memory limit."); result.append(buf, size);
            } else if (size < 0) {
                const int error = errno;
                require(error == EAGAIN || error == EINTR, "Firewall command read failed.");
                empty = error == EAGAIN;
            }
            if (!exited) { pid_t done = waitpid(pid, &status, WNOHANG); exited = done == pid; require(done >= 0 || errno == EINTR, "Firewall command wait failed."); }
            if (exitSeen && empty) break;
            require(now() < deadline, "Firewall command timed out; verify cleanup before retrying.");
            pollfd fd{input.value, POLLIN, 0}; poll(&fd, 1, 10);
        }
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Firewall command failed; sampling unavailable.");
    } catch (...) { kill(-pid, SIGKILL); if (!exited) while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} throw; }
    // No descendants of a completed verifier may retain our locks or pipe.
    kill(-pid, SIGKILL);
    return result;
}
std::string fw(int family, const Words& args) {
    Words all{binaries[family == 4 ? 0 : 1], "-w", "2"}; all.insert(all.end(), args.begin(), args.end());
    return command(all, args[0] == "-I" || args[0] == "-D");
}
Tables tables() {
    Tables value;
    for (int i = 0; i < 2; ++i) {
        std::istringstream lines(fw(i ? 6 : 4, {"-S"})); std::string line;
        size_t tokens = 0;
        while (std::getline(lines, line)) {
            auto row = words(line); maskVolatile(row); tokens += row.size();
            require(tokens <= 16384 && value[i].size() < 2048, "Firewall snapshot exceeds memory limit.");
            if (!row.empty()) value[i].push_back(std::move(row));
        }
        require(!value[i].empty(), "Empty firewall listing is not proof of cleanup.");
    }
    return value;
}
void lockFile(const std::string& path, int target) {
    Fd file(open(path.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
    require(file.value >= 0, "Cannot open firewall lock; sampling refused.");
    struct stat info{};
    require(fstat(file.value, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() && info.st_nlink == 1,
            "Unsafe firewall lock; sampling refused.");
    require(fchmod(file.value, 0600) == 0 && flock(file.value, LOCK_EX | LOCK_NB) == 0,
            "PocketUFW is busy or locking failed; retry after the current operation.");
    require(dup2(file.value, target) == target, "Cannot retain firewall lock.");
    if (file.value == target) file.value = -1;
    fcntl(target, F_SETFD, FD_CLOEXEC);
}
void verify(const std::string& engine) {
    // DEGRADED/INACTIVE exit non-zero, so a failed or timed-out verifier means the same thing as wrong output.
    std::string state;
    try { state = command({shell, engine, "verify"}, false, 15000); } catch (const Error&) {}
    require(state == "ACTIVE\n", "Firewall is not independently verified ACTIVE.");
}
void groupAvailable() {
    for (const auto& bin : binaries) {
        std::istringstream lines(command({bin + "-save"})); std::string line;
        while (std::getline(lines, line)) {
            auto row = words(line);
            if (std::find(row.begin(), row.end(), "NFLOG") == row.end()) continue;
            for (size_t i = 0; i < row.size(); ++i) if (row[i] == "--nflog-group") {
                require(i + 1 < row.size() && row[i + 1] != "17", "NFLOG group 17 is already in use; sampling refused.");
            }
        }
    }
}
Tables cleanup(const std::vector<Entry>* allowed = nullptr) {
    auto before = tables();
    // Validate every reserved rule before deleting any. Never remove by index/prefix alone.
    for (int i = 0; i < 2; ++i) for (const auto& row : before[i]) if (owned(i ? 6 : 4, row) && allowed) {
        auto tag = *(std::find(row.begin(), row.end(), "--nflog-prefix") + 1);
        require(std::any_of(allowed->begin(), allowed->end(), [&](const Entry& e) { return e.tag == tag; }),
                "Another diagnostic session appeared; manual review required.");
    }
    bool failed = false;
    for (int i = 0; i < 2; ++i) for (auto it = before[i].rbegin(); it != before[i].rend(); ++it) if (owned(i ? 6 : 4, *it)) {
        Words args = *it; args[0] = "-D";
        try { fw(i ? 6 : 4, args); } catch (...) { failed = true; }
    }
    auto after = tables();
    for (const auto& t : after) for (const auto& r : t) require(!reserved(r), "Probe cleanup incomplete. Use Recover Insights probes.");
    require(!failed, "A cleanup command failed. Use Recover Insights probes to verify.");
    return after;
}
std::string sessionId() {
    std::array<unsigned char, 16> bytes{};
    require(syscall(SYS_getrandom, bytes.data(), bytes.size(), GRND_NONBLOCK) == static_cast<ssize_t>(bytes.size()), "Secure session ID unavailable.");
    const char* hex = "0123456789abcdef"; std::string value;
    for (auto b : bytes) { value += hex[b >> 4]; value += hex[b & 15]; } return value;
}

struct Collector {
    Fd fd;
    std::array<Packet, packetLimit> packets{};
    int count = 0, records = 0, unreadable = 0, unrelated = 0, loss = 0, elapsed = 0;
    uint32_t serial = 0, lastSequence = 0; bool haveSequence = false;
    explicit Collector() : fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER)) {
        require(fd.value >= 0, "Kernel NFLOG is unavailable; no probes installed.");
        sockaddr_nl local{}; local.nl_family = AF_NETLINK;
        require(bind(fd.value, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0, "Cannot bind NFLOG socket.");
        int buffer = 64 * 1024;
        require(setsockopt(fd.value, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) == 0, "Cannot bound NFLOG receive buffer.");
        nfulnl_msg_config_cmd bindGroup{NFULNL_CFG_CMD_BIND}; configure(NFULA_CFG_CMD, &bindGroup, sizeof(bindGroup));
        nfulnl_msg_config_mode mode{}; mode.copy_range = htonl(44); mode.copy_mode = NFULNL_COPY_PACKET;
        configure(NFULA_CFG_MODE, &mode, sizeof(mode));
        uint16_t flags = htons(NFULNL_CFG_F_SEQ); configure(NFULA_CFG_FLAGS, &flags, sizeof(flags));
        // Never PF_UNBIND/PF_BIND: do not displace another subsystem's logger.
    }
    void configure(uint16_t type, const void* data, size_t length) {
        alignas(nlmsghdr) std::array<uint8_t, 128> bytes{};
        auto* header = reinterpret_cast<nlmsghdr*>(bytes.data());
        header->nlmsg_len = NLMSG_LENGTH(sizeof(nfgenmsg)) + NLA_ALIGN(NLA_HDRLEN + length);
        header->nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
        header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; header->nlmsg_seq = ++serial;
        auto* gen = reinterpret_cast<nfgenmsg*>(NLMSG_DATA(header)); gen->version = NFNETLINK_V0; gen->res_id = htons(group);
        auto* attr = reinterpret_cast<nlattr*>(bytes.data() + NLMSG_LENGTH(sizeof(nfgenmsg)));
        attr->nla_type = type; attr->nla_len = NLA_HDRLEN + length;
        memcpy(reinterpret_cast<uint8_t*>(attr) + NLA_HDRLEN, data, length);
        sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
        require(sendto(fd.value, bytes.data(), header->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) == static_cast<ssize_t>(header->nlmsg_len),
                "NFLOG configuration failed; no probes installed.");
        const int64_t deadline = now() + 1500;
        while (now() < deadline) {
            pollfd wait{fd.value, POLLIN, 0}; if (poll(&wait, 1, 50) <= 0) continue;
            alignas(nlmsghdr) uint8_t response[4096]; sockaddr_nl sender{}; socklen_t size = sizeof(sender);
            ssize_t received = recvfrom(fd.value, response, sizeof(response), 0, reinterpret_cast<sockaddr*>(&sender), &size);
            if (received < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            require(received >= static_cast<ssize_t>(NLMSG_LENGTH(sizeof(nlmsgerr))) && sender.nl_pid == 0, "Invalid NFLOG acknowledgement.");
            auto* ack = reinterpret_cast<nlmsghdr*>(response);
            require(ack->nlmsg_type == NLMSG_ERROR && ack->nlmsg_seq == serial && ack->nlmsg_len >= NLMSG_LENGTH(sizeof(nlmsgerr)) && ack->nlmsg_len <= static_cast<unsigned>(received) &&
                    reinterpret_cast<nlmsgerr*>(NLMSG_DATA(ack))->error == 0,
                    "NFLOG unsupported or group already bound; no probes installed.");
            return;
        }
        throw Error("NFLOG configuration timed out; no probes installed.");
    }
    void record(const nlmsghdr* header, const std::vector<Entry>& entries) {
        ++records;
        if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nfgenmsg))) { ++unreadable; return; }
        const auto* gen = reinterpret_cast<const nfgenmsg*>(NLMSG_DATA(header));
        if (ntohs(gen->res_id) != group || (gen->nfgen_family != AF_INET && gen->nfgen_family != AF_INET6)) { ++unrelated; return; }
        const uint8_t* payload = nullptr; size_t payloadSize = 0; std::string tag;
        bool hook = false, bad = false; uint32_t sequence = 0; bool sequenceSeen = false;
        const auto* ptr = reinterpret_cast<const uint8_t*>(header) + NLMSG_LENGTH(sizeof(nfgenmsg));
        size_t left = header->nlmsg_len - NLMSG_LENGTH(sizeof(nfgenmsg));
        std::array<bool, NFULA_MAX + 1> seen{};
        while (left >= NLA_HDRLEN) {
            const auto* attr = reinterpret_cast<const nlattr*>(ptr);
            if (attr->nla_len < NLA_HDRLEN || attr->nla_len > left || NLA_ALIGN(attr->nla_len) > left) { bad = true; break; }
            unsigned type = attr->nla_type & NLA_TYPE_MASK; size_t size = attr->nla_len - NLA_HDRLEN;
            const uint8_t* data = ptr + NLA_HDRLEN;
            if (type <= NFULA_MAX) { if (seen[type]) bad = true; seen[type] = true; }
            if (type == NFULA_PAYLOAD) { payload = data; payloadSize = size; }
            if (type == NFULA_PREFIX) {
                if (size > 0 && size <= 64 && data[size - 1] == 0) tag.assign(reinterpret_cast<const char*>(data), size - 1);
                else bad = true;
            }
            if (type == NFULA_PACKET_HDR) hook = size == sizeof(nfulnl_msg_packet_hdr) && data[2] == 1;
            if (type == NFULA_SEQ && size == 4) { memcpy(&sequence, data, 4); sequence = ntohl(sequence); sequenceSeen = true; }
            size_t step = NLA_ALIGN(attr->nla_len); left -= step; ptr += step;
        }
        if (bad || left) { ++unreadable; return; }
        if (sequenceSeen) {
            if (haveSequence && sequence != lastSequence + 1) loss = 1;
            lastSequence = sequence; haveSequence = true;
        }
        auto entry = std::find_if(entries.begin(), entries.end(), [&](const Entry& e) { return e.tag == tag && e.family == (gen->nfgen_family == AF_INET ? 4 : 6); });
        if (entry == entries.end() || !hook || entry->family != (gen->nfgen_family == AF_INET ? 4 : 6)) { ++unrelated; return; }
        Packet packet; packet.scope = entry->scope; packet.reason = entry->reason;
        if (!payload || payloadSize > (entry->family == 4 ? 24u : 44u) || !decode(payload, payloadSize, entry->family, packet)) { ++unreadable; return; }
        packets[count++] = packet;
    }
    void collect(const std::vector<Entry>& entries, int64_t start) {
        while (records < packetLimit && now() < start + durationMs) {
            require(!interrupted, "Sampling interrupted; sample discarded.");
            pollfd waits[] = {{fd.value, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};
            int result = poll(waits, 2, static_cast<int>(std::max<int64_t>(0, std::min<int64_t>(100, start + durationMs - now()))));
            if (result < 0 && errno == EINTR) continue;
            require(result >= 0, "NFLOG polling failed; sample discarded.");
            require(!(waits[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)), "Sampling stopped or app disconnected; sample discarded.");
            if (!(waits[0].revents & POLLIN)) { require(!(waits[0].revents & (POLLHUP | POLLERR | POLLNVAL)), "NFLOG socket failed; sample discarded."); continue; }
            alignas(nlmsghdr) std::array<uint8_t, 16384> bytes{};
            sockaddr_nl sender{}; iovec vector{bytes.data(), bytes.size()}; msghdr message{};
            message.msg_name = &sender; message.msg_namelen = sizeof(sender); message.msg_iov = &vector; message.msg_iovlen = 1;
            ssize_t length = recvmsg(fd.value, &message, 0);
            if (length < 0) { if (errno == ENOBUFS) { loss = 1; continue; } if (errno == EINTR || errno == EAGAIN) continue; throw Error("NFLOG receive failed; sample discarded."); }
            if (sender.nl_pid != 0) { ++unrelated; ++records; continue; }
            if (message.msg_flags & MSG_TRUNC) { loss = 1; ++unreadable; ++records; continue; }
            unsigned remaining = static_cast<unsigned>(length);
            for (auto* header = reinterpret_cast<nlmsghdr*>(bytes.data()); NLMSG_OK(header, remaining) && records < packetLimit; header = NLMSG_NEXT(header, remaining)) {
                if (header->nlmsg_type == ((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET)) record(header, entries);
                else if (header->nlmsg_type != NLMSG_DONE) { ++unreadable; ++records; }
            }
            // Datagram bytes live only in this stack buffer and are never printed or persisted.
        }
        require(!interrupted, "Sampling interrupted; sample discarded.");
        elapsed = static_cast<int>(std::min<int64_t>(durationMs, now() - start));
    }
    void report(bool tunnel) const {
        printf("PUFW_INSIGHTS_V1\ncleanup=verified\nstate=ACTIVE\ntunnel=%d\nelapsed_ms=%d\nrecords=%d\nunreadable=%d\nunrelated=%d\nloss=%d\n", tunnel ? 1 : 0, elapsed, records, unreadable, unrelated, loss);
        for (int i = 0; i < count; ++i) {
            const auto& p = packets[i];
            printf("packet=%c|%d|%c|%s|%d|%d|%d\n", p.scope, p.family, p.reason, p.source.data(), p.protocol, p.sourcePort, p.destinationPort);
        }
        printf("end=verified\n");
    }
};
} // namespace

int main(int argc, char** argv) {
    // No user-supplied duration, group, rules, command text, or output paths.
    if (argc != 3 || (std::string(argv[1]) != "capture" && std::string(argv[1]) != "recover") || argv[2][0] != '/') return 2;
    rlimit core{0, 0}; if (setrlimit(RLIMIT_CORE, &core)) return 2;
    // Bound retained data explicitly. RLIMIT_AS is unsuitable for Android's Scudo
    // allocator, which reserves a large virtual region without committing RAM.
    // Commands: 256 KiB; tables: 2048 rows / 16384 tokens per family; packets: 256.

    signal(SIGPIPE, SIG_IGN); signal(SIGINT, stop); signal(SIGTERM, stop); signal(SIGHUP, stop);
    // The verifier must use exactly the same backends and locks as this helper.
    setenv("POCKETUFW_IPTABLES4", binaries[0].c_str(), 1); setenv("POCKETUFW_IPTABLES6", binaries[1].c_str(), 1);
    setenv("POCKETUFW_LOCK", lockPath.c_str(), 1);
    bool touched = false;
    try {
#ifndef PUFW_HOST_TEST
        require(geteuid() == 0, "Root access is required for Insights.");
#endif
        lockFile(lockPath + ".operation", 8); Fd operation(8);
        if (std::string(argv[1]) == "recover") {
            lockFile(lockPath, 9);
            // strip() runs first: an unrecognized reserved rule must stop recovery before any deletion.
            try { auto before = tables(); auto expected = strip(before); auto after = cleanup(); require(after == expected, "Rules changed during recovery; review firewall state."); }
            catch (...) { close(9); throw; }
            close(9); verify(argv[2]);
            printf("PUFW_INSIGHTS_RECOVERED_V1\ncleanup=verified\nstate=ACTIVE\nend=verified\n"); return 0;
        }
        checkRequest();
        std::string session = sessionId(); plan(tables(), session); verify(argv[2]);
        lockFile(lockPath, 9);
        auto baseline = tables(); auto entries = plan(baseline, session); groupAvailable();
        Collector collector; // Ready and acknowledged BEFORE any rule insertion.
        std::string problem;
        int64_t start = now();
        try {
            for (const auto& e : entries) {
                checkRequest();
                require(now() < start + durationMs, "Sampling interrupted or setup exceeded 10 seconds.");
                Words args{"-I", chain(e.scope), std::to_string(e.position)}; args.insert(args.end(), e.spec.begin(), e.spec.end());
                touched = true; fw(e.family, args);
            }
            verifyProbes(tables(), baseline, entries);
#ifdef PUFW_HOST_TEST
            fprintf(stderr, "Sampling ready\n");
#endif
            collector.collect(entries, start);
        } catch (const std::exception& e) { problem = e.what(); }
        // Stop receiving before cleanup. A second ordinary signal cannot interrupt rollback.
        close(collector.fd.value); collector.fd.value = -1;
        signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN); signal(SIGHUP, SIG_IGN);
        bool rulesRestored = false;
        try {
            auto restored = cleanup(&entries);
            // cleanup() returned, so no reserved probe remains. Later failures must not ask for recovery.
            touched = false;
            rulesRestored = restored == baseline;
        } catch (...) { close(9); throw; }
        // Verify protection after cleanup even when the sample must be withheld.
        // Release the rules lock first; the verifier acquires it independently.
        close(9); verify(argv[2]);
        require(rulesRestored, "Probes removed, but other firewall rules changed during the sample; sample withheld. Review firewall rules.");
        if (!problem.empty()) { printf("error=%s Cleanup verified; firewall ACTIVE.\n", problem.c_str()); return 1; }
        collector.report(std::any_of(entries.begin(), entries.end(), [](const Entry& e) { return e.scope == 'T'; })); return 0;
    } catch (const ReviewRequired& e) {
        // Only thrown before any deletion in this run. Recovery would refuse the same rule, so never suggest it.
        printf("error=%s Nothing was removed, disabled or rebuilt. Review this rule before recovering%s.\n", e.what(),
               touched ? "; Insights probes from this sample may remain" : "");
        return 1;
    } catch (const std::exception& e) {
        printf("error=%s%s\n", e.what(), touched ? " Cleanup not verified. Use Recover Insights probes before another sample." : "");
        return 1;
    }
}
