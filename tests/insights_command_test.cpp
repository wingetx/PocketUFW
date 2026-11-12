// Deterministic regressions for the helper's bounded command runner.
// The hook below makes a child's last output land, and the child exit, exactly
// between an empty non-blocking read and the helper's waitpid. Host-only.
#include <sys/wait.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <unistd.h>

namespace {
pid_t (*const realWaitpid)(pid_t, int*, int) = ::waitpid;
std::string gate;  // Test children write nothing until this file exists.
bool armed = false;
int nohangCalls = 0;
}  // namespace

// The first WNOHANG check after arming opens the gate, waits for the child to write
// and exit, and only then reports that exit, as a descheduled helper would see it.
pid_t testWaitpid(pid_t pid, int* status, int options) {
    if (armed && (options & WNOHANG) && ++nohangCalls == 1) {
        if (FILE* file = fopen(gate.c_str(), "w")) fclose(file);
        return realWaitpid(pid, status, 0);
    }
    return realWaitpid(pid, status, options);
}

#define waitpid testWaitpid
#define main insightsMain
#include "../android/app/src/main/cpp/insights.cpp"
#undef main
#undef waitpid

namespace {
std::string afterGate(const std::string& body) {
    return "while [ ! -e '" + gate + "' ]; do sleep 0.005; done; " + body;
}
std::string failure(const Words& args) {
    try { command(args); } catch (const Error& e) { return e.what(); }
    return "";
}
void arm() { armed = true; nohangCalls = 0; unlink(gate.c_str()); }
}  // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    gate = std::string(argv[1]) + "/gate";
    const std::string sh = "/bin/sh";

    // Output that lands after the last empty read is kept, across several reads.
    arm();
    const std::string late = command({sh, "-c", afterGate(
        "printf 'late-1\\n'; head -c 9000 /dev/zero | tr '\\000' x; printf '\\nlate-2\\n'")});
    assert(nohangCalls == 1);
    assert(late.size() == 7 + 9000 + 8);
    assert(late.compare(0, 7, "late-1\n") == 0);
    assert(late.compare(late.size() - 8, 8, "\nlate-2\n") == 0);

    // A late failure is still a failure, with its output read.
    arm();
    assert(failure({sh, "-c", afterGate("printf 'partial\\n'; exit 3")}) ==
           "Firewall command failed; sampling unavailable.");
    armed = false;

    // The memory limit still holds.
    assert(failure({sh, "-c", "head -c 300000 /dev/zero"}) == "Firewall listing exceeds memory limit.");

    // A descendant still holding the pipe after the child exits adds no wait.
    const auto started = std::chrono::steady_clock::now();
    assert(command({sh, "-c", "sleep 5 & printf done"}) == "done");
    assert(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(1500));

    // The deadline still holds for a child that never exits.
    assert(failure({sh, "-c", "exec sleep 5"}) == "Firewall command timed out; verify cleanup before retrying.");

    unlink(gate.c_str());
    puts("insights command runner: late output, limits and deadline OK");
    return 0;
}
