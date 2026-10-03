#pragma once

#include <memory>
#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/base/types.h"

namespace mint {
enum class DebuggerBackend { kGdbRemote, kLldbDap };
enum class DebuggerState { kDisconnected, kConnected, kStopped, kRunning, kExited };
struct DebuggerEndpoint {
    std::string host; // Numeric IPv4/IPv6 only; DNS cannot honor a strict deadline.
    u16 port = 0;
    // TCP debugger protocols have no authentication/encryption. Remote use must
    // be explicitly acknowledged; loopback + a user-managed tunnel is preferred.
    bool allowPlaintextRemote = false;
};
struct DebuggerRegisterSpec { std::string name; u32 number = 0, bits = 0; };
struct DebuggerRegister {
    std::string name, value;
    u32 number = 0;
    std::vector<u8> bytes; // Target order, no guessed host-endian conversion.
    bool available = true;
};
struct DebuggerOptions {
    u32 timeoutMs = 3000; // Per operation, bounded 1..30000 ms.
    // Optional exact RSP 'g' layout supplied by the target owner. Without a
    // target XML/layout, registers are returned as one labeled raw register file.
    std::vector<DebuggerRegisterSpec> registerLayout;
};
struct DebuggerSnapshot {
    DebuggerBackend backend = DebuggerBackend::kGdbRemote;
    DebuggerState state = DebuggerState::kDisconnected;
    u64 threadId = 0;
    u32 signal = 0;
    std::string reason;
    bool supportsMemory = false, supportsInstructionBreakpoints = false;
    std::vector<std::string> notes;
};
struct DebuggerThread { u64 id = 0; std::string name; bool selected = false; };
struct DebuggerFrame { u64 id = 0; Address pc = kNoAddress; std::string name, source; u64 line = 0; };
struct DebuggerModule { std::string id, name, path; Address start = kNoAddress, end = kNoAddress; };
struct DebuggerImageMapping {
    Address imageStart = 0, runtimeStart = 0; u64 size = 0;
    std::string module; // Explicit module evidence/user selection, never a guessed slide.
};

// Injectable byte transport; deadlines use steady-clock milliseconds from
// debuggerMonotonicMs(). On success progress must be 1..capacity; EOF is error.
// No background reader, process launch, console evaluation or shell execution.
class DebuggerTransport {
public:
    virtual ~DebuggerTransport() = default;
    virtual Status readSome(u8* data, size_t capacity, size_t* count, u64 deadlineMs) = 0;
    virtual Status writeSome(const u8* data, size_t size, size_t* count, u64 deadlineMs) = 0;
    virtual void close() = 0;
};
u64 debuggerMonotonicMs();

// The owning Session worker must serialize calls. Protocol/deadline errors
// close the connection to prevent a delayed reply being applied to a later
// operation; failed reads never mutate caller output. Connecting never starts a
// process. RSP connects to an already attached all-stop stub; DAP initializes
// an adapter and requires explicit attachProcess(pid, optional executable).
class DebuggerClient {
public:
    DebuggerClient();
    ~DebuggerClient();
    DebuggerClient(const DebuggerClient&) = delete;
    DebuggerClient& operator=(const DebuggerClient&) = delete;
    Status connectTcp(const DebuggerEndpoint&, DebuggerBackend, const DebuggerOptions& = {});
    Status connect(std::unique_ptr<DebuggerTransport>, DebuggerBackend, const DebuggerOptions& = {});
    void disconnect(); // No kill/resume command; disconnect effects follow stub policy.
    const DebuggerSnapshot& snapshot() const;
    Status attachProcess(u64 pid, const std::string& executable = {}); // DAP only.
    Status readRegisters(std::vector<DebuggerRegister>* out);
    Status readMemory(Address address, size_t length, std::vector<u8>* out);
    Status threads(std::vector<DebuggerThread>* out);
    Status selectThread(u64 id);
    Status stackFrames(size_t maximum, std::vector<DebuggerFrame>* out);
    Status modules(std::vector<DebuggerModule>* out); // DAP module inventory.
    Status programCounter(Address* out);
    Status discoverRegisterLayout(); // Bounded RSP target.xml; no external entity expansion.
    Status setImageMappings(const std::vector<DebuggerImageMapping>& mappings);
    Status imageToRuntime(Address image, Address* runtime) const;
    Status runtimeToImage(Address runtime, Address* image) const;
    Status setBreakpoint(Address address, bool enabled, u32 instructionSize = 1);
    Status step(); // Single instruction, not a source-level step.
    Status resume();
    Status interrupt();
    Status waitForStop(); // Explicit bounded wait; no polling/background thread.
    static constexpr size_t kMaxMemoryRead = 16384;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
std::string debuggerSnapshotText(const DebuggerSnapshot& snapshot);
}  // namespace mint
