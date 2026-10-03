#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mint/debug/debugger.h"

using namespace mint;
namespace {
size_t checks = 0;
void require(bool value, const std::string& message) { ++checks; if (!value) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); } }
void okay(const Status& status, const std::string& message) { require(status.ok(), message + ": " + status.message()); }
struct Wire {
    std::string input, output;
    size_t position = 0, readFragment = 1, writeFragment = 2;
    bool closed = false, zeroProgress = false, failWrite = false;
};
class Fake final : public DebuggerTransport {
public:
    explicit Fake(std::shared_ptr<Wire> wire) : wire_(std::move(wire)) {}
    Status readSome(u8* data, size_t capacity, size_t* count, u64 deadline) override {
        require(deadline > debuggerMonotonicMs() && deadline - debuggerMonotonicMs() <= 30000, "bounded read deadline");
        if (wire_->zeroProgress) { *count = 0; return Status::success(); }
        if (wire_->position == wire_->input.size()) return Status::error(ErrorCode::kIoError, "simulated deadline / EOF");
        const auto n = std::min({capacity, wire_->readFragment, wire_->input.size() - wire_->position});
        std::copy_n(wire_->input.data() + wire_->position, n, data); wire_->position += n; *count = n; return Status::success();
    }
    Status writeSome(const u8* data, size_t size, size_t* count, u64 deadline) override {
        require(deadline > debuggerMonotonicMs() && deadline - debuggerMonotonicMs() <= 30000, "bounded write deadline");
        if (wire_->failWrite) return Status::error(ErrorCode::kIoError, "simulated write failure");
        const auto n = std::min(size, wire_->writeFragment); wire_->output.append(reinterpret_cast<const char*>(data), n); *count = n; return Status::success();
    }
    void close() override { wire_->closed = true; }
private: std::shared_ptr<Wire> wire_;
};
std::string packet(const std::string& payload) {
    unsigned sum = 0; for (unsigned char c : payload) sum = (sum + c) & 255;
    const char* digits = "0123456789abcdef"; return '$' + payload + '#' + digits[sum >> 4] + digits[sum & 15];
}
std::string rspHandshake() { return '+' + packet("PacketSize=4000") + '+' + packet("vCont;c;s") + '+' + packet("T05thread:2;"); }
std::shared_ptr<Wire> wire(std::string input, size_t fragment = 3) { auto result = std::make_shared<Wire>(); result->input = std::move(input); result->readFragment = fragment; return result; }
Status connect(DebuggerClient& client, const std::shared_ptr<Wire>& input, DebuggerBackend backend, const DebuggerOptions& options = {}) { return client.connect(std::unique_ptr<DebuggerTransport>(new Fake(input)), backend, options); }
std::string frame(const std::string& json) { return "Content-Length: " + std::to_string(json.size()) + "\r\n\r\n" + json; }
std::string response(unsigned seq, unsigned request, const std::string& command, const std::string& body = "{}") { return frame("{\"seq\":" + std::to_string(seq) + ",\"type\":\"response\",\"request_seq\":" + std::to_string(request) + ",\"command\":\"" + command + "\",\"success\":true,\"body\":" + body + '}'); }
std::string event(unsigned seq, const std::string& name, const std::string& body = "{}") { return frame("{\"seq\":" + std::to_string(seq) + ",\"type\":\"event\",\"event\":\"" + name + "\",\"body\":" + body + '}'); }
std::string dapHandshake() {
    return response(1, 1, "initialize", "{\"supportsConfigurationDoneRequest\":true,\"supportsReadMemoryRequest\":true,\"supportsInstructionBreakpoints\":true,\"supportsSteppingGranularity\":true}") +
           event(2, "initialized") + response(3, 2, "attach") + event(4, "stopped", "{\"reason\":\"entry\",\"threadId\":7}") + response(5, 3, "configurationDone");
}
void dapAttach(DebuggerClient& client, const std::shared_ptr<Wire>& input) { okay(connect(client, input, DebuggerBackend::kLldbDap), "DAP initialize"); require(client.snapshot().state == DebuggerState::kConnected, "initialize never implicitly attaches/starts target"); okay(client.attachProcess(123, "/tmp/fixture"), "explicit DAP PID attach"); require(client.snapshot().state == DebuggerState::kStopped && client.snapshot().threadId == 7, "reordered attach/configuration responses and stopped event"); }
void expandedWorkspace(){
    DebuggerClient mapping;okay(mapping.setImageMappings({{0x1000,0xFEDCBA9876543000ULL,0x1000,"fixture"}}),"explicit image mapping");Address address=0;okay(mapping.imageToRuntime(0x1234,&address),"map image address to live ASLR address");require(address==0xFEDCBA9876543234ULL,"ASLR mapping exact64-bit delta");okay(mapping.runtimeToImage(address,&address),"map live PC back to Program");require(address==0x1234,"inverse runtime mapping");require(!mapping.setImageMappings({{0x1000,0x2000,0x1000,"a"},{0x1800,0x9000,0x1000,"b"}}).ok(),"ambiguous mappings rejected atomically");okay(mapping.imageToRuntime(0x1234,&address),"prior mapping preserved after failure");require(address==0xFEDCBA9876543234ULL&&!mapping.imageToRuntime(0x2000,&address).ok(),"mapping range is exclusive and bounded");
    const auto inventory="{\"threads\":[{\"id\":7,\"name\":\"main\"},{\"id\":8,\"name\":\"worker\"}]}";
    auto input=wire(dapHandshake()+response(6,4,"threads",inventory)+response(7,5,"threads",inventory)+response(8,6,"stackTrace","{\"stackFrames\":[{\"id\":1,\"name\":\"worker\",\"instructionPointerReference\":\"0xfedcba9876543234\",\"source\":{\"path\":\"fixture.c\"},\"line\":12},{\"id\":2,\"name\":\"caller\",\"instructionPointerReference\":\"0xfedcba9876543300\"}]}" )+response(9,7,"modules","{\"modules\":[{\"id\":\"main\",\"name\":\"fixture\",\"path\":\"/fixture\",\"addressRange\":\"0xfedcba9876543000-0xfedcba9876543fff\"}]}" )+response(10,8,"stackTrace","{\"stackFrames\":[{\"id\":1,\"name\":\"worker\",\"instructionPointerReference\":\"0xfedcba9876543234\"}]}"));
    DebuggerClient client;dapAttach(client,input);std::vector<DebuggerThread> threads;okay(client.threads(&threads),"typed DAP thread inventory");require(threads.size()==2&&threads[0].selected&&threads[1].name=="worker","named threads and selected thread exposed");okay(client.selectThread(8),"select explicit existing thread");require(client.snapshot().threadId==8,"thread selection retained for subsequent operations");std::vector<DebuggerFrame> frames;okay(client.stackFrames(32,&frames),"bounded DAP call stack");require(frames.size()==2&&frames[0].pc==0xFEDCBA9876543234ULL&&frames[0].line==12,"typed frames preserve exact PC and source info");std::vector<DebuggerModule> modules;okay(client.modules(&modules),"typed DAP module inventory");require(modules.size()==1&&modules[0].start==0xFEDCBA9876543000ULL,"loaded module address evidence exposed");okay(client.programCounter(&address),"DAP current PC");require(address==0xFEDCBA9876543234ULL&&input->output.find("\"threadId\":8")!=std::string::npos,"current PC follows explicitly selected thread");
    const auto xml="<target><feature><reg name='rax' bitsize='64' regnum='0'/><reg name='rip' bitsize='64' regnum='1'/></feature></target>";
    auto rsp=wire(rspHandshake()+'+'+packet("m2,3")+'+'+packet("l")+'+'+packet(std::string("l")+xml)+'+'+packet("OK")+'+'+packet("00000000000000003412000000000000"));DebuggerClient remote;okay(connect(remote,rsp,DebuggerBackend::kGdbRemote),"expanded RSP workspace connect");okay(remote.threads(&threads),"RSP bounded thread inventory");require(threads.size()==2&&threads[0].id==2,"RSP typed thread IDs");okay(remote.discoverRegisterLayout(),"flattened target XML yields exact register names/widths");okay(remote.programCounter(&address),"RSP named little-endian PC");require(address==0x1234,"RSP discovered layout decodes program counter without guesses");
}

void rspWorkflow(size_t fragment) {
    auto input = wire(rspHandshake() + '+' + packet("OK") + '+' + packet("01000000xxxxxxxx") + '+' + packet("01020304") + '+' + packet("OK") + '+' + packet("T05thread:2;") + '+' + packet("T02thread:2;") + '+' + packet("OK") + '+' + packet("W00"), fragment);
    DebuggerOptions options; options.registerLayout = {{"pc", 16, 32}, {"flags", 17, 32}};
    DebuggerClient client; okay(connect(client, input, DebuggerBackend::kGdbRemote, options), "RSP connect");
    require(client.snapshot().state == DebuggerState::kStopped && client.snapshot().threadId == 2 && client.snapshot().signal == 5, "RSP initial stopped state");
    std::vector<DebuggerRegister> registers; okay(client.readRegisters(&registers), "RSP registers");
    require(registers.size() == 2 && registers[0].name == "pc" && registers[0].bytes == std::vector<u8>({1, 0, 0, 0}) && !registers[1].available && registers[1].value == "xxxxxxxx", "target bytes and unavailable registers not guessed");
    std::vector<u8> memory; constexpr Address address = 0xfffffffffff01000ULL;
    okay(client.readMemory(address, 4, &memory), "RSP memory"); require(memory == std::vector<u8>({1, 2, 3, 4}), "RSP exact memory bytes");
    okay(client.setBreakpoint(address, true, 4), "RSP breakpoint"); okay(client.step(), "RSP instruction step");
    require(client.snapshot().state == DebuggerState::kRunning, "step returns without indefinite target-stop wait"); okay(client.waitForStop(), "explicit step stop wait");
    okay(client.resume(), "RSP continue"); okay(client.interrupt(), "RSP interrupt"); okay(client.waitForStop(), "RSP interrupted stop"); require(client.snapshot().signal == 2, "interrupt stop signal");
    okay(client.setBreakpoint(address, false, 4), "RSP remove breakpoint"); okay(client.resume(), "RSP final continue"); okay(client.waitForStop(), "RSP exit wait");
    require(client.snapshot().state == DebuggerState::kExited, "RSP target exit");
    require(input->output.find(packet("mfffffffffff01000,4")) != std::string::npos && input->output.find(packet("Z0,fffffffffff01000,4")) != std::string::npos, "RSP 64-bit addresses preserved");
    require(input->output.find(packet("vCont;s:2")) != std::string::npos && input->output.find(packet("vCont;c")) != std::string::npos && input->output.find('\x03') != std::string::npos && input->output.find(packet("Hg2")) != std::string::npos, "RSP negotiated run-control commands select stopped register/stepping thread");
    require(input->output.find("qRcmd") == std::string::npos && input->output.find("vRun") == std::string::npos, "no shell/launch commands");
    client.disconnect(); require(input->closed && client.snapshot().state == DebuggerState::kDisconnected, "explicit local disconnect");
}
void dapWorkflow(size_t fragment) {
    const auto incoming = dapHandshake() + response(6, 4, "readMemory", "{\"address\":\"0xfffffffffff01000\",\"data\":\"AQIDBA==\"}") +
        response(7, 5, "stackTrace", "{\"stackFrames\":[{\"id\":0}]}") + response(8, 6, "scopes", "{\"scopes\":[{\"name\":\"Registers\",\"presentationHint\":\"registers\",\"variablesReference\":42}]}") +
        response(9, 7, "variables", "{\"variables\":[{\"name\":\"General Purpose Registers\",\"value\":\"\",\"variablesReference\":43}]}") +
        response(10, 8, "variables", "{\"variables\":[{\"name\":\"r0\",\"value\":\"0x01020304\",\"variablesReference\":0},{\"name\":\"pc\",\"value\":\"0xffffffffffffffff\",\"variablesReference\":0}]}") +
        response(11, 9, "setInstructionBreakpoints", "{\"breakpoints\":[{\"verified\":true}]}") + response(12, 10, "stepIn") + event(13, "stopped", "{\"reason\":\"step\",\"threadId\":7}") +
        response(14, 11, "continue") + response(15, 12, "pause") + event(16, "stopped", "{\"reason\":\"pause\",\"threadId\":7}") + response(17, 13, "setInstructionBreakpoints", "{\"breakpoints\":[]}") +
        response(18, 14, "continue") + event(19, "exited", "{\"exitCode\":0}");
    auto input = wire(incoming, fragment); DebuggerClient client; dapAttach(client, input);
    constexpr Address address = 0xfffffffffff01000ULL; std::vector<u8> memory; okay(client.readMemory(address, 4, &memory), "DAP memory"); require(memory == std::vector<u8>({1, 2, 3, 4}), "DAP strict base64 memory");
    std::vector<DebuggerRegister> registers; okay(client.readRegisters(&registers), "DAP register scope tree"); require(registers.size() == 2 && registers[0].name == "r0" && registers[1].value == "0xffffffffffffffff" && registers[1].bytes.empty(), "DAP register text kept without invented binary layout");
    okay(client.setBreakpoint(address, true), "DAP instruction breakpoint"); okay(client.step(), "DAP instruction step"); require(client.snapshot().state == DebuggerState::kRunning, "DAP step runs"); okay(client.waitForStop(), "DAP step event");
    okay(client.resume(), "DAP continue"); okay(client.interrupt(), "DAP pause"); okay(client.waitForStop(), "DAP pause stopped event"); okay(client.setBreakpoint(address, false), "DAP remove instruction breakpoint");
    okay(client.resume(), "DAP final continue"); okay(client.waitForStop(), "DAP exit event"); require(client.snapshot().state == DebuggerState::kExited, "DAP exited state");
    require(input->output.find("\"memoryReference\":\"0xfffffffffff01000\"") != std::string::npos && input->output.find("\"instructionReference\":\"0xfffffffffff01000\"") != std::string::npos, "DAP address strings retain all 64 bits");
    require(input->output.find("\"granularity\":\"instruction\"") != std::string::npos && input->output.find("\"pid\":123") != std::string::npos, "explicit typed attach and instruction step");
    require(input->output.find("launch") == std::string::npos && input->output.find("evaluate") == std::string::npos && input->output.find("attachCommands") == std::string::npos, "DAP command surface excludes execution strings");
    client.disconnect(); require(input->closed, "DAP local close");
}
void hostileRsp() {
    DebuggerClient client; std::vector<u8> memory{9, 9};
    std::string wrong = packet("0102"); wrong.back() = wrong.back() == '0' ? '1' : '0';
    auto checksum = wire(rspHandshake() + '+' + wrong + packet("0102")); okay(connect(client, checksum, DebuggerBackend::kGdbRemote), "checksum retry connect"); okay(client.readMemory(0x1000, 2, &memory), "checksum retransmission accepted"); require(checksum->output.find('-') != std::string::npos && memory == std::vector<u8>({1, 2}), "corrupt packet NACK then valid bytes");
    auto malformed = wire(rspHandshake() + '+' + wrong + wrong + wrong); okay(connect(client, malformed, DebuggerBackend::kGdbRemote), "bad checksum fixture connect"); memory = {9, 9}; require(!client.readMemory(0x1000, 2, &memory).ok() && memory == std::vector<u8>({9, 9}) && malformed->closed, "repeated checksum failure atomic and disconnects");
    auto length = wire(rspHandshake() + '+' + packet("010203")); okay(connect(client, length, DebuggerBackend::kGdbRemote), "length fixture connect"); require(!client.readMemory(0x1000, 2, &memory).ok() && memory == std::vector<u8>({9, 9}) && length->closed, "wrong memory response length atomic");
    auto oversize = wire(rspHandshake() + "+$" + std::string(65537, '0'), 4096); okay(connect(client, oversize, DebuggerBackend::kGdbRemote), "oversize fixture connect"); require(!client.readMemory(0x1000, 2, &memory).ok() && oversize->closed && memory == std::vector<u8>({9, 9}), "oversized RSP response bounded");
    auto rle = wire(rspHandshake() + '+' + packet("OK") + '+' + packet("0* ")); okay(connect(client, rle, DebuggerBackend::kGdbRemote), "RLE fixture connect"); std::vector<DebuggerRegister> registers; okay(client.readRegisters(&registers), "RLE register response"); require(registers.size() == 1 && registers[0].bytes == std::vector<u8>({0, 0}) && registers[0].name.find("layout unknown") != std::string::npos, "RLE decoded without invented register layout");
    auto noack = wire('+' + packet("PacketSize=4000;QStartNoAckMode+") + '+' + packet("OK") + packet("vCont;c;s") + packet("S05") + packet("01")); okay(connect(client, noack, DebuggerBackend::kGdbRemote), "no-ack negotiated"); okay(client.readMemory(1, 1, &memory), "no-ack memory"); require(std::count(noack->output.begin(), noack->output.end(), '+') == 4, "final OK ack then no further packet acknowledgements (plus two qSupported feature flags)");
    auto nack = wire('-' + rspHandshake()); okay(connect(client, nack, DebuggerBackend::kGdbRemote), "request retransmission on negative ACK"); const auto command = packet("qSupported:swbreak+;vContSupported+"); const auto first = nack->output.find(command); require(first != std::string::npos && nack->output.find(command, first + command.size()) != std::string::npos, "NACK resends exact request");
    auto unknown = wire(rspHandshake() + '+' + packet("")); okay(connect(client, unknown, DebuggerBackend::kGdbRemote), "unsupported fixture connect"); memory = {9}; require(client.readMemory(1, 1, &memory).code() == ErrorCode::kUnsupported && memory == std::vector<u8>({9}) && !unknown->closed, "unsupported packet preserves connection/output");
    auto duplicateThread = wire('+' + packet("PacketSize=4000") + '+' + packet("vCont;c;s") + '+' + packet("T05thread:1;thread:2;")); require(!connect(client, duplicateThread, DebuggerBackend::kGdbRemote).ok() && duplicateThread->closed, "ambiguous stopped thread rejected");
    auto zero = wire(""); zero->zeroProgress = true; require(!connect(client, zero, DebuggerBackend::kGdbRemote).ok() && zero->closed, "zero-progress transport rejected");
    auto writeError = wire(""); writeError->failWrite = true; require(!connect(client, writeError, DebuggerBackend::kGdbRemote).ok() && writeError->closed, "transport write failure closes candidate");
}
void hostileDap() {
    DebuggerClient client; std::vector<u8> memory{9};
    auto wrongId = wire(dapHandshake() + response(6, 99, "readMemory", "{\"address\":\"1\",\"data\":\"AQ==\"}")); dapAttach(client, wrongId); require(!client.readMemory(1, 1, &memory).ok() && memory == std::vector<u8>({9}) && wrongId->closed, "DAP wrong request ID atomic/disconnected");
    auto wrongCommand = wire(dapHandshake() + response(6, 4, "evaluate")); dapAttach(client, wrongCommand); require(!client.readMemory(1, 1, &memory).ok() && wrongCommand->closed, "DAP response command must match");
    auto badBase64 = wire(dapHandshake() + response(6, 4, "readMemory", "{\"address\":\"1\",\"data\":\"AR==\"}")); dapAttach(client, badBase64); require(!client.readMemory(1, 1, &memory).ok() && badBase64->closed && memory == std::vector<u8>({9}), "noncanonical base64 padding bits rejected");
    auto badAddress = wire(dapHandshake() + response(6, 4, "readMemory", "{\"address\":\"2\",\"data\":\"AQ==\"}")); dapAttach(client, badAddress); require(!client.readMemory(1, 1, &memory).ok() && badAddress->closed, "DAP memory reference validated");
    auto partial = wire(dapHandshake() + response(6, 4, "readMemory", "{\"address\":\"1\",\"data\":\"AQ==\",\"unreadableBytes\":1}")); dapAttach(client, partial); require(client.readMemory(1, 2, &memory).code() == ErrorCode::kUnsupported && memory == std::vector<u8>({9}) && !partial->closed, "partial memory never silently replaces requested bytes");
    auto untrusted = wire(dapHandshake() + event(6, "output", "{\"output\":\"$(touch /tmp/not-authorized) \\u001b[31m\",\"data\":{\"url\":\"file:///secret\"}}") + response(7, 4, "readMemory", "{\"address\":\"1\",\"data\":\"AQ==\"}")); dapAttach(client, untrusted); okay(client.readMemory(1, 1, &memory), "untrusted output ignored"); require(untrusted->output.find("touch") == std::string::npos && untrusted->output.find("file://") == std::string::npos, "untrusted event text never executed or sent back");
    auto changed = wire(dapHandshake() + event(6, "continued", "{\"threadId\":7}") + response(7, 4, "readMemory", "{\"address\":\"1\",\"data\":\"AQ==\"}")); dapAttach(client, changed); memory = {9}; require(!client.readMemory(1, 1, &memory).ok() && memory == std::vector<u8>({9}) && client.snapshot().state == DebuggerState::kRunning, "async running event invalidates stale stopped snapshot");
    auto reverse = wire(frame("{\"seq\":1,\"type\":\"request\",\"command\":\"runInTerminal\",\"arguments\":{\"args\":[\"sh\",\"-c\",\"touch forbidden\"]}}")); require(!connect(client, reverse, DebuggerBackend::kLldbDap).ok() && reverse->closed && reverse->output.find("touch") == std::string::npos, "reverse terminal/launch request refused");
    auto oversize = wire("Content-Length: 1048577\r\n\r\n"); require(!connect(client, oversize, DebuggerBackend::kLldbDap).ok() && oversize->closed, "oversized DAP frame rejected before allocation");
    auto duplicateHeader = wire("Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}"); require(!connect(client, duplicateHeader, DebuggerBackend::kLldbDap).ok() && duplicateHeader->closed, "duplicate content length rejected");
    auto duplicateKey = wire(frame("{\"seq\":1,\"seq\":2,\"type\":\"response\",\"request_seq\":1,\"command\":\"initialize\",\"success\":true,\"body\":{}}")); require(!connect(client, duplicateKey, DebuggerBackend::kLldbDap).ok() && duplicateKey->closed, "duplicate JSON key rejected");
    auto invalidUnicode = wire(frame("{\"seq\":1,\"type\":\"response\",\"request_seq\":1,\"command\":\"initialize\",\"success\":true,\"body\":{\"text\":\"\\ud800\"}}")); require(!connect(client, invalidUnicode, DebuggerBackend::kLldbDap).ok() && invalidUnicode->closed, "unpaired Unicode surrogate rejected");
    auto fractionalId = wire(frame("{\"seq\":1.5,\"type\":\"response\",\"request_seq\":1,\"command\":\"initialize\",\"success\":true,\"body\":{}}")); require(!connect(client, fractionalId, DebuggerBackend::kLldbDap).ok() && fractionalId->closed, "fractional message identifier rejected");
    auto nonmonotonic = wire(dapHandshake() + response(5, 4, "readMemory")); dapAttach(client, nonmonotonic); require(!client.readMemory(1, 1, &memory).ok() && nonmonotonic->closed, "replayed DAP sequence rejected");
    std::string depth(40, '['); depth += "0"; depth += std::string(40, ']'); auto deep = wire(response(1, 1, "initialize", "{\"nested\":" + depth + '}')); require(!connect(client, deep, DebuggerBackend::kLldbDap).ok() && deep->closed, "JSON depth budget enforced");
}
void inputValidation() {
    DebuggerClient client; std::vector<u8> memory{7}; std::vector<DebuggerRegister> registers(1);
    require(!client.readMemory(0, 1, &memory).ok() && memory == std::vector<u8>({7}), "disconnected memory read atomic");
    require(!client.readMemory(0, 0, &memory).ok() && !client.readMemory(0, DebuggerClient::kMaxMemoryRead + 1, &memory).ok() && !client.readMemory(~u64(0), 2, &memory).ok(), "memory resource/address-overflow validation");
    require(!client.readRegisters(&registers).ok() && registers.size() == 1, "disconnected register read atomic");
    require(!client.step().ok() && !client.resume().ok() && !client.interrupt().ok() && !client.waitForStop().ok() && !client.setBreakpoint(1, true).ok(), "disconnected control rejected");
    require(!client.attachProcess(123).ok(), "PID attach not implicit");
    require(!client.connectTcp({"example.com", 1234, true}, DebuggerBackend::kGdbRemote).ok(), "DNS/implicit endpoint not accepted");
    require(client.connectTcp({"192.0.2.1", 1234, false}, DebuggerBackend::kGdbRemote).code() == ErrorCode::kUnsupported, "non-loopback unauthenticated TCP explicitly acknowledged before socket creation");
    require(!client.connectTcp({"127.0.0.1", 0, false}, DebuggerBackend::kGdbRemote).ok(), "empty explicit port rejected without connection");
    DebuggerOptions options; options.timeoutMs = 30001; auto badTimeout = wire(""); require(!connect(client, badTimeout, DebuggerBackend::kGdbRemote, options).ok() && badTimeout->closed, "deadline bound validated");
    options.timeoutMs = 3000; options.registerLayout = {{"reg", 0, 7}}; auto badBits = wire(""); require(!connect(client, badBits, DebuggerBackend::kGdbRemote, options).ok() && badBits->closed, "non-byte register layout rejected");
    require(debuggerSnapshotText(client.snapshot()).find("disconnected") != std::string::npos, "debugger status display");
}

// This peer is a controlled protocol fixture, not a real debugger or debuggee.
// Every accept/read/write uses the same four-second absolute server deadline;
// failed client tests cannot leave an unbounded join or accept behind.
void mockCheck(bool good, const std::string& message) { if (!good) throw std::runtime_error(message); }
bool socketReady(int fd, short events, u64 limit) {
    for (;;) {
        const u64 now = debuggerMonotonicMs(); if (now >= limit) return false;
        pollfd item{fd, events, 0}; const int result = ::poll(&item, 1, static_cast<int>(limit - now));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return false;
        return (item.revents & (events | POLLHUP | POLLERR)) != 0;
    }
}
struct MockPeer {
    int fd; u64 limit;
    ~MockPeer() { ::close(fd); }
    char byte() {
        char c = 0;
        for (;;) {
            mockCheck(socketReady(fd, POLLIN, limit), "mock read exceeded absolute deadline");
            const auto count = ::recv(fd, &c, 1, 0);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            mockCheck(count == 1, "mock expected request bytes, received EOF/error"); return c;
        }
    }
    void send(const std::string& bytes, size_t fragment = 3, bool delayed = false) {
        for (size_t offset = 0; offset < bytes.size();) {
            mockCheck(socketReady(fd, POLLOUT, limit), "mock write exceeded absolute deadline");
#ifdef MSG_NOSIGNAL
            const auto count = ::send(fd, bytes.data() + offset, std::min(fragment, bytes.size() - offset), MSG_NOSIGNAL);
#else
            const auto count = ::send(fd, bytes.data() + offset, std::min(fragment, bytes.size() - offset), 0);
#endif
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            mockCheck(count > 0, "mock socket write failed"); offset += static_cast<size_t>(count);
            if (delayed && offset < bytes.size()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    void expectClosed() {
        mockCheck(socketReady(fd, POLLIN, limit), "client did not close socket within deadline");
        char c = 0; const auto count = ::recv(fd, &c, 1, 0);
        mockCheck(count == 0, "client disconnect must close locally without kill/resume/extra commands");
    }
    void halfClose() { mockCheck(::shutdown(fd, SHUT_WR) == 0, "mock half-close failed"); }
    std::string rspRequest(const std::string& expected) {
        mockCheck(byte() == '$', "RSP request marker missing"); std::string payload;
        for (;;) { const char c = byte(); if (c == '#') break; mockCheck(payload.size() < 4096, "mock RSP request bound"); payload += c; }
        const char high = byte(), low = byte();
        const std::string encoded = packet(payload);
        mockCheck(high == encoded[encoded.size() - 2] && low == encoded.back(), "actual TCP RSP request checksum mismatch");
        mockCheck(payload == expected, "unexpected actual TCP RSP command: " + payload); return payload;
    }
    void rspExchange(const std::string& command, const std::string& reply, size_t fragment = 3) {
        rspRequest(command); send('+' + packet(reply), fragment, true); mockCheck(byte() == '+', "actual TCP client did not ACK RSP packet");
    }
    std::string dapRequest(unsigned sequence, const std::string& command) {
        std::string header;
        while (header.size() < 4096 && (header.size() < 4 || header.compare(header.size() - 4, 4, "\r\n\r\n"))) header += byte();
        mockCheck(header.rfind("Content-Length: ", 0) == 0 && header.size() < 4096, "actual TCP DAP header framing");
        const size_t end = header.find("\r\n"); const std::string digits = header.substr(16, end - 16);
        size_t size = 0; mockCheck(!digits.empty(), "mock DAP length missing");
        for (char digit : digits) { mockCheck(digit >= '0' && digit <= '9' && size <= 4096, "mock DAP request length bound"); size = size * 10 + static_cast<size_t>(digit - '0'); }
        mockCheck(size > 0 && size <= 4096, "mock DAP request body bound");
        std::string body; body.reserve(size); for (size_t i = 0; i < size; ++i) body += byte();
        mockCheck(body.find("\"seq\":" + std::to_string(sequence) + ',') != std::string::npos && body.find("\"type\":\"request\"") != std::string::npos && body.find("\"command\":\"" + command + "\"") != std::string::npos, "unexpected actual TCP DAP request");
        mockCheck(body.find("launch") == std::string::npos && body.find("evaluate") == std::string::npos && body.find("attachCommands") == std::string::npos, "mock rejects process-execution request surface");
        return body;
    }
};
class LoopbackMock {
public:
    LoopbackMock() {
        listener_ = ::socket(AF_INET, SOCK_STREAM, 0); require(listener_ >= 0, "create controlled loopback listener");
        require(::fcntl(listener_, F_SETFL, O_NONBLOCK) == 0 && ::fcntl(listener_, F_SETFD, FD_CLOEXEC) == 0, "bounded loopback listener flags");
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = 0;
        require(::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(listener_, 1) == 0, "bind/listen explicit loopback ephemeral port");
        socklen_t size = sizeof(address); require(::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &size) == 0, "resolve controlled loopback port"); port_ = ntohs(address.sin_port);
    }
    ~LoopbackMock() { if (thread_.joinable()) thread_.join(); if (listener_ >= 0) ::close(listener_); }
    DebuggerEndpoint endpoint() const { return {"127.0.0.1", port_, false}; }
    void start(const std::function<void(MockPeer&)>& work) {
        thread_ = std::thread([this, work] {
            try {
                const u64 limit = debuggerMonotonicMs() + 4000;
                mockCheck(socketReady(listener_, POLLIN, limit), "controlled loopback accept deadline");
                const int accepted = ::accept(listener_, nullptr, nullptr); mockCheck(accepted >= 0, "controlled loopback accept failed");
                MockPeer peer{accepted, limit};
                mockCheck(::fcntl(accepted, F_SETFL, O_NONBLOCK) == 0 && ::fcntl(accepted, F_SETFD, FD_CLOEXEC) == 0, "controlled peer nonblocking/CLOEXEC flags");
                int yes = 1; mockCheck(::setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == 0, "controlled peer packet fragmentation flag");
#ifdef SO_NOSIGPIPE
                mockCheck(::setsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) == 0, "controlled peer SIGPIPE guard");
#endif
                work(peer);
            } catch (const std::exception& failure) { error_ = failure.what(); }
        });
    }
    void finish() { thread_.join(); require(error_.empty(), "bounded controlled loopback peer: " + error_); }
    void refuse() { ::close(listener_); listener_ = -1; }
private:
    int listener_ = -1; u16 port_ = 0; std::thread thread_; std::string error_;
};
void mockRspHandshake(MockPeer& peer) {
    peer.rspExchange("qSupported:swbreak+;vContSupported+", "PacketSize=4000", 1);
    peer.rspExchange("vCont?", "vCont;c;s", 2);
    peer.rspExchange("?", "T05thread:2;", 1);
}
void mockDapHandshake(MockPeer& peer) {
    peer.dapRequest(1, "initialize"); peer.send(response(1, 1, "initialize", "{\"supportsConfigurationDoneRequest\":true,\"supportsReadMemoryRequest\":true,\"supportsSteppingGranularity\":true}"), 3, true);
    const auto attach = peer.dapRequest(2, "attach"); mockCheck(attach.find("\"pid\":123") != std::string::npos, "controlled mock PID only");
    peer.send(event(2, "initialized"), 1, true); peer.dapRequest(3, "configurationDone");
    // Events and out-of-order request responses share one TCP write stream.
    peer.send(event(3, "stopped", "{\"reason\":\"entry\",\"threadId\":7}") + response(4, 3, "configurationDone") + response(5, 2, "attach"), 65536);
}
void tcpRspWorkflow() {
    LoopbackMock server; server.start([](MockPeer& peer) {
        mockRspHandshake(peer);
        peer.rspExchange("mfffffffffff01000,4", "01020304", 1);
        peer.rspRequest("vCont;s:2"); peer.send('+' + packet("T05thread:2;"), 2, true); mockCheck(peer.byte() == '+', "TCP stopped event ACK");
        peer.expectClosed();
    });
    DebuggerOptions options; options.timeoutMs = 2000; DebuggerClient client;
    okay(client.connectTcp(server.endpoint(), DebuggerBackend::kGdbRemote, options), "real TCP RSP fragmented handshake");
    require(client.snapshot().state == DebuggerState::kStopped && client.snapshot().threadId == 2, "real TCP RSP initial stopped state");
    std::vector<u8> memory{9}; okay(client.readMemory(0xfffffffffff01000ULL, 4, &memory), "real TCP RSP high-address memory"); require(memory == std::vector<u8>({1, 2, 3, 4}), "real TCP RSP fragmented exact memory bytes");
    okay(client.step(), "real TCP RSP single instruction step"); require(client.snapshot().state == DebuggerState::kRunning, "real TCP RSP nonblocking run control"); okay(client.waitForStop(), "real TCP RSP bounded stop event");
    client.disconnect(); require(client.snapshot().state == DebuggerState::kDisconnected, "real TCP RSP local disconnect"); server.finish();
}
void tcpDapWorkflow() {
    LoopbackMock server; server.start([](MockPeer& peer) {
        mockDapHandshake(peer); const auto memory = peer.dapRequest(4, "readMemory");
        mockCheck(memory.find("\"memoryReference\":\"0xfffffffffff01000\"") != std::string::npos && memory.find("\"count\":4") != std::string::npos, "actual TCP DAP exact memory arguments");
        peer.send(response(6, 4, "readMemory", "{\"address\":\"0xfffffffffff01000\",\"data\":\"AQIDBA==\"}"), 2, true);
        const auto step = peer.dapRequest(5, "stepIn"); mockCheck(step.find("\"granularity\":\"instruction\"") != std::string::npos, "actual TCP DAP instruction step argument");
        peer.send(response(7, 5, "stepIn") + event(8, "stopped", "{\"reason\":\"step\",\"threadId\":7}"), 65536); peer.expectClosed();
    });
    DebuggerOptions options; options.timeoutMs = 2000; DebuggerClient client;
    okay(client.connectTcp(server.endpoint(), DebuggerBackend::kLldbDap, options), "real TCP DAP fragmented header/body initialization");
    require(client.snapshot().state == DebuggerState::kConnected, "real TCP DAP initialization does not attach process"); okay(client.attachProcess(123), "real TCP DAP controlled mock attach");
    require(client.snapshot().state == DebuggerState::kStopped && client.snapshot().threadId == 7, "real TCP DAP coalesced events and reordered responses");
    std::vector<u8> memory{9}; okay(client.readMemory(0xfffffffffff01000ULL, 4, &memory), "real TCP DAP memory frame"); require(memory == std::vector<u8>({1, 2, 3, 4}), "real TCP DAP fragmented binary memory");
    okay(client.step(), "real TCP DAP instruction step"); require(client.snapshot().state == DebuggerState::kRunning, "real TCP DAP step state"); okay(client.waitForStop(), "real TCP DAP coalesced stop event"); client.disconnect(); server.finish();
}
void tcpFaults(DebuggerBackend backend) {
    for (bool timeout : {false, true}) {
        LoopbackMock server; server.start([backend, timeout](MockPeer& peer) {
            if (backend == DebuggerBackend::kGdbRemote) { mockRspHandshake(peer); peer.rspRequest("m1000,2"); peer.send("+"); if (!timeout) peer.send("$01", 1); }
            else { mockDapHandshake(peer); peer.dapRequest(4, "readMemory"); if (!timeout) peer.send("Content-Length: 64\r\n\r\n{\"seq\":6", 1); }
            if (!timeout) peer.halfClose(); peer.expectClosed();
        });
        DebuggerOptions options; options.timeoutMs = 2000; DebuggerClient client;
        okay(client.connectTcp(server.endpoint(), backend, options), "real TCP fault fixture handshake"); if (backend == DebuggerBackend::kLldbDap) okay(client.attachProcess(123), "real TCP fault fixture explicit mock attach");
        // The fresh connection's public options supply the operation deadline;
        // no hidden options are changed and caller bytes must remain intact.
        const u64 start = debuggerMonotonicMs(); std::vector<u8> memory{0xaa, 0xbb}; const auto status = client.readMemory(0x1000, 2, &memory); const auto elapsed = debuggerMonotonicMs() - start;
        require(!status.ok() && status.code() == ErrorCode::kIoError && memory == std::vector<u8>({0xaa, 0xbb}) && client.snapshot().state == DebuggerState::kDisconnected, timeout ? "actual TCP operation timeout is atomic and closes socket" : "actual TCP mid-frame EOF is atomic and closes socket");
        if (timeout) require(elapsed >= 1000 && elapsed < 3500 && status.message().find("deadline") != std::string::npos, "actual TCP absolute operation deadline measured");
        server.finish();
    }
    LoopbackMock rejected; const auto endpoint = rejected.endpoint(); rejected.refuse(); DebuggerClient client; DebuggerOptions options; options.timeoutMs = 250;
    const u64 start = debuggerMonotonicMs(); const auto status = client.connectTcp(endpoint, backend, options);
    require(!status.ok() && status.code() == ErrorCode::kIoError && debuggerMonotonicMs() - start < 1000 && client.snapshot().state == DebuggerState::kDisconnected, "actual TCP refused connection stays disconnected and bounded");
}
}  // namespace
int main() {
    inputValidation();
    expandedWorkspace();
    for (size_t fragment : {size_t(1), size_t(2), size_t(3), size_t(64), size_t(4096)}) { rspWorkflow(fragment); dapWorkflow(fragment); }
    hostileRsp(); hostileDap();
    tcpRspWorkflow(); tcpDapWorkflow(); tcpFaults(DebuggerBackend::kGdbRemote); tcpFaults(DebuggerBackend::kLldbDap);
    std::cout << "External debugger simulated protocols + real loopback TCP: " << checks << " checks; passed (no real debugger/debuggee operated)\n";
}
