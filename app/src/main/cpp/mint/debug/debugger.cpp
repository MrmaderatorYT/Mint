#include "mint/debug/debugger.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace mint {
u64 debuggerMonotonicMs() {
    return static_cast<u64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}
namespace {
constexpr size_t kMaxFrame = 1024 * 1024, kMaxRsp = 65536;
Status bad(const std::string& message) { return Status::error(ErrorCode::kBadFormat, "debug protocol: " + message); }
Status unsupported(const std::string& message) { return Status::error(ErrorCode::kUnsupported, message); }
Status io(const std::string& message) { return Status::error(ErrorCode::kIoError, "debug transport: " + message); }
std::string hex(u64 n) { std::ostringstream out; out << std::hex << n; return out.str(); }
int digit(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
bool integer(const std::string& text, unsigned base, u64* out) {
    if (text.empty()) return false;
    u64 value = 0;
    for (char c : text) { const int d = digit(c); if (d < 0 || unsigned(d) >= base || value > (~u64(0) - unsigned(d)) / base) return false; value = value * base + unsigned(d); }
    *out = value; return true;
}
bool addressValue(const std::string& text, Address* out) { return text.size() >= 2 && text[0] == '0' && text[1] == 'x' ? integer(text.substr(2), 16, out) : integer(text, 10, out); }
bool bytesFromHex(const std::string& text, std::vector<u8>* out, bool unavailable = false, bool* available = nullptr) {
    if (text.size() % 2 || text.size() > kMaxRsp) return false;
    std::vector<u8> result; result.reserve(text.size() / 2); bool known = true;
    for (size_t i = 0; i < text.size(); i += 2) {
        const int high = digit(text[i]), low = digit(text[i + 1]);
        if (high >= 0 && low >= 0) result.push_back(static_cast<u8>(high * 16 + low));
        else if (unavailable && text[i] == 'x' && text[i + 1] == 'x') { result.push_back(0); known = false; }
        else return false;
    }
    if (available) *available = known;
    *out = std::move(result); return true;
}
bool utf8(const std::string& text) {
    for (size_t i = 0; i < text.size();) {
        const auto c = static_cast<u8>(text[i++]); if (c < 0x80) continue;
        unsigned count = 0; u32 value = 0, minimum = 0;
        if (c >= 0xc2 && c <= 0xdf) { count = 1; value = c & 0x1f; minimum = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { count = 2; value = c & 0x0f; minimum = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { count = 3; value = c & 7; minimum = 0x10000; }
        else return false;
        while (count--) { if (i >= text.size() || (static_cast<u8>(text[i]) & 0xc0) != 0x80) return false; value = (value << 6) | (static_cast<u8>(text[i++]) & 0x3f); }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
    }
    return true;
}
std::string quote(const std::string& text) {
    std::string result = "\""; const char* digits = "0123456789abcdef";
    for (unsigned char c : text) {
        if (c == '"' || c == '\\') { result += '\\'; result += c; }
        else if (c < 32) { result += "\\u00"; result += digits[c >> 4]; result += digits[c & 15]; }
        else result += c;
    }
    result += '"'; return result;
}
std::string safeText(std::string text) { if (text.size() > 4096) { text.resize(4096); while (!text.empty() && !utf8(text)) text.pop_back(); } for (char& c : text) if (static_cast<unsigned char>(c) < 32 || c == 127) c = ' '; return text; }

struct Json {
    enum Kind { Null, Boolean, Number, String, Object, Array } kind = Null;
    std::string text; bool boolean = false;
    std::map<std::string, Json> object;
    std::vector<Json> array;
    const Json* get(const std::string& key) const { auto it = object.find(key); return kind == Object && it != object.end() ? &it->second : nullptr; }
    std::string string(const std::string& key) const { const auto* v = get(key); return v && v->kind == String ? v->text : std::string(); }
    bool flag(const std::string& key) const { const auto* v = get(key); return v && v->kind == Boolean && v->boolean; }
    bool uint(const std::string& key, u64* n) const { const auto* v = get(key); return v && v->kind == Number && integer(v->text, 10, n); }
};
class JsonParser {
public:
    explicit JsonParser(const std::string& text) : text_(text) {}
    bool parse(Json* out) { if (text_.size() > kMaxFrame || !value(out, 0)) return false; space(); return pos_ == text_.size(); }
private:
    void space() { while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\r' || text_[pos_] == '\n' || text_[pos_] == '\t')) ++pos_; }
    bool take(char c) { space(); if (pos_ >= text_.size() || text_[pos_] != c) return false; ++pos_; return true; }
    bool unicode(u32* out) { if (text_.size() - pos_ < 4) return false; *out = 0; for (unsigned i = 0; i < 4; ++i) { int d = digit(text_[pos_++]); if (d < 0) return false; *out = *out * 16 + unsigned(d); } return true; }
    bool string(std::string* out) {
        if (!take('"')) return false;
        while (pos_ < text_.size() && out->size() <= 262144) {
            const unsigned char c = text_[pos_++]; if (c == '"') return utf8(*out); if (c < 32) return false;
            if (c != '\\') { *out += c; continue; }
            if (pos_ == text_.size()) return false;
            char e = text_[pos_++];
            if (e == '"' || e == '\\' || e == '/') *out += e;
            else if (e == 'b') *out += '\b'; else if (e == 'f') *out += '\f'; else if (e == 'n') *out += '\n'; else if (e == 'r') *out += '\r'; else if (e == 't') *out += '\t';
            else if (e == 'u') {
                u32 n = 0; if (!unicode(&n)) return false;
                if (n >= 0xd800 && n <= 0xdbff) { if (text_.size() - pos_ < 2 || text_[pos_++] != '\\' || text_[pos_++] != 'u') return false; u32 low = 0; if (!unicode(&low) || low < 0xdc00 || low > 0xdfff) return false; n = 0x10000 + ((n - 0xd800) << 10) + low - 0xdc00; }
                else if (n >= 0xdc00 && n <= 0xdfff) return false;
                if (n < 0x80) *out += static_cast<char>(n);
                else if (n < 0x800) { *out += static_cast<char>(0xc0 | (n >> 6)); *out += static_cast<char>(0x80 | (n & 63)); }
                else if (n < 0x10000) { *out += static_cast<char>(0xe0 | (n >> 12)); *out += static_cast<char>(0x80 | ((n >> 6) & 63)); *out += static_cast<char>(0x80 | (n & 63)); }
                else { *out += static_cast<char>(0xf0 | (n >> 18)); *out += static_cast<char>(0x80 | ((n >> 12) & 63)); *out += static_cast<char>(0x80 | ((n >> 6) & 63)); *out += static_cast<char>(0x80 | (n & 63)); }
            } else return false;
        }
        return false;
    }
    bool value(Json* out, unsigned depth) {
        space(); if (depth > 32 || ++nodes_ > 16384 || pos_ == text_.size()) return false;
        char c = text_[pos_];
        if (c == '"') { out->kind = Json::String; return string(&out->text); }
        if (c == '{') {
            out->kind = Json::Object; ++pos_; if (take('}')) return true;
            do { std::string key; Json child; if (!string(&key) || key.size() > 1024 || !take(':') || !value(&child, depth + 1) || !out->object.emplace(std::move(key), std::move(child)).second) return false; if (take('}')) return true; } while (take(','));
            return false;
        }
        if (c == '[') {
            out->kind = Json::Array; ++pos_; if (take(']')) return true;
            do { Json child; if (!value(&child, depth + 1)) return false; out->array.push_back(std::move(child)); if (take(']')) return true; } while (take(',')); return false;
        }
        for (const auto& literal : {std::string("true"), std::string("false"), std::string("null")}) if (text_.compare(pos_, literal.size(), literal) == 0) { pos_ += literal.size(); out->kind = literal == "null" ? Json::Null : Json::Boolean; out->boolean = literal == "true"; return true; }
        const auto start = pos_; if (c == '-') ++pos_;
        if (pos_ == text_.size() || text_[pos_] < '0' || text_[pos_] > '9') return false;
        if (text_[pos_] == '0') ++pos_; else while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
        if (pos_ < text_.size() && text_[pos_] == '.') { ++pos_; const auto digits = pos_; while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_; if (digits == pos_) return false; }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) { ++pos_; if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_; const auto digits = pos_; while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_; if (digits == pos_) return false; }
        out->kind = Json::Number; out->text = text_.substr(start, pos_ - start); return out->text.size() <= 128;
    }
    const std::string& text_; size_t pos_ = 0, nodes_ = 0;
};

bool base64(const std::string& text, std::vector<u8>* out) {
    if (text.size() % 4 || text.size() > (DebuggerClient::kMaxMemoryRead + 2) / 3 * 4) return false;
    const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<u8> result;
    for (size_t i = 0; i < text.size(); i += 4) {
        u32 value = 0; unsigned padding = 0;
        for (unsigned j = 0; j < 4; ++j) {
            if (text[i + j] == '=') { if (i + 4 != text.size() || j < 2) return false; ++padding; value <<= 6; }
            else { if (padding) return false; auto d = alphabet.find(text[i + j]); if (d == std::string::npos) return false; value = (value << 6) | static_cast<u32>(d); }
        }
        if (padding > 2 || (padding == 1 && (value & 0xff)) || (padding == 2 && (value & 0xffff))) return false;
        result.push_back(static_cast<u8>(value >> 16)); if (padding < 2) result.push_back(static_cast<u8>(value >> 8)); if (!padding) result.push_back(static_cast<u8>(value));
    }
    *out = std::move(result); return true;
}

Status ready(int fd, short event, u64 deadline) {
    for (;;) {
        const u64 now = debuggerMonotonicMs(); if (now >= deadline) return io("operation deadline exceeded");
        pollfd item{fd, event, 0}; const int result = ::poll(&item, 1, static_cast<int>(std::min<u64>(deadline - now, INT_MAX)));
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return io("socket poll failed"); if (!result) return io("operation deadline exceeded");
        if (item.revents & event) return Status::success();
        if (item.revents & (POLLHUP | POLLERR | POLLNVAL)) return io("connection closed or socket error");
    }
}
class TcpTransport final : public DebuggerTransport {
public:
    explicit TcpTransport(int fd) : fd_(fd) {} ~TcpTransport() override { close(); }
    Status readSome(u8* data, size_t capacity, size_t* count, u64 deadline) override {
        for (;;) { auto status = ready(fd_, POLLIN, deadline); if (!status.ok()) return status; const auto n = ::recv(fd_, data, capacity, 0); if (n > 0) { *count = static_cast<size_t>(n); return Status::success(); } if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue; return io(n ? "socket read failed" : "peer closed connection"); }
    }
    Status writeSome(const u8* data, size_t size, size_t* count, u64 deadline) override {
        for (;;) { auto status = ready(fd_, POLLOUT, deadline); if (!status.ok()) return status;
#ifdef MSG_NOSIGNAL
            const auto n = ::send(fd_, data, size, MSG_NOSIGNAL);
#else
            const auto n = ::send(fd_, data, size, 0);
#endif
            if (n > 0) { *count = static_cast<size_t>(n); return Status::success(); } if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue; return io("socket write failed"); }
    }
    void close() override { if (fd_ >= 0) { ::close(fd_); fd_ = -1; } }
private: int fd_ = -1;
};
Status tcp(const DebuggerEndpoint& endpoint, u64 deadline, std::unique_ptr<DebuggerTransport>* out) {
    if (!endpoint.port || endpoint.host.size() > 128 || endpoint.host.find('\0') != std::string::npos) return bad("invalid explicit endpoint");
    sockaddr_storage storage{}; socklen_t length = 0; bool loopback = false; int family = AF_INET;
    auto* v4 = reinterpret_cast<sockaddr_in*>(&storage); auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
    if (::inet_pton(AF_INET, endpoint.host.c_str(), &v4->sin_addr) == 1) { v4->sin_family = AF_INET; v4->sin_port = htons(endpoint.port); length = sizeof(*v4); loopback = (ntohl(v4->sin_addr.s_addr) >> 24) == 127; }
    else if (::inet_pton(AF_INET6, endpoint.host.c_str(), &v6->sin6_addr) == 1) { family = AF_INET6; v6->sin6_family = AF_INET6; v6->sin6_port = htons(endpoint.port); length = sizeof(*v6); loopback = IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr); }
    else return bad("endpoint must be a numeric IPv4/IPv6 address (use loopback with a tunnel)");
    if (!loopback && !endpoint.allowPlaintextRemote) return unsupported("Remote debugger TCP is unauthenticated plaintext; explicit acknowledgement or a loopback tunnel is required");
    const int fd = ::socket(family, SOCK_STREAM, 0); if (fd < 0) return io("socket creation failed");
    std::unique_ptr<DebuggerTransport> candidate(new TcpTransport(fd));
    if (::fcntl(fd, F_SETFL, O_NONBLOCK) < 0 || ::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) return io("socket flags failed");
#ifdef SO_NOSIGPIPE
    int yes = 1; if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) != 0) return io("socket signal guard failed");
#endif
    const int result = ::connect(fd, reinterpret_cast<sockaddr*>(&storage), length);
    if (result < 0 && errno != EINPROGRESS) return io("TCP connection failed");
    if (result < 0) { auto status = ready(fd, POLLOUT, deadline); if (!status.ok()) return status; int error = 0; socklen_t size = sizeof(error); if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) || error) return io("TCP connection failed"); }
    *out = std::move(candidate); return Status::success();
}
}  // namespace

struct DebuggerClient::Impl {
    DebuggerSnapshot state;
    DebuggerOptions options;
    std::unique_ptr<DebuggerTransport> transport;
    std::array<u8, 4096> buffer{}; size_t cursor = 0, end = 0;
    bool noAck = false, vContinue = false, vStep = false, initialized = false, configurationDone = false, instructionStep = false, attached = false;
    size_t packetSize = kMaxRsp; u32 seq = 0, incomingSeq = 0; u64 stoppedEpoch = 0;
    std::map<u32, std::string> requests;
    std::map<u32, Json> responses;
    std::set<Address> breakpoints;
    std::vector<DebuggerImageMapping> mappings;
    ~Impl() { if (transport) transport->close(); }
    u64 deadline() const { return debuggerMonotonicMs() + options.timeoutMs; }
    Status fail(Status status) { if (transport) transport->close(); transport.reset(); state.state = DebuggerState::kDisconnected; state.reason = safeText(status.message()); return status; }
    Status stopped() const { return transport && attached && state.state == DebuggerState::kStopped ? Status::success() : unsupported("Operation requires a connected stopped target"); }
    Status read(u8* out, size_t size, u64 limit) {
        while (size) {
            if (debuggerMonotonicMs() >= limit) return fail(io("operation deadline exceeded"));
            if (cursor == end) { size_t count = 0; auto status = transport->readSome(buffer.data(), buffer.size(), &count, limit); if (!status.ok()) return fail(status); if (!count || count > buffer.size()) return fail(bad("transport returned invalid read progress")); cursor = 0; end = count; }
            const auto count = std::min(size, end - cursor); std::memcpy(out, buffer.data() + cursor, count); cursor += count; out += count; size -= count;
        }
        return Status::success();
    }
    Status write(const std::string& bytes, u64 limit) {
        for (size_t position = 0; position < bytes.size();) {
            if (debuggerMonotonicMs() >= limit) return fail(io("operation deadline exceeded"));
            size_t count = 0; auto status = transport->writeSome(reinterpret_cast<const u8*>(bytes.data() + position), bytes.size() - position, &count, limit);
            if (!status.ok()) return fail(status); if (!count || count > bytes.size() - position) return fail(bad("transport returned invalid write progress")); position += count;
        }
        return Status::success();
    }
    Status rspSend(const std::string& command, u64 limit) {
        if (command.size() > packetSize) return unsupported("Request exceeds negotiated GDB packet size");
        unsigned checksum = 0; for (unsigned char c : command) checksum = (checksum + c) & 255;
        const char* digits = "0123456789abcdef"; const auto packet = '$' + command + '#' + digits[checksum >> 4] + digits[checksum & 15];
        for (unsigned retry = 0; retry < 3; ++retry) { auto status = write(packet, limit); if (!status.ok()) return status; if (noAck) return status; u8 ack = 0; status = read(&ack, 1, limit); if (!status.ok()) return status; if (ack == '+') return status; if (ack != '-') return fail(bad("GDB acknowledgement expected")); }
        return fail(bad("GDB retransmission limit exceeded"));
    }
    Status rspReceive(std::string* out, u64 limit) {
        for (unsigned messages = 0, badChecksums = 0; messages < 64; ++messages) {
            u8 byte = 0; auto status = read(&byte, 1, limit); if (!status.ok()) return status;
            if (byte != '$') return fail(bad("GDB packet marker expected (non-stop notifications unsupported)"));
            std::string encoded; unsigned sum = 0;
            for (;;) { status = read(&byte, 1, limit); if (!status.ok()) return status; if (byte == '#') break; if (byte == '$' || encoded.size() >= kMaxRsp) return fail(bad("invalid/oversized GDB packet")); encoded += static_cast<char>(byte); sum = (sum + byte) & 255; }
            u8 checksum[2]{}; status = read(checksum, 2, limit); if (!status.ok()) return status;
            const int high = digit(static_cast<char>(checksum[0])), low = digit(static_cast<char>(checksum[1]));
            if (high < 0 || low < 0 || unsigned(high * 16 + low) != sum) { if (noAck || ++badChecksums >= 3) return fail(bad("GDB checksum mismatch")); status = write("-", limit); if (!status.ok()) return status; continue; }
            std::string decoded;
            for (size_t i = 0; i < encoded.size(); ++i) {
                u8 c = static_cast<u8>(encoded[i]);
                if (c == '}') { if (++i == encoded.size()) return fail(bad("truncated GDB escape")); decoded += static_cast<char>(static_cast<u8>(encoded[i]) ^ 0x20); }
                else if (c == '*') { if (decoded.empty() || ++i == encoded.size()) return fail(bad("invalid GDB run length")); const auto count = static_cast<u8>(encoded[i]); if (count < 32 || count > 126 || count == '#' || count == '$' || count - 29 > kMaxRsp - decoded.size()) return fail(bad("invalid/oversized GDB run length")); decoded.append(count - 29, decoded.back()); }
                else decoded += static_cast<char>(c);
                if (decoded.size() > kMaxRsp) return fail(bad("expanded GDB packet exceeds limit"));
            }
            if (!noAck) { status = write("+", limit); if (!status.ok()) return status; }
            if (decoded.size() > 1 && decoded[0] == 'O' && decoded != "OK") { std::vector<u8> console; if (!bytesFromHex(decoded.substr(1), &console)) return fail(bad("invalid GDB console packet")); continue; }
            *out = std::move(decoded); return Status::success();
        }
        return fail(bad("GDB response/event budget exceeded"));
    }
    Status rsp(const std::string& command, std::string* out, u64 limit) {
        auto status = rspSend(command, limit); if (!status.ok()) return status;
        status = rspReceive(out, limit); if (!status.ok()) return status;
        if (!out->empty() && (*out)[0] == 'E') return unsupported("GDB server rejected the request");
        return status;
    }
    Status stopReply(const std::string& reply) {
        if (reply.size() < 3 || digit(reply[1]) < 0 || digit(reply[2]) < 0) return fail(bad("invalid GDB stop reply"));
        if (reply[0] == 'W' || reply[0] == 'X') { if (reply.size() != 3) return fail(bad("unsupported GDB exit-reply suffix")); state.state = DebuggerState::kExited; state.reason = reply[0] == 'W' ? "Target exited" : "Target terminated by signal"; return Status::success(); }
        if (reply[0] != 'T' && reply[0] != 'S') return fail(bad("GDB stop reply expected"));
        if (reply[0] == 'S' && reply.size() != 3) return fail(bad("unsupported GDB signal suffix"));
        u64 thread = 0; bool hasThread = false;
        for (size_t pos = 3; pos < reply.size();) {
            const auto finish = reply.find(';', pos); if (finish == std::string::npos) return fail(bad("unterminated GDB stop field"));
            const auto colon = reply.find(':', pos); if (colon == std::string::npos || colon == pos || colon >= finish) return fail(bad("invalid GDB stop field"));
            if (reply.compare(pos, colon - pos, "thread") == 0) { if (hasThread || !integer(reply.substr(colon + 1, finish - colon - 1), 16, &thread) || !thread) return fail(bad("invalid/duplicate GDB stopped thread")); hasThread = true; }
            pos = finish + 1;
        }
        state.state = DebuggerState::kStopped; state.signal = static_cast<u32>(digit(reply[1]) * 16 + digit(reply[2])); state.threadId = thread;
        state.reason = "GDB stop signal " + std::to_string(state.signal); ++stoppedEpoch; return Status::success();
    }
    Status dapSend(const std::string& command, const std::string& arguments, u32* id, u64 limit) {
        if (seq == INT_MAX || requests.size() >= 8) return fail(bad("DAP request sequence budget exceeded"));
        *id = ++seq;
        const auto message = "{\"seq\":" + std::to_string(*id) + ",\"type\":\"request\",\"command\":" + quote(command) + ",\"arguments\":" + arguments + '}';
        requests[*id] = command;
        return write("Content-Length: " + std::to_string(message.size()) + "\r\n\r\n" + message, limit);
    }
    Status dapMessage(u64 limit) {
        std::string header; u8 c = 0;
        while (header.size() < 8192 && (header.size() < 4 || header.compare(header.size() - 4, 4, "\r\n\r\n"))) { auto status = read(&c, 1, limit); if (!status.ok()) return status; if (c > 127 || (!c)) return fail(bad("DAP header must be ASCII")); header += static_cast<char>(c); }
        if (header.size() >= 8192) return fail(bad("DAP header limit exceeded"));
        u64 length = 0; bool seen = false;
        for (size_t start = 0; start + 2 < header.size();) {
            const auto finish = header.find("\r\n", start); if (finish == start) break;
            const auto colon = header.find(':', start); if (colon == std::string::npos || colon > finish) return fail(bad("invalid DAP header field"));
            auto name = header.substr(start, colon - start); std::transform(name.begin(), name.end(), name.begin(), [](unsigned char n) { return n >= 'A' && n <= 'Z' ? n + 32 : n; });
            auto value = header.substr(colon + 1, finish - colon - 1); while (!value.empty() && value.front() == ' ') value.erase(value.begin()); while (!value.empty() && value.back() == ' ') value.pop_back();
            if (name == "content-length") { if (seen || !integer(value, 10, &length) || !length || length > kMaxFrame) return fail(bad("invalid/oversized duplicate DAP Content-Length")); seen = true; }
            else if (name != "content-type") return fail(bad("unsupported DAP header field"));
            start = finish + 2;
        }
        if (!seen) return fail(bad("DAP Content-Length missing"));
        std::string message(static_cast<size_t>(length), '\0'); auto status = read(reinterpret_cast<u8*>(message.data()), message.size(), limit); if (!status.ok()) return status;
        Json json; if (!JsonParser(message).parse(&json) || json.kind != Json::Object) return fail(bad("invalid bounded DAP JSON"));
        u64 sequence = 0; if (!json.uint("seq", &sequence) || !sequence || sequence > INT_MAX || sequence <= incomingSeq) return fail(bad("non-monotonic DAP sequence")); incomingSeq = static_cast<u32>(sequence);
        const auto type = json.string("type");
        if (type == "request") return fail(unsupported("Adapter reverse requests (including terminal/shell execution) are refused"));
        if (type == "response") {
            u64 id = 0; const auto* success = json.get("success");
            if (!json.uint("request_seq", &id) || id > INT_MAX || !requests.count(static_cast<u32>(id)) || responses.count(static_cast<u32>(id)) ||
                json.string("command") != requests.at(static_cast<u32>(id)) || !success || success->kind != Json::Boolean) return fail(bad("DAP response does not match a pending request"));
            responses[static_cast<u32>(id)] = std::move(json); return Status::success();
        }
        if (type != "event" || json.string("event").empty()) return fail(bad("unsupported DAP message type"));
        const auto event = json.string("event"); const auto* body = json.get("body");
        if (event == "initialized") initialized = true;
        else if (event == "stopped") {
            if (!body || body->kind != Json::Object || body->string("reason").empty()) return fail(bad("invalid DAP stopped event"));
            u64 thread = 0; if (body->get("threadId") && (!body->uint("threadId", &thread) || !thread || thread > INT_MAX)) return fail(bad("invalid DAP thread ID"));
            state.state = DebuggerState::kStopped; state.threadId = thread; state.reason = safeText(body->string("reason")); ++stoppedEpoch;
        } else if (event == "continued") { state.state = DebuggerState::kRunning; state.reason = "Target running"; }
        else if (event == "exited") { state.state = DebuggerState::kExited; state.reason = "Target exited"; }
        else if (event == "terminated") { state.state = DebuggerState::kConnected; attached = false; state.reason = "Debug session terminated (target exit not implied)"; }
        // Output, telemetry, hyperlinks and other untrusted adapter data are not
        // interpreted or executed. Only the state events above affect control.
        return Status::success();
    }
    Status dapWait(u32 id, Json* out, u64 limit) {
        for (unsigned events = 0; events < 128; ++events) {
            auto found = responses.find(id);
            if (found != responses.end()) { Json reply = std::move(found->second); responses.erase(found); requests.erase(id); if (!reply.flag("success")) return unsupported("DAP adapter rejected request: " + safeText(reply.string("message"))); const auto* body = reply.get("body"); if (body) *out = *body; else *out = Json(); return Status::success(); }
            auto status = dapMessage(limit); if (!status.ok()) return status;
        }
        return fail(bad("DAP event budget exceeded"));
    }
    Status dap(const std::string& command, const std::string& args, Json* out, u64 limit) { u32 id = 0; auto status = dapSend(command, args, &id, limit); return status.ok() ? dapWait(id, out, limit) : status; }
    Status thread(u64 limit) {
        if (state.threadId) return Status::success();
        Json body; auto status = dap("threads", "{}", &body, limit); if (!status.ok()) return status;
        const auto* threads = body.get("threads"); u64 id = 0;
        if (!threads || threads->kind != Json::Array || threads->array.empty() || threads->array.size() > 4096 || !threads->array.front().uint("id", &id) || !id || id > INT_MAX) return fail(bad("no valid DAP thread"));
        state.threadId = id; return Status::success();
    }
};

DebuggerClient::DebuggerClient() : impl_(new Impl) {}
DebuggerClient::~DebuggerClient() = default;
void DebuggerClient::disconnect() { impl_.reset(new Impl); }
const DebuggerSnapshot& DebuggerClient::snapshot() const { return impl_->state; }
Status DebuggerClient::connectTcp(const DebuggerEndpoint& endpoint, DebuggerBackend backend, const DebuggerOptions& options) {
    if (backend != DebuggerBackend::kGdbRemote && backend != DebuggerBackend::kLldbDap) return bad("invalid explicit backend");
    if (!options.timeoutMs || options.timeoutMs > 30000) return bad("timeout must be 1..30000 milliseconds");
    const auto start = debuggerMonotonicMs();
    std::unique_ptr<DebuggerTransport> transport; auto status = tcp(endpoint, start + options.timeoutMs, &transport); if (!status.ok()) return status;
    const auto elapsed = debuggerMonotonicMs() - start; if (elapsed >= options.timeoutMs) return io("connect deadline exceeded");
    auto remaining = options; remaining.timeoutMs = static_cast<u32>(options.timeoutMs - elapsed);
    status = connect(std::move(transport), backend, remaining);
    if (status.ok()) { impl_->options = options; impl_->state.notes.push_back("Debugger TCP is unauthenticated plaintext; use a trusted loopback tunnel. Disconnect closes the client only and does not guarantee the stub preserves target state."); }
    return status;
}
Status DebuggerClient::connect(std::unique_ptr<DebuggerTransport> transport, DebuggerBackend backend, const DebuggerOptions& options) {
    if (!transport) return bad("null transport");
    if ((backend != DebuggerBackend::kGdbRemote && backend != DebuggerBackend::kLldbDap) || !options.timeoutMs || options.timeoutMs > 30000 || options.registerLayout.size() > 1024) { transport->close(); return bad("invalid backend/options"); }
    size_t bytes = 0; std::set<std::string> names; std::set<u32> numbers;
    for (const auto& reg : options.registerLayout) {
        if (reg.name.empty() || reg.name.size() > 128 || !utf8(reg.name) || !reg.bits || reg.bits % 8 || reg.bits > 4096 || !names.insert(reg.name).second || !numbers.insert(reg.number).second || reg.bits / 8 > kMaxRsp / 2 - bytes) { transport->close(); return bad("invalid exact RSP register layout"); }
        bytes += reg.bits / 8;
    }
    std::unique_ptr<Impl> candidate(new Impl); candidate->transport = std::move(transport); candidate->options = options; candidate->state.backend = backend; candidate->state.state = DebuggerState::kConnected;
    const auto limit = candidate->deadline(); Status status;
    if (backend == DebuggerBackend::kGdbRemote) {
        std::string features; status = candidate->rsp("qSupported:swbreak+;vContSupported+", &features, limit); if (!status.ok()) return status;
        bool noAck = false;
        for (size_t start = 0; start < features.size();) { const auto finish = features.find(';', start); const auto item = features.substr(start, finish == std::string::npos ? finish : finish - start);
            if (item.compare(0, 11, "PacketSize=") == 0) { u64 value = 0; if (!integer(item.substr(11), 16, &value) || value < 64) return candidate->fail(bad("invalid GDB PacketSize")); candidate->packetSize = static_cast<size_t>(std::min<u64>(value, kMaxRsp)); }
            if (item == "QStartNoAckMode+") noAck = true;
            if (finish == std::string::npos) break; start = finish + 1;
        }
        if (noAck) { std::string reply; status = candidate->rsp("QStartNoAckMode", &reply, limit); if (!status.ok()) return status; if (reply == "OK") candidate->noAck = true; else if (!reply.empty()) return candidate->fail(bad("invalid no-ack negotiation reply")); }
        std::string actions; status = candidate->rsp("vCont?", &actions, limit); if (!status.ok()) return status;
        if (!actions.empty()) {
            if (actions.compare(0, 5, "vCont") || (actions.size() > 5 && actions[5] != ';')) return candidate->fail(bad("invalid GDB vCont capability reply"));
            for (size_t start = 6; start < actions.size();) { const auto finish = actions.find(';', start); const auto action = actions.substr(start, finish == std::string::npos ? finish : finish - start); if (action.size() != 1 || std::string("cCsStr").find(action[0]) == std::string::npos) return candidate->fail(bad("invalid GDB vCont action")); if (action == "c") candidate->vContinue = true; if (action == "s") candidate->vStep = true; if (finish == std::string::npos) break; start = finish + 1; }
        }
        std::string reply; status = candidate->rsp("?", &reply, limit); if (!status.ok()) return status; status = candidate->stopReply(reply); if (!status.ok()) return status;
        candidate->state.supportsMemory = true; candidate->state.supportsInstructionBreakpoints = true; candidate->attached = true;
        if (options.registerLayout.empty()) candidate->state.notes.push_back("RSP target register layout not supplied: register file is returned raw in target byte order, without guessed names/widths.");
    } else {
        Json capabilities; status = candidate->dap("initialize", "{\"clientID\":\"mint\",\"adapterID\":\"lldb\",\"pathFormat\":\"path\",\"linesStartAt1\":true,\"columnsStartAt1\":true,\"supportsMemoryReferences\":true,\"supportsRunInTerminalRequest\":false,\"supportsStartDebuggingRequest\":false}", &capabilities, limit);
        if (!status.ok()) return status; if (capabilities.kind != Json::Object) return candidate->fail(bad("DAP initialize capabilities missing"));
        candidate->configurationDone = capabilities.flag("supportsConfigurationDoneRequest"); candidate->instructionStep = capabilities.flag("supportsSteppingGranularity");
        candidate->state.supportsMemory = capabilities.flag("supportsReadMemoryRequest"); candidate->state.supportsInstructionBreakpoints = capabilities.flag("supportsInstructionBreakpoints"); candidate->state.reason = "Adapter initialized; no process launched or attached";
    }
    impl_ = std::move(candidate); return Status::success();
}
Status DebuggerClient::attachProcess(u64 pid, const std::string& executable) {
    auto& p = *impl_; if (!p.transport || p.state.backend != DebuggerBackend::kLldbDap || p.attached) return unsupported("Explicit PID attach requires an initialized, unattached LLDB-DAP adapter");
    if (!pid || pid > INT_MAX || executable.size() > 4096 || executable.find('\0') != std::string::npos || !utf8(executable)) return bad("invalid explicit process ID/executable");
    const auto limit = p.deadline(); u32 id = 0; const auto args = "{\"pid\":" + std::to_string(pid) + ",\"stopOnEntry\":true" + (executable.empty() ? "" : ",\"program\":" + quote(executable)) + '}';
    auto status = p.dapSend("attach", args, &id, limit); if (!status.ok()) return status;
    for (unsigned events = 0; !p.initialized && events < 128; ++events) { status = p.dapMessage(limit); if (!status.ok()) return status; }
    if (!p.initialized) return p.fail(bad("DAP initialized event budget exceeded"));
    Json body;
    if (p.configurationDone) { status = p.dap("configurationDone", "{}", &body, limit); if (!status.ok()) return p.transport ? p.fail(status) : status; }
    status = p.dapWait(id, &body, limit); if (!status.ok()) return p.transport ? p.fail(status) : status; p.attached = true;
    if (p.state.state == DebuggerState::kConnected) p.state.reason = "Attached; awaiting a stopped event";
    return Status::success();
}
Status DebuggerClient::readMemory(Address address, size_t length, std::vector<u8>* out) {
    auto& p = *impl_; if (!out || !length || length > kMaxMemoryRead || length - 1 > ~u64(0) - address) return bad("invalid bounded memory read");
    auto status = p.stopped(); if (!status.ok()) return status; if (!p.state.supportsMemory) return unsupported("Adapter does not support memory reads");
    const auto limit = p.deadline(); const auto epoch = p.stoppedEpoch; std::vector<u8> candidate;
    if (p.state.backend == DebuggerBackend::kGdbRemote) {
        const size_t chunkSize = std::min(kMaxMemoryRead, (p.packetSize - 32) / 2);
        while (candidate.size() < length) { const auto count = std::min(chunkSize, length - candidate.size()); std::string reply; status = p.rsp("m" + hex(address + candidate.size()) + ',' + hex(count), &reply, limit); if (!status.ok()) return status; if (reply.empty()) return unsupported("GDB memory read unsupported"); std::vector<u8> chunk; if (!bytesFromHex(reply, &chunk) || chunk.size() != count) return p.fail(bad("GDB memory length/encoding mismatch")); candidate.insert(candidate.end(), chunk.begin(), chunk.end()); }
    }
    else { Json body; status = p.dap("readMemory", "{\"memoryReference\":" + quote("0x" + hex(address)) + ",\"count\":" + std::to_string(length) + '}', &body, limit); if (!status.ok()) return status;
        Address returned = 0; u64 unreadable = 0;
        if (!addressValue(body.string("address"), &returned) || returned != address || (body.get("unreadableBytes") && !body.uint("unreadableBytes", &unreadable)) || !base64(body.string("data"), &candidate)) return p.fail(bad("DAP memory address/base64 mismatch"));
        if (unreadable || candidate.size() < length) return unsupported("Requested memory range is not fully readable"); if (candidate.size() != length) return p.fail(bad("DAP memory exceeds requested count"));
    }
    if (p.state.state != DebuggerState::kStopped || p.stoppedEpoch != epoch) return unsupported("Target state changed during memory read; result discarded");
    *out = std::move(candidate); return Status::success();
}
Status DebuggerClient::readRegisters(std::vector<DebuggerRegister>* out) {
    auto& p = *impl_; if (!out) return bad("null register output"); auto status = p.stopped(); if (!status.ok()) return status;
    const auto limit = p.deadline(); const auto epoch = p.stoppedEpoch; std::vector<DebuggerRegister> candidate;
    if (p.state.backend == DebuggerBackend::kGdbRemote) {
        std::string reply;
        if (p.state.threadId) { status = p.rsp("Hg" + hex(p.state.threadId), &reply, limit); if (!status.ok()) return status; if (reply.empty()) return unsupported("GDB stub cannot select the stopped register thread"); if (reply != "OK") return p.fail(bad("invalid GDB thread-selection response")); }
        status = p.rsp("g", &reply, limit); if (!status.ok()) return status; if (reply.empty()) return unsupported("GDB register read unsupported");
        if (p.options.registerLayout.empty()) { DebuggerRegister reg; reg.name = "raw-register-file (target order; layout unknown)"; reg.value = reply; if (!bytesFromHex(reply, &reg.bytes, true, &reg.available)) return p.fail(bad("invalid GDB register encoding")); candidate.push_back(std::move(reg)); }
        else { size_t position = 0; for (const auto& spec : p.options.registerLayout) { const auto count = spec.bits / 4; if (position > reply.size() || count > reply.size() - position) return p.fail(bad("GDB register layout length mismatch")); DebuggerRegister reg; reg.name = spec.name; reg.number = spec.number; reg.value = reply.substr(position, count); if (!bytesFromHex(reg.value, &reg.bytes, true, &reg.available)) return p.fail(bad("invalid GDB register bytes")); position += count; candidate.push_back(std::move(reg)); } if (position != reply.size()) return p.fail(bad("GDB extra register bytes outside exact layout")); }
    } else {
        status = p.thread(limit); if (!status.ok()) return status; Json body;
        status = p.dap("stackTrace", "{\"threadId\":" + std::to_string(p.state.threadId) + ",\"startFrame\":0,\"levels\":1}", &body, limit); if (!status.ok()) return status;
        const auto* frames = body.get("stackFrames"); u64 frame = 0;
        if (!frames || frames->kind != Json::Array || frames->array.size() != 1 || !frames->array[0].uint("id", &frame) || frame > INT_MAX) return p.fail(bad("DAP top stack frame missing"));
        status = p.dap("scopes", "{\"frameId\":" + std::to_string(frame) + '}', &body, limit); if (!status.ok()) return status;
        const auto* scopes = body.get("scopes"); if (!scopes || scopes->kind != Json::Array || scopes->array.size() > 128) return p.fail(bad("invalid DAP scopes"));
        std::vector<std::pair<u64, unsigned>> pending; std::set<u64> visited;
        for (const auto& scope : scopes->array) if (scope.string("presentationHint") == "registers" || scope.string("name") == "Registers") { u64 ref = 0; if (!scope.uint("variablesReference", &ref) || !ref || ref > INT_MAX) return p.fail(bad("invalid DAP register scope reference")); pending.emplace_back(ref, 0); }
        if (pending.empty()) return unsupported("DAP adapter exposes no register scope");
        for (size_t index = 0; index < pending.size(); ++index) {
            const auto ref = pending[index].first; const auto depth = pending[index].second; if (index >= 16 || depth > 4 || !visited.insert(ref).second) return p.fail(bad("DAP register hierarchy budget/cycle"));
            status = p.dap("variables", "{\"variablesReference\":" + std::to_string(ref) + '}', &body, limit); if (!status.ok()) return status;
            const auto* vars = body.get("variables"); if (!vars || vars->kind != Json::Array || vars->array.size() > 1024) return p.fail(bad("invalid DAP registers array"));
            for (const auto& item : vars->array) {
                u64 child = 0; if (item.get("variablesReference") && (!item.uint("variablesReference", &child) || child > INT_MAX)) return p.fail(bad("invalid DAP register child"));
                if (child) { pending.emplace_back(child, depth + 1); if (pending.size() > 16) return p.fail(bad("DAP register scope budget exceeded")); continue; }
                const auto* value = item.get("value"); const auto name = item.string("name"); if (name.empty() || !value || value->kind != Json::String || candidate.size() >= 1024) return p.fail(bad("invalid/oversized DAP register value"));
                DebuggerRegister reg; reg.name = safeText(name); reg.value = safeText(value->text); reg.number = static_cast<u32>(candidate.size()); candidate.push_back(std::move(reg));
            }
        }
    }
    if (p.state.state != DebuggerState::kStopped || p.stoppedEpoch != epoch) return unsupported("Target state changed during register read; result discarded");
    *out = std::move(candidate); return Status::success();
}
Status DebuggerClient::threads(std::vector<DebuggerThread>* out){
    auto& p=*impl_;if(!out)return bad("missing thread output");auto status=p.stopped();if(!status.ok())return status;
    const auto limit=p.deadline(),epoch=p.stoppedEpoch;std::vector<DebuggerThread> candidate;std::set<u64> seen;
    if(p.state.backend==DebuggerBackend::kLldbDap){Json body;status=p.dap("threads","{}",&body,limit);if(!status.ok())return status;const auto* values=body.get("threads");if(!values||values->kind!=Json::Array||values->array.size()>4096)return p.fail(bad("invalid DAP thread inventory"));for(const auto& value:values->array){u64 id=0;if(!value.uint("id",&id)||!id||id>INT_MAX||!seen.insert(id).second)return p.fail(bad("invalid/duplicate DAP thread ID"));candidate.push_back({id,safeText(value.string("name")),id==p.state.threadId});}}
    else {std::string reply;for(unsigned page=0;page<64;++page){status=p.rsp(page?"qsThreadInfo":"qfThreadInfo",&reply,limit);if(!status.ok())return status;if(reply=="l")break;if(reply.empty())return unsupported("RSP thread inventory unavailable");if(reply[0]!='m')return p.fail(bad("invalid RSP thread inventory"));size_t at=1;while(at<reply.size()){const auto end=reply.find(',',at);u64 id=0;if(!integer(reply.substr(at,end==std::string::npos?std::string::npos:end-at),16,&id)||!id||!seen.insert(id).second||candidate.size()>=4096)return p.fail(bad("invalid/oversized RSP thread ID"));candidate.push_back({id,"thread 0x"+hex(id),id==p.state.threadId});if(end==std::string::npos)break;at=end+1;}if(page==63)return p.fail(bad("RSP thread inventory page limit"));}}
    if(p.state.state!=DebuggerState::kStopped||p.stoppedEpoch!=epoch)return unsupported("Target changed during thread inventory");*out=std::move(candidate);return Status::success();
}
Status DebuggerClient::selectThread(u64 id){
    auto& p=*impl_;if(!id)return bad("thread ID must be positive");std::vector<DebuggerThread> inventory;auto status=threads(&inventory);if(!status.ok())return status;if(std::none_of(inventory.begin(),inventory.end(),[&](const DebuggerThread& thread){return thread.id==id;}))return unsupported("Thread no longer exists in current inventory");
    if(p.state.backend==DebuggerBackend::kGdbRemote){std::string reply;status=p.rsp("Hg"+hex(id),&reply,p.deadline());if(!status.ok())return status;if(reply!="OK")return unsupported("RSP server cannot select that thread");}
    p.state.threadId=id;return Status::success();
}
Status DebuggerClient::stackFrames(size_t maximum,std::vector<DebuggerFrame>* out){
    auto& p=*impl_;if(!out||!maximum||maximum>256)return bad("stack frame limit must be 1..256");auto status=p.stopped();if(!status.ok())return status;if(p.state.backend!=DebuggerBackend::kLldbDap)return unsupported("RSP does not expose a portable stackTrace; use a DAP adapter for unwind-backed frames");
    const auto limit=p.deadline(),epoch=p.stoppedEpoch;status=p.thread(limit);if(!status.ok())return status;Json body;status=p.dap("stackTrace","{\"threadId\":"+std::to_string(p.state.threadId)+",\"startFrame\":0,\"levels\":"+std::to_string(maximum)+"}",&body,limit);if(!status.ok())return status;
    const auto* frames=body.get("stackFrames");if(!frames||frames->kind!=Json::Array||frames->array.size()>maximum)return p.fail(bad("invalid DAP stack frames"));std::vector<DebuggerFrame> candidate;std::set<u64> ids;
    for(const auto& value:frames->array){DebuggerFrame frame;if(!value.uint("id",&frame.id)||frame.id>INT_MAX||!ids.insert(frame.id).second)return p.fail(bad("invalid DAP stack frame ID"));frame.name=safeText(value.string("name"));const auto address=value.string("instructionPointerReference");if(!address.empty()&&!addressValue(address,&frame.pc))return p.fail(bad("invalid DAP stack instruction address"));const auto* source=value.get("source");if(source&&source->kind==Json::Object)frame.source=safeText(source->string("path"));if(value.get("line")&&!value.uint("line",&frame.line))return p.fail(bad("invalid DAP stack source line"));candidate.push_back(std::move(frame));}
    if(p.state.state!=DebuggerState::kStopped||p.stoppedEpoch!=epoch)return unsupported("Target changed during stack read");*out=std::move(candidate);return Status::success();
}
Status DebuggerClient::modules(std::vector<DebuggerModule>* out){
    auto& p=*impl_;if(!out)return bad("missing module output");auto status=p.stopped();if(!status.ok())return status;if(p.state.backend!=DebuggerBackend::kLldbDap)return unsupported("RSP module inventory is target-specific; configure explicit image mappings or use DAP modules");
    const auto epoch=p.stoppedEpoch;Json body;status=p.dap("modules","{\"startModule\":0,\"moduleCount\":4096}",&body,p.deadline());if(!status.ok())return status;const auto* values=body.get("modules");if(!values||values->kind!=Json::Array||values->array.size()>4096)return p.fail(bad("invalid DAP module inventory"));std::vector<DebuggerModule> candidate;
    for(const auto& value:values->array){DebuggerModule module;const auto* id=value.get("id");if(!id||(id->kind!=Json::Number&&id->kind!=Json::String))return p.fail(bad("invalid DAP module ID"));module.id=safeText(id->text);module.name=safeText(value.string("name"));module.path=safeText(value.string("path"));const auto range=value.string("addressRange");if(!range.empty()){const auto dash=range.find('-');if(dash==std::string::npos||!addressValue(range.substr(0,dash),&module.start)||!addressValue(range.substr(dash+1),&module.end)||module.end<module.start)return p.fail(bad("invalid DAP module address range"));}candidate.push_back(std::move(module));}
    if(p.state.state!=DebuggerState::kStopped||p.stoppedEpoch!=epoch)return unsupported("Target changed during module inventory");*out=std::move(candidate);return Status::success();
}
Status DebuggerClient::programCounter(Address* out){
    if(!out)return bad("missing PC output");if(impl_->state.backend==DebuggerBackend::kLldbDap){std::vector<DebuggerFrame> frames;auto status=stackFrames(1,&frames);if(!status.ok())return status;if(frames.empty()||frames[0].pc==kNoAddress)return unsupported("DAP adapter did not report an instruction address");*out=frames[0].pc;return Status::success();}
    std::vector<DebuggerRegister> registers;auto status=readRegisters(&registers);if(!status.ok())return status;
    for(const auto& reg:registers)if(reg.name=="pc"||reg.name=="rip"||reg.name=="eip"){if(!reg.available||reg.bytes.empty()||reg.bytes.size()>8)return unsupported("PC unavailable or wider than supported address width");Address pc=0;for(size_t i=0;i<reg.bytes.size();++i)pc|=Address(reg.bytes[i])<<(8*i);*out=pc;return Status::success();}return unsupported("RSP PC needs an exact little-endian target register layout");
}
Status DebuggerClient::discoverRegisterLayout(){
    auto& p=*impl_;auto status=p.stopped();if(!status.ok())return status;if(p.state.backend!=DebuggerBackend::kGdbRemote)return unsupported("RSP target XML only");const auto limit=p.deadline();std::string xml,reply;size_t totalXml=0;std::set<std::string> visited;
    std::function<Status(const std::string&,unsigned,std::string*)> fetch=[&](const std::string& file,unsigned depth,std::string* output)->Status{
        if(depth>8||visited.size()>=16||!visited.insert(file).second||file.empty()||file.size()>128||file[0]=='/'||file.find("..")!=std::string::npos||file.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/")!=std::string::npos)return unsupported("Target XML include path/cycle/depth budget exceeded");std::string document;
        for(size_t page=0;page<64;++page){auto fetched=p.rsp("qXfer:features:read:"+file+":"+hex(document.size())+",400",&reply,limit);if(!fetched.ok())return fetched;if(reply.empty())return unsupported("Server does not expose requested target feature XML");if((reply[0]!='m'&&reply[0]!='l')||reply.size()==1||reply.size()-1>65536-totalXml)return p.fail(bad("invalid/oversized RSP target XML"));document+=reply.substr(1);totalXml+=reply.size()-1;if(reply[0]=='l')break;if(page==63)return unsupported("Target XML page budget exceeded");}
        // This is a tag reader, not an entity-capable XML engine. DTD hints are
        // inert; entity declarations/references are explicitly refused.
        if(document.find("<!ENTITY")!=std::string::npos||document.find('&')!=std::string::npos)return unsupported("Target XML entity expansion is unsupported");
        for(size_t at=0;(at=document.find("<xi:include",at))!=std::string::npos;){const auto end=document.find('>',at),href=document.find("href",at);if(end==std::string::npos||href==std::string::npos||href>end)return p.fail(bad("malformed target XML include"));size_t cursor=href+4;while(cursor<end&&std::isspace(static_cast<unsigned char>(document[cursor])))++cursor;if(cursor==end||document[cursor++]!='=')return p.fail(bad("malformed target XML include href"));while(cursor<end&&std::isspace(static_cast<unsigned char>(document[cursor])))++cursor;if(cursor==end||(document[cursor]!='\''&&document[cursor]!='\"'))return p.fail(bad("target XML href must be quoted"));const char marker=document[cursor++];const auto finish=document.find(marker,cursor);if(finish==std::string::npos||finish>end)return p.fail(bad("unterminated target XML href"));std::string included;auto fetched=fetch(document.substr(cursor,finish-cursor),depth+1,&included);if(!fetched.ok())return fetched;document.replace(at,end-at+1,included);at+=included.size();}
        *output=std::move(document);return Status::success();
    };
    status=fetch("target.xml",0,&xml);if(!status.ok())return status;
    std::vector<DebuggerRegisterSpec> layout;std::set<u32> numbers;std::set<std::string> names;u64 next=0;size_t bytes=0;
    for(size_t at=0;(at=xml.find("<reg",at))!=std::string::npos;){if(at+4<xml.size()&&xml[at+4]!=' '&&xml[at+4]!='\t'&&xml[at+4]!='\r'&&xml[at+4]!='\n'){at+=4;continue;}const auto end=xml.find('>',at);if(end==std::string::npos)return p.fail(bad("unterminated XML register tag"));std::map<std::string,std::string> attrs;size_t cursor=at+4;while(cursor<end){while(cursor<end&&(std::isspace(static_cast<unsigned char>(xml[cursor]))||xml[cursor]=='/'))++cursor;if(cursor==end)break;const auto start=cursor;while(cursor<end&&(std::isalnum(static_cast<unsigned char>(xml[cursor]))||xml[cursor]=='_'||xml[cursor]=='-'))++cursor;const auto key=xml.substr(start,cursor-start);while(cursor<end&&std::isspace(static_cast<unsigned char>(xml[cursor])))++cursor;if(key.empty()||cursor==end||xml[cursor++]!='=')return p.fail(bad("invalid XML register attribute"));while(cursor<end&&std::isspace(static_cast<unsigned char>(xml[cursor])))++cursor;if(cursor==end||(xml[cursor]!='\''&&xml[cursor]!='\"'))return p.fail(bad("XML attribute must be quoted"));const char quoteChar=xml[cursor++];const auto finish=xml.find(quoteChar,cursor);if(finish==std::string::npos||finish>end||!attrs.emplace(key,xml.substr(cursor,finish-cursor)).second)return p.fail(bad("invalid duplicate XML attribute"));cursor=finish+1;}
        u64 bits=0,id=next;if(!integer(attrs["bitsize"],10,&bits)||!bits||bits%8||bits>4096||(!attrs["regnum"].empty()&&!integer(attrs["regnum"],10,&id))||id>UINT_MAX||attrs["name"].empty()||attrs["name"].size()>128||!names.insert(attrs["name"]).second||!numbers.insert(static_cast<u32>(id)).second||layout.size()>=1024||bits/8>kMaxRsp/2-bytes)return p.fail(bad("invalid XML register metadata"));
        // The g-packet is register-number order. Gaps are not guessed.
        if(id!=layout.size())return unsupported("Non-contiguous XML register numbers need an explicit exact packet layout");layout.push_back({attrs["name"],static_cast<u32>(id),static_cast<u32>(bits)});bytes+=bits/8;next=id+1;at=end+1;
    }if(layout.empty())return unsupported("Target XML contains no flattened register definitions");p.options.registerLayout=std::move(layout);return Status::success();
}
Status DebuggerClient::setImageMappings(const std::vector<DebuggerImageMapping>& mappings){
    if(mappings.size()>4096)return bad("image mapping limit exceeded");for(size_t i=0;i<mappings.size();++i){const auto& a=mappings[i];if(!a.size||a.imageStart>kNoAddress-a.size||a.runtimeStart>kNoAddress-a.size||a.module.size()>4096)return bad("invalid image mapping extent");for(size_t j=0;j<i;++j){const auto& b=mappings[j];if((a.imageStart<b.imageStart+b.size&&b.imageStart<a.imageStart+a.size)||(a.runtimeStart<b.runtimeStart+b.size&&b.runtimeStart<a.runtimeStart+a.size))return bad("ambiguous overlapping image mapping");}}impl_->mappings=mappings;return Status::success();
}
Status DebuggerClient::imageToRuntime(Address image,Address* runtime)const{if(!runtime)return bad("missing runtime address output");for(const auto& mapping:impl_->mappings)if(image>=mapping.imageStart&&image-mapping.imageStart<mapping.size){*runtime=mapping.runtimeStart+(image-mapping.imageStart);return Status::success();}return unsupported("Image address has no confirmed runtime mapping");}
Status DebuggerClient::runtimeToImage(Address runtime,Address* image)const{if(!image)return bad("missing image address output");for(const auto& mapping:impl_->mappings)if(runtime>=mapping.runtimeStart&&runtime-mapping.runtimeStart<mapping.size){*image=mapping.imageStart+(runtime-mapping.runtimeStart);return Status::success();}return unsupported("Runtime address has no confirmed Program mapping");}
Status DebuggerClient::setBreakpoint(Address address, bool enabled, u32 instructionSize) {
    auto& p = *impl_; auto status = p.stopped(); if (!status.ok()) return status;
    if (!instructionSize || instructionSize > 16) return bad("breakpoint instruction kind must be 1..16 bytes");
    if (!p.state.supportsInstructionBreakpoints) return unsupported("Adapter does not support instruction breakpoints");
    const auto limit = p.deadline();
    if (p.state.backend == DebuggerBackend::kGdbRemote) { if (enabled && !p.breakpoints.count(address) && p.breakpoints.size() >= 256) return unsupported("Instruction breakpoint limit is 256"); std::string reply; status = p.rsp(std::string(enabled ? "Z0," : "z0,") + hex(address) + ',' + hex(instructionSize), &reply, limit); if (!status.ok()) return status; if (reply.empty()) return unsupported("GDB software breakpoints unsupported"); if (reply != "OK") return p.fail(bad("GDB breakpoint acknowledgement invalid")); if (enabled) p.breakpoints.insert(address); else p.breakpoints.erase(address); }
    else {
        auto candidate = p.breakpoints; if (enabled) candidate.insert(address); else candidate.erase(address); if (candidate.size() > 256) return unsupported("Instruction breakpoint limit is 256");
        std::string args = "{\"breakpoints\":["; for (auto value : candidate) { if (args.back() != '[') args += ','; args += "{\"instructionReference\":" + quote("0x" + hex(value)) + '}'; } args += "]}";
        Json body; status = p.dap("setInstructionBreakpoints", args, &body, limit); if (!status.ok()) return status; const auto* values = body.get("breakpoints");
        if (!values || values->kind != Json::Array || values->array.size() != candidate.size()) return p.fail(bad("DAP breakpoint response length mismatch"));
        for (const auto& value : values->array) if (!value.flag("verified")) return unsupported("Adapter did not verify all requested instruction breakpoints; remote breakpoint state may be partial");
        p.breakpoints = std::move(candidate);
    }
    return Status::success();
}
Status DebuggerClient::step() {
    auto& p = *impl_; auto status = p.stopped(); if (!status.ok()) return status; const auto limit = p.deadline(); const auto epoch = p.stoppedEpoch;
    if (p.state.backend == DebuggerBackend::kGdbRemote) {
        if (!p.vStep && p.state.threadId) { std::string reply; status = p.rsp("Hc" + hex(p.state.threadId), &reply, limit); if (!status.ok()) return status; if (reply.empty()) return unsupported("GDB stub cannot select the stopped stepping thread"); if (reply != "OK") return p.fail(bad("invalid GDB continue-thread response")); }
        status = p.rspSend(p.vStep ? "vCont;s" + (p.state.threadId ? ':' + hex(p.state.threadId) : "") : "s", limit);
    }
    else { if (!p.instructionStep) return unsupported("Adapter lacks instruction stepping granularity"); status = p.thread(limit); if (!status.ok()) return status; Json body; status = p.dap("stepIn", "{\"threadId\":" + std::to_string(p.state.threadId) + ",\"granularity\":\"instruction\"}", &body, limit); }
    if (status.ok() && (!p.attached || p.state.state == DebuggerState::kExited)) return unsupported("Target session ended while stepping");
    if (status.ok() && p.stoppedEpoch == epoch) { p.state.state = DebuggerState::kRunning; p.state.reason = "Instruction step requested; await stopped event"; } return status;
}
Status DebuggerClient::resume() {
    auto& p = *impl_; auto status = p.stopped(); if (!status.ok()) return status; const auto limit = p.deadline(); const auto epoch = p.stoppedEpoch;
    if (p.state.backend == DebuggerBackend::kGdbRemote) status = p.rspSend(p.vContinue ? "vCont;c" : "c", limit);
    else { status = p.thread(limit); if (!status.ok()) return status; Json body; status = p.dap("continue", "{\"threadId\":" + std::to_string(p.state.threadId) + '}', &body, limit); }
    if (status.ok() && (!p.attached || p.state.state == DebuggerState::kExited)) return unsupported("Target session ended while continuing");
    if (status.ok() && p.stoppedEpoch == epoch) { p.state.state = DebuggerState::kRunning; p.state.reason = "Target running"; } return status;
}
Status DebuggerClient::interrupt() {
    auto& p = *impl_; if (!p.transport || p.state.state != DebuggerState::kRunning) return unsupported("Interrupt requires a connected running target"); const auto limit = p.deadline();
    if (p.state.backend == DebuggerBackend::kGdbRemote) return p.write(std::string(1, '\x03'), limit);
    auto status = p.thread(limit); if (!status.ok()) return status; Json body; return p.dap("pause", "{\"threadId\":" + std::to_string(p.state.threadId) + '}', &body, limit);
}
Status DebuggerClient::waitForStop() {
    auto& p = *impl_; if (!p.transport) return unsupported("No debugger connection"); if (p.state.state == DebuggerState::kStopped || p.state.state == DebuggerState::kExited) return Status::success();
    if (!p.attached || (p.state.state != DebuggerState::kRunning && p.state.state != DebuggerState::kConnected)) return unsupported("No attached target to await"); const auto limit = p.deadline();
    if (p.state.backend == DebuggerBackend::kGdbRemote) { std::string reply; auto status = p.rspReceive(&reply, limit); return status.ok() ? p.stopReply(reply) : status; }
    for (unsigned events = 0; events < 128; ++events) { auto status = p.dapMessage(limit); if (!status.ok()) return status; if (p.state.state == DebuggerState::kStopped || p.state.state == DebuggerState::kExited) return Status::success(); if (!p.attached) return unsupported("Debug session terminated before target stop"); }
    return p.fail(bad("DAP stopped-event budget exceeded"));
}
std::string debuggerSnapshotText(const DebuggerSnapshot& snapshot) {
    const char* names[] = {"disconnected", "connected", "stopped", "running", "exited"}; const auto index = static_cast<unsigned>(snapshot.state);
    std::ostringstream out; out << (snapshot.backend == DebuggerBackend::kGdbRemote ? "GDB Remote" : "LLDB-DAP") << ": " << (index < 5 ? names[index] : "unknown") << '\n';
    if (snapshot.threadId) out << "thread " << snapshot.threadId << '\n'; if (!snapshot.reason.empty()) out << snapshot.reason << '\n';
    for (const auto& note : snapshot.notes) out << "note: " << note << '\n'; return out.str();
}
}  // namespace mint
