#include "mint/db/database.h"

#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <dlfcn.h>

namespace mint {
namespace {

struct sqlite3;
struct sqlite3_stmt;
using Destructor = void (*)(void*);

/// Keep SQLite out of the shipped link interface. Android exposes it from the
/// system runtime, while desktop tests use libsqlite3.dylib/libsqlite3.so.
struct SqliteApi {
    void* library = nullptr;
    bool attempted = false;
    int (*open)(const char*, sqlite3**) = nullptr;
    int (*close)(sqlite3*) = nullptr;
    int (*exec)(sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**) = nullptr;
    const char* (*errmsg)(sqlite3*) = nullptr;
    int (*prepare)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = nullptr;
    int (*bindInt64)(sqlite3_stmt*, int, std::int64_t) = nullptr;
    int (*bindText)(sqlite3_stmt*, int, const char*, int, Destructor) = nullptr;
    int (*step)(sqlite3_stmt*) = nullptr;
    int (*finalize)(sqlite3_stmt*) = nullptr;
    int (*reset)(sqlite3_stmt*) = nullptr;
    int (*clearBindings)(sqlite3_stmt*) = nullptr;
    std::int64_t (*columnInt64)(sqlite3_stmt*, int) = nullptr;
    const unsigned char* (*columnText)(sqlite3_stmt*, int) = nullptr;
    std::int64_t (*lastInsertRowid)(sqlite3*) = nullptr;

    bool load() {
        if (attempted) return library != nullptr;
        attempted = true;
#if defined(__ANDROID__)
        const char* names[] = {"libsqlite.so", "libsqlite.so.0"};
#else
        const char* names[] = {"libsqlite3.dylib", "libsqlite3.so", "libsqlite3.so.0"};
#endif
        for (const char* name : names) { library = dlopen(name, RTLD_NOW | RTLD_LOCAL); if (library) break; }
        if (!library) return false;
#define MINT_SQLITE_LOAD(field, symbol) field = reinterpret_cast<decltype(field)>(dlsym(library, symbol))
        MINT_SQLITE_LOAD(open, "sqlite3_open"); MINT_SQLITE_LOAD(close, "sqlite3_close"); MINT_SQLITE_LOAD(exec, "sqlite3_exec");
        MINT_SQLITE_LOAD(errmsg, "sqlite3_errmsg"); MINT_SQLITE_LOAD(prepare, "sqlite3_prepare_v2"); MINT_SQLITE_LOAD(bindInt64, "sqlite3_bind_int64");
        MINT_SQLITE_LOAD(bindText, "sqlite3_bind_text"); MINT_SQLITE_LOAD(step, "sqlite3_step"); MINT_SQLITE_LOAD(finalize, "sqlite3_finalize"); MINT_SQLITE_LOAD(reset, "sqlite3_reset"); MINT_SQLITE_LOAD(clearBindings, "sqlite3_clear_bindings");
        MINT_SQLITE_LOAD(columnInt64, "sqlite3_column_int64"); MINT_SQLITE_LOAD(columnText, "sqlite3_column_text"); MINT_SQLITE_LOAD(lastInsertRowid, "sqlite3_last_insert_rowid");
#undef MINT_SQLITE_LOAD
        return open && close && exec && errmsg && prepare && bindInt64 && bindText && step && finalize && reset && clearBindings && columnInt64 && columnText && lastInsertRowid;
    }
};

SqliteApi& api() { static SqliteApi value; value.load(); return value; }
constexpr int kOk = 0;
constexpr int kRow = 100;
constexpr int kDone = 101;
constexpr intptr_t kTransient = -1;

Status dbError(const SqliteApi& sqlite, sqlite3* db, const char* context) {
    return Status::error(ErrorCode::kIoError, std::string(context) + ": " + (db && sqlite.errmsg ? sqlite.errmsg(db) : "sqlite unavailable"));
}

}  // namespace

Database::~Database() { close(); }

Status Database::open(const std::string& path) {
    close(); SqliteApi& sqlite = api(); if (!sqlite.open) return Status::error(ErrorCode::kUnsupported, "system SQLite is unavailable");
    sqlite3* db = nullptr;
    if (sqlite.open(path.c_str(), &db) != kOk) { if (db) sqlite.close(db); return dbError(sqlite, db, "sqlite open"); }
    handle_ = db; return ensureSchema();
}

void Database::close() { SqliteApi& sqlite = api(); if (handle_ && sqlite.close) { sqlite.close(static_cast<sqlite3*>(handle_)); handle_ = nullptr; } }

Status Database::execute(const std::string& sql) {
    SqliteApi& sqlite = api(); if (!handle_ || !sqlite.exec) return Status::error(ErrorCode::kInternalError, "database is not open");
    char* error = nullptr; const int code = sqlite.exec(static_cast<sqlite3*>(handle_), sql.c_str(), nullptr, nullptr, &error);
    if (code == kOk) return Status::success(); return dbError(sqlite, static_cast<sqlite3*>(handle_), error ? error : "sqlite exec");
}

Status Database::ensureSchema() {
    return execute("PRAGMA user_version=1; PRAGMA foreign_keys=ON;"
                   "CREATE TABLE IF NOT EXISTS binaries(hash TEXT PRIMARY KEY, path TEXT, analyzed_at INTEGER);"
                   "CREATE TABLE IF NOT EXISTS functions(id INTEGER PRIMARY KEY, entry INTEGER NOT NULL, name TEXT, size INTEGER, binary_hash TEXT);"
                   "CREATE TABLE IF NOT EXISTS instructions(id INTEGER PRIMARY KEY, function_id INTEGER, address INTEGER, op TEXT);"
                   "CREATE TABLE IF NOT EXISTS blocks(id INTEGER PRIMARY KEY, function_id INTEGER, block_index INTEGER, start INTEGER, end INTEGER);"
                   "CREATE TABLE IF NOT EXISTS calls(caller_id INTEGER, target INTEGER, UNIQUE(caller_id,target));"
                   "CREATE INDEX IF NOT EXISTS functions_entry ON functions(entry);"
                   "CREATE UNIQUE INDEX IF NOT EXISTS functions_entry_unique ON functions(entry);"
                   "CREATE INDEX IF NOT EXISTS calls_target ON calls(target);");
}

Status Database::persist(const IrFunction& function, const std::string& binaryHash) {
    SqliteApi& sqlite = api(); if (!handle_ || !sqlite.prepare) return Status::error(ErrorCode::kInternalError, "database is not open");
    Status transaction = execute("BEGIN IMMEDIATE;"); if (!transaction.ok()) return transaction;
    sqlite3_stmt* statement = nullptr;
    if (sqlite.prepare(static_cast<sqlite3*>(handle_), "INSERT OR REPLACE INTO functions(entry,name,size,binary_hash) VALUES(?,?,?,?)", -1, &statement, nullptr) != kOk) { execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "prepare function"); }
    sqlite.bindInt64(statement, 1, static_cast<std::int64_t>(function.entry)); sqlite.bindText(statement, 2, function.name.c_str(), -1, reinterpret_cast<Destructor>(kTransient)); sqlite.bindInt64(statement, 3, static_cast<std::int64_t>(function.insns.size())); sqlite.bindText(statement, 4, binaryHash.c_str(), -1, reinterpret_cast<Destructor>(kTransient));
    if (sqlite.step(statement) != kDone) { sqlite.finalize(statement); execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "insert function"); }
    sqlite.finalize(statement); const std::int64_t functionId = sqlite.lastInsertRowid(static_cast<sqlite3*>(handle_));
    auto prepare = [&](const char* sql) -> sqlite3_stmt* { sqlite3_stmt* result = nullptr; return sqlite.prepare(static_cast<sqlite3*>(handle_), sql, -1, &result, nullptr) == kOk ? result : nullptr; };
    statement = prepare("INSERT INTO instructions(function_id,address,op) VALUES(?,?,?)");
    if (!statement) { execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "prepare instructions"); }
    for (const IrInsn& insn : function.insns) { sqlite.bindInt64(statement, 1, functionId); sqlite.bindInt64(statement, 2, static_cast<std::int64_t>(insn.address)); sqlite.bindText(statement, 3, opName(insn.op), -1, reinterpret_cast<Destructor>(kTransient)); if (sqlite.step(statement) != kDone) { sqlite.finalize(statement); execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "insert instruction"); } sqlite.reset(statement); sqlite.clearBindings(statement); }
    sqlite.finalize(statement);
    statement = prepare("INSERT INTO blocks(function_id,block_index,start,end) VALUES(?,?,?,?)");
    if (!statement) { execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "prepare blocks"); }
    for (const IrBlock& block : function.blocks) { sqlite.bindInt64(statement, 1, functionId); sqlite.bindInt64(statement, 2, block.id); sqlite.bindInt64(statement, 3, static_cast<std::int64_t>(block.start)); sqlite.bindInt64(statement, 4, static_cast<std::int64_t>(block.end)); if (sqlite.step(statement) != kDone) { sqlite.finalize(statement); execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "insert block"); } sqlite.reset(statement); sqlite.clearBindings(statement); }
    sqlite.finalize(statement);
    statement = prepare("INSERT OR IGNORE INTO calls(caller_id,target) VALUES(?,?)");
    if (!statement) { execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "prepare calls"); }
    for (const IrInsn& insn : function.insns) if ((insn.op == MintOp::kCall || insn.op == MintOp::kCallInd) && insn.a.isConstant()) { sqlite.bindInt64(statement, 1, functionId); sqlite.bindInt64(statement, 2, static_cast<std::int64_t>(insn.a.offset)); if (sqlite.step(statement) != kDone) { sqlite.finalize(statement); execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "insert call"); } sqlite.reset(statement); sqlite.clearBindings(statement); }
    sqlite.finalize(statement);
    if (!binaryHash.empty()) { statement = prepare("INSERT OR REPLACE INTO binaries(hash,path,analyzed_at) VALUES(?,?,strftime('%s','now'))"); if (!statement) { execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "prepare binary"); } sqlite.bindText(statement, 1, binaryHash.c_str(), -1, reinterpret_cast<Destructor>(kTransient)); sqlite.bindText(statement, 2, "", -1, reinterpret_cast<Destructor>(kTransient)); if (sqlite.step(statement) != kDone) { sqlite.finalize(statement); execute("ROLLBACK;"); return dbError(sqlite, static_cast<sqlite3*>(handle_), "insert binary"); } sqlite.finalize(statement); }
    return execute("COMMIT;");
}

Status Database::functionsCalling(const std::string& target, std::vector<DbFunction>* out) const {
    if (!out) return Status::error(ErrorCode::kInternalError, "null database query output"); out->clear(); SqliteApi& sqlite = api();
    if (!handle_ || !sqlite.prepare) return Status::error(ErrorCode::kInternalError, "database is not open");
    errno = 0;
    char* end = nullptr;
    const unsigned long long numericTarget = std::strtoull(target.c_str(), &end, 0);
    if (target.empty() || end == target.c_str() || *end != '\0' || errno == ERANGE) {
        return Status::error(ErrorCode::kBadFormat,
                             "call target must be a numeric address");
    }
    sqlite3_stmt* statement = nullptr; const char* sql = "SELECT f.id,f.entry,f.name,f.size FROM functions f JOIN calls c ON c.caller_id=f.id WHERE c.target=?";
    if (sqlite.prepare(static_cast<sqlite3*>(handle_), sql, -1, &statement, nullptr) != kOk) return dbError(sqlite, static_cast<sqlite3*>(handle_), "prepare query");
    sqlite.bindInt64(statement, 1, static_cast<std::int64_t>(numericTarget)); int code = 0;
    while ((code = sqlite.step(statement)) == kRow) { DbFunction row; row.id = sqlite.columnInt64(statement, 0); row.entry = static_cast<Address>(sqlite.columnInt64(statement, 1)); const unsigned char* name = sqlite.columnText(statement, 2); row.name = name ? reinterpret_cast<const char*>(name) : ""; row.size = static_cast<u32>(sqlite.columnInt64(statement, 3)); out->push_back(std::move(row)); }
    sqlite.finalize(statement); return code == kDone ? Status::success() : dbError(sqlite, static_cast<sqlite3*>(handle_), "query functions");
}

bool Database::hasBinary(const std::string& binaryHash) const {
    SqliteApi& sqlite = api(); if (!handle_ || !sqlite.prepare) return false; sqlite3_stmt* statement = nullptr;
    if (sqlite.prepare(static_cast<sqlite3*>(handle_), "SELECT 1 FROM binaries WHERE hash=? LIMIT 1", -1, &statement, nullptr) != kOk) return false;
    sqlite.bindText(statement, 1, binaryHash.c_str(), -1, reinterpret_cast<Destructor>(kTransient)); const bool found = sqlite.step(statement) == kRow; sqlite.finalize(statement); return found;
}

}  // namespace mint
