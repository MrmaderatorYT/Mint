#pragma once

#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/ir/ir_function.h"

namespace mint {

struct DbFunction {
    i64 id = 0;
    Address entry = 0;
    std::string name;
    u32 size = 0;
};

struct ProgramAnnotation {
    Address address = 0;
    std::string kind;
    std::string value;
};

/// Thin native SQLite wrapper. SQLite is deliberately not exposed in public
/// headers; Android and host use different system library names, while the
/// schema and the cache format remain identical.
class Database {
public:
    /// Bumped whenever the schema changes shape. Read at open; a file written by a
    /// newer build is refused, an older one is rebuilt.
    static constexpr int kSchemaVersion = 2;

    Database() = default;
    ~Database();
    Database(const Database&) = delete;

    Status open(const std::string& path);
    void close();
    bool isOpen() const { return handle_ != nullptr; }
    Status execute(const std::string& sql);
    Status ensureSchema();
    /// Runs a statement whose first row and column is one integer.
    Status queryScalar(const std::string& sql, i64* out) const;
    Status persist(const IrFunction& function, const std::string& binaryHash = {});
    Status functionsCalling(const std::string& target, std::vector<DbFunction>* out) const;
    bool hasBinary(const std::string& binaryHash) const;
    Status readAnnotations(std::vector<ProgramAnnotation>* out) const;
    Status writeAnnotations(const std::vector<ProgramAnnotation>& entries);

private:
    void* handle_ = nullptr;
};

}  // namespace mint
