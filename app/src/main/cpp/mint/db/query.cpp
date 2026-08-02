#include "mint/db/query.h"

namespace mint {

Status queryFunctionsCalling(Database* database, const std::string& target,
                             std::vector<DbFunction>* result) {
    if (!database) return Status::error(ErrorCode::kInternalError, "null analysis database");
    return database->functionsCalling(target, result);
}

}  // namespace mint
