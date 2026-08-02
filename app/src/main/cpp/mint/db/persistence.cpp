#include "mint/db/persistence.h"

namespace mint {

Status persistAnalysis(Database* database, const IrFunction& function,
                        const std::string& binaryHash) {
    if (!database) return Status::error(ErrorCode::kInternalError, "null analysis database");
    return database->persist(function, binaryHash);
}

}  // namespace mint
