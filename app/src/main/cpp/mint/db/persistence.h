#pragma once

#include <string>

#include "mint/base/status.h"
#include "mint/db/database.h"

namespace mint {

Status persistAnalysis(Database* database, const IrFunction& function,
                        const std::string& binaryHash = {});

}  // namespace mint
