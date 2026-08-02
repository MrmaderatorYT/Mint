#pragma once

#include <string>
#include <vector>

#include "mint/base/status.h"
#include "mint/db/database.h"

namespace mint {

Status queryFunctionsCalling(Database* database, const std::string& target,
                             std::vector<DbFunction>* result);

}  // namespace mint
