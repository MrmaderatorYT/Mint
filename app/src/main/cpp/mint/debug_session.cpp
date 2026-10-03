#include "mint/session.h"
#include <algorithm>
#include <sstream>

namespace mint {
DataTypeManager Session::importedDebugTypes() const {
    DataTypeManager types(image_.pointerSize());
    std::vector<std::string> pending;
    for(const auto& type:debugInfo_.types)if(!type.declaration.empty())pending.push_back(type.declaration);
    std::string library="MINT_TYPES 1 "+std::to_string(image_.pointerSize())+'\n';
    for(const auto& declaration:pending)library+=declaration+'\n';
    if(types.deserialize(library).ok())return types;
    const auto passes=pending.size();
    for(size_t pass=0;pass<passes && !pending.empty();++pass) {
        bool progress=false;
        for(auto it=pending.begin();it!=pending.end();) {
            if(types.define(*it).ok()){it=pending.erase(it);progress=true;}else ++it;
        }
        if(!progress)break;
    }
    return types;
}
void Session::loadDebugInfo() {
    debugInfo_={};
    externalDebugDigest_.clear();
    if(image_.format()==ImageFormat::kElf64 || image_.format()==ImageFormat::kElf32 || image_.format()==ImageFormat::kMachO64) {
        const auto status=readDwarf(image_,&debugInfo_);
        if(!status.ok()){debugInfo_.partial=true;debugInfo_.warnings.push_back(status.toString());}
    }
    program_=Program(image_.pointerSize());
    const auto status=program_.setImportedTypes(importedDebugTypes());
    if(!status.ok())debugInfo_.warnings.push_back("Debug types not adopted: "+status.toString());
}
std::string Session::sourceLocationText(Address address) const {
    // A line row applies until the next row in that sequence, never across an
    // end_sequence marker or from an unrelated earlier compile unit.
    const DwarfSourceRow* selected=nullptr;Address bestEnd=0;
    for(size_t i=0;i+1<debugInfo_.sources.size();++i) {
        const auto& row=debugInfo_.sources[i];const auto& next=debugInfo_.sources[i+1];
        if(!row.endSequence && row.address<=address && address<next.address &&
           (!selected || row.address>selected->address || (row.address==selected->address && next.address<bestEnd))) {
            selected=&row;bestEnd=next.address;
        }
    }
    if(!selected)return {};
    return selected->file+":"+std::to_string(selected->line)+(selected->column?":"+std::to_string(selected->column):"");
}
} // namespace mint
