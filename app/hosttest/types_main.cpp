#include "mint/types/data_type_manager.h"
#include "mint/analysis/demangle.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace mint;

namespace {
unsigned checks = 0;
void check(bool condition, const std::string& message) {
    ++checks;
    if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
void accepted(DataTypeManager& types, const std::string& declaration) {
    auto s = types.define(declaration);
    check(s.ok(), declaration + ": " + s.toString());
}
void rejected(DataTypeManager& types, const std::string& declaration) {
    const auto before = types.serialize();
    check(!types.define(declaration).ok(), "reject " + declaration);
    check(types.serialize() == before, "failed definition is atomic");
}
DataTypeLayout layout(const DataTypeManager& types, const std::string& expression) {
    DataTypeLayout out;
    const auto s = types.resolve(expression, &out);
    check(s.ok(), "resolve " + expression + ": " + s.toString());
    return out;
}
}

int main(int argc,char** argv) {
    if(argc==2 && std::string(argv[1])=="--emit-header") {
        DataTypeManager library;check(library.deserialize("MINT_TYPES 1 8\nNode=struct{value:i32;next:Node*}\nWire=packed{tag:u8;payload:u32}\nSparse=struct{tag:u8;payload:u32@16}\nWords=u16[3]\nArrayPointer=Words*\nNodePointer=Node*\nPair=struct{node:Node;other:Node*}\nValue=union{number:u64;words:u16[4]}\nColor=enum:i32{Red=-1;Green=2}\n").ok(),"header library");
        std::string header;check(library.cHeader(&header).ok(),"header export");std::cout<<header;return 0;
    }
    DataTypeManager types;
    check(layout(types, "u8").size == 1, "u8");
    check(layout(types, "u64").alignment == 8, "u64 alignment");
    check(layout(types, "pointer").size == 8, "pointer builtin");
    check(layout(types, "void*").size == 8, "void pointer");
    check(layout(DataTypeManager(4), "u32*").size == 4, "32-bit pointers");
    DataTypeLayout out;
    check(!DataTypeManager(3).resolve("u8", &out).ok(), "invalid target pointer width");
    accepted(types, "Packet = struct { length:u32; bytes:u8[16]; next:Packet* }");
    auto packet = layout(types, "Packet");
    check(packet.size == 32 && packet.alignment == 8, "Packet layout padding");
    check(packet.fields.size() == 3 && packet.fields[2].offset == 24, "recursive pointer layout");
    accepted(types, "Wire=packed{tag:u8;value:u32}");
    auto wire = layout(types, "Wire");
    check(wire.size == 5 && wire.alignment == 1 && wire.fields[1].offset == 1, "packed wire layout");
    accepted(types, "Value=union{integer:u64;real:f64;raw:u8[3]}");
    auto value = layout(types, "Value");
    check(value.size == 8 && value.alignment == 8 && value.fields[2].offset == 0, "union layout");
    accepted(types, "Sparse=struct{tag:u8;payload:u32@0x10}");
    check(layout(types, "Sparse").size == 20, "explicit field offset");
    accepted(types, "Color=enum:i8{Red=-128;Green=127}");
    auto color = layout(types, "Color");
    check(color.size == 1 && color.isSigned && color.enumerators[0].value == -128, "signed enum");
    accepted(types, "Handle=u64");
    check(layout(types, "Handle[4]").size == 32, "array alias");
    check(layout(types, "u8*[4]").size == 32, "pointer array");
    check(layout(types, "u8[4]*").size == 8, "array pointer");
    check(layout(types, "Packet[3]").size == 96, "aggregate array");
    accepted(types, "Links=struct{first:Packet*;last:Packet*}");
    const auto before = types.serialize();
    check(!types.erase("Packet").ok() && types.serialize() == before, "referenced type cannot be erased");
    check(types.erase("Links").ok(), "erase unreferenced type");
    rejected(types, "Bad=struct{self:Bad}");
    rejected(types, "Bad=struct{x:void}");
    rejected(types, "Bad=void[2]");
    rejected(types, "Bad=void[2]*");
    rejected(types, "Bad=struct{x:void}*");
    rejected(types, "Bad=struct{x:u32;y:u8@1}*");
    rejected(types, "Bad=struct{x:u32;y:u32@2}");
    rejected(types, "Bad=union{x:u32@4}");
    rejected(types, "Bad=struct{x:u32;x:u32}");
    rejected(types, "Bad=enum:u8{Min=-1}");
    rejected(types, "Bad=enum:i8{High=128}");
    rejected(types, "Bad=enum:f32{X=1}");
    rejected(types, "Bad=enum:Color{X=1}");
    rejected(types, "Bad=enum:u8{X=1;X=2}");
    rejected(types, "Bad=struct{}");
    rejected(types, "Bad=enum:u8{}");
    rejected(types, "Bad=u64[1073741824]");
    rejected(types, "Bad=u8[18446744073709551616]");
    rejected(types, "Bad=u8[0]");
    rejected(types, "Bad=Missing*");
    rejected(types, "u64=u8");
    rejected(types, "Bad=u8;garbage");
    rejected(types, "Bad=enum:i64{X=-9223372036854775809}");
    accepted(types, "Min=enum:i64{X=-9223372036854775808}");
    accepted(types, "Item=u32");
    accepted(types, "ItemContainer=struct{one:Item;tail:u8@4}");
    rejected(types, "Item=u64");
    check(layout(types, "Item").size == 4, "replacement validates existing dependent layouts");

    DataTypeManager restored;
    check(restored.deserialize(types.serialize()).ok(), "roundtrip deserialize");
    check(restored.serialize() == types.serialize(), "canonical deterministic roundtrip");
    check(restored.declarationFor("Packet") == "Packet=struct{length:u32;bytes:u8[16];next:Packet*}", "canonical declaration");
    check(restored.renderDefinitions().find("+0x18 next: Packet*") != std::string::npos, "field display");
    const auto persisted = restored.serialize();
    check(!restored.deserialize("MINT_TYPES 1 8\nA=B\nB=A\n").ok(), "cross-definition by-value cycle");
    check(restored.serialize() == persisted, "failed deserialize is atomic");
    check(!restored.deserialize("MINT_TYPES 1 8\nA=u8\nA=u16\n").ok(), "duplicate persistence entry");
    check(!restored.deserialize("MINT_TYPES 2 8\n").ok(), "future format rejected");
    check(!restored.deserialize("MINT_TYPES 1 4\n").ok(), "pointer width mismatch rejected");
    check(!restored.deserialize("MINT_TYPES 1 8\nA=u8").ok(), "truncated declaration rejected");
    check(restored.deserialize("MINT_TYPES 1 8\nA=struct{b:B*}\nB=struct{a:A*}\n").ok(), "forward recursive pointer references");
    check(layout(restored, "A").size == 8, "forward reference layout");
    std::string header;check(restored.cHeader(&header).ok(),"mutually recursive aggregate C header");
    check(header.find("offsetof(A, b)")!=std::string::npos,"header exact offset assertions");
    DataTypeManager cyclic;check(cyclic.define("Alias=Alias*").ok(),"recursive pointer alias valid DTM");
    header="unchanged";check(!cyclic.cHeader(&header).ok() && header=="unchanged","unrepresentable C alias export is atomic");
    std::string depth = "u8";
    for (unsigned i = 0; i < 65; ++i) depth += '*';
    check(!types.resolve(depth, &out).ok(), "bounded suffix nesting");
    check(!types.define(std::string(16385, 'A')).ok(), "declaration byte budget");
    check(!types.deserialize(std::string(1024 * 1024 + 1, 'A')).ok(), "library byte budget");

    check(demangleSymbol("_ZN3Foo3barEi") == "Foo::bar(int)", "C++ demangle");
    check(demangleSymbol("_ZTV3Foo") == "vtable for Foo", "vtable symbol display");
    check(demangleSymbol("_ZTI3Foo") == "typeinfo for Foo", "RTTI symbol display");
    check(demangleSymbol("_Zinvalid") == "_Zinvalid", "invalid demangle fallback");
    check(demangleSymbol("malloc") == "malloc", "ordinary symbol unchanged");
    const std::string longSymbol = "_Z" + std::string(4097, 'A');
    check(demangleSymbol(longSymbol) == longSymbol, "demangle input budget");
    std::cout << "types/demangle checks: " << checks << " passed\n";
}
