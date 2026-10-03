#include <cstring>
#include <functional>
#include <iostream>
#include <vector>

#include "mint/analysis/code_analyzer.h"
#include "mint/decompile/decompiler.h"
#include "mint/interp/emulator.h"
#include "mint/ir/lifter.h"
#include "mint/ir/registers.h"

namespace {
using namespace mint;
int checks = 0, failures = 0;
bool expect(bool condition, const std::string& description) {
    ++checks;
    if (!condition) { ++failures; std::cerr << "FAIL " << description << '\n'; }
    return condition;
}
std::vector<u8> words(std::initializer_list<u32> instructions) {
    std::vector<u8> bytes;
    for (u32 word : instructions) for (unsigned n = 0; n < 4; ++n) bytes.push_back(static_cast<u8>(word >> (n * 8)));
    return bytes;
}
std::vector<u8> halves(std::initializer_list<u16> instructions) {
    std::vector<u8> bytes;
    for (u16 word : instructions) { bytes.push_back(static_cast<u8>(word)); bytes.push_back(static_cast<u8>(word >> 8)); }
    return bytes;
}
using Initialize = std::function<void(InterpState&)>;
void run(Arch architecture, const std::vector<u8>& bytes, u64 expected, const std::string& label,
         const Initialize& initialize = {}, unsigned expectedIntrinsics = 0, bool checkC = true) {
    ElfImage image;
    if (!expect(image.loadRaw(ByteView(bytes.data(), bytes.size()), architecture, 0x1000, 0x1000).ok(), label + " raw import")) return;
    CodeAnalyzer analyzer; CodeAnalyzer::Options options; options.linearSweepFallback = false;
    if (!expect(analyzer.analyze(image, options).ok() && analyzer.functionAt(0x1000), label + " native function discovery")) return;
    Lifter lifter;
    if (!expect(lifter.open(architecture).ok(), label + " native lifter opens")) return;
    IrFunction function;
    if (!expect(lifter.liftFunction(*analyzer.functionAt(0x1000), image.memory(), &function).ok(), label + " full function lift")) return;
    const auto invalid = function.verify();
    if (!expect(invalid.empty(), label + " IR width/arity/CFG verification")) {
        for (const auto& error : invalid) std::cerr << error << '\n';
        std::cerr << function.toText(); return;
    }
    expect(function.intrinsicCount == expectedIntrinsics, label + " honest intrinsic coverage");
    const bool arm = architecture == Arch::kArm32 || architecture == Arch::kThumb;
    const u8 width = arm || architecture == Arch::kRiscV32 || architecture == Arch::kX86_32 ? 4 : 8;
    const u64 resultRegister = arm ? arm32::kRn(0) :
        (architecture == Arch::kX86_32 || architecture == Arch::kX86_64 ? x86::kRax : riscv::kXn(10));
    Emulator emulator(architecture);
    emulator.state().memory().map(image.memory());
    if (arm) {
        emulator.state().setRegister(arm32::kLr, 0x8001, 4);
        emulator.state().setRegister(arm32::kSp, 0x4000, 4);
        emulator.state().setRegister(arm32::kFlagC, 1, 1);
    } else if (architecture == Arch::kRiscV32 || architecture == Arch::kRiscV64) {
        emulator.state().setRegister(riscv::kXn(1), 0x8000, width);
        emulator.state().setRegister(riscv::kSp, 0x4000, width);
    }
    if (initialize) initialize(emulator.state());
    InterpResult result;
    const auto status = emulator.run(function, InterpOptions{}, &result);
    if (expectedIntrinsics) {
        expect(!result.returned || emulator.state().registerValue(resultRegister, width).isUnknown(), label + " unsafe instruction cannot produce confident result");
    } else {
        const auto actual = emulator.state().registerValue(resultRegister, width);
        if (!expect(status.ok() && result.returned && actual.concreteLike() && actual.bits == expected,
                    label + " executable lifted semantics")) std::cerr << status.toString() << " " << result.stopReason << " actual=" << actual.toString() << '\n' << function.toText();
    }
    DecompileResult decompiled;
    expect(decompileIr(function, &decompiled).ok() && !decompiled.cSource.empty() && decompiled.cSource.find("return") != std::string::npos,
           label + " SSA/structuring/C emitter integration");
    if (checkC && !expectedIntrinsics)
        expect(decompiled.cSource.find("intrinsic") == std::string::npos, label + " supported scalar instructions do not become pseudo-intrinsics");
}

void armContracts() {
    run(Arch::kArm32,words({0xe3a00007,0xe2800005,0xe2400002,0xe12fff1e}),10,"ARM scalar arithmetic");
    run(Arch::kThumb,halves({0x2007,0x3005,0x3802,0x4770}),10,"Thumb scalar arithmetic");
    run(Arch::kArm32,words({0xe1d100d0,0xe12fff1e}),0xffffff80,"ARM signed byte load",[](InterpState& s){s.setRegister(arm32::kRn(1),0x3000,4);s.memory().writeByte(0x3000,0x80);});
    run(Arch::kThumb,halves({0x2007,0x6008,0x6808,0x3001,0x4770}),8,"Thumb load/store roundtrip",[](InterpState& s){s.setRegister(arm32::kRn(1),0x3000,4);});
    run(Arch::kThumb,halves({0xb510,0x2007,0xbd10}),7,"Thumb push/pop return",[](InterpState& s){s.setRegister(arm32::kRn(4),0x1234,4);});
    run(Arch::kArm32,words({0xe92d4010,0xe3a00007,0xe8bd8010}),7,"ARM push/pop return",[](InterpState& s){s.setRegister(arm32::kRn(4),0x1234,4);});
    for (u64 value : {u64{0},u64{1}}) {
        run(Arch::kArm32,words({0xe3500000,0x0a000002,0xe3a00007,0xe12fff1e,0xe1a00000,0xe3a00009,0xe12fff1e}),value?7:9,
            "ARM compare/conditional branch",[value](InterpState& s){s.setRegister(arm32::kRn(0),value,4);});
        run(Arch::kThumb,halves({0x2800,0xd001,0x2007,0x4770,0x2009,0x4770}),value?7:9,
            "Thumb compare/conditional branch",[value](InterpState& s){s.setRegister(arm32::kRn(0),value,4);});
    }
    for(u64 value:{u64{0},u64{3}}) {
        run(Arch::kThumb,halves({0x2800,0xbf08,0x2007,0x4770}),value?value:7,"Thumb IT register predication",[value](InterpState& s){s.setRegister(arm32::kRn(0),value,4);});
        run(Arch::kArm32,words({0xe3500000,0x03a00007,0xe12fff1e}),value?value:7,"ARM register predication",[value](InterpState& s){s.setRegister(arm32::kRn(0),value,4);});
        // ITE EQ: true/false mask must not flip after a narrow MOV sets flags.
        run(Arch::kThumb,halves({0x2800,0xbf0c,0x2007,0x2009,0x4770}),value?9:7,"Thumb ITE condition-mask and implicit flag suppression",[value](InterpState& s){s.setRegister(arm32::kRn(0),value,4);});
    }
    run(Arch::kThumb,halves({0x2800,0xbf08,0x6808,0x4770}),0,"Thumb predicated memory remains honest intrinsic",[](InterpState& s){s.setRegister(arm32::kRn(0),0,4);},1,false);
    run(Arch::kArm32,words({0xe1a00110,0xe12fff1e}),0,"ARM register shift over width",[](InterpState& s){s.setRegister(arm32::kRn(0),7,4);s.setRegister(arm32::kRn(1),33,4);});
    run(Arch::kThumb,halves({0xa001,0x4770}),0x1008,"Thumb ADR aligned PC value");
}

void riscvContracts(Arch architecture) {
    const u8 width=architecture==Arch::kRiscV32?4:8;
    const u64 mask=width==4?0xffffffff:~u64{0};
    run(architecture,words({0x00700513,0x00550513,0xffe50513,0x00008067}),10,"RISC-V scalar arithmetic");
    run(architecture,halves({0x451d,0x0515,0x1579,0x8082}),10,"RISC-V compressed scalar arithmetic");
    run(architecture,words({0x00700013,0x00900513,0x00008067}),9,"RISC-V x0 write is discarded");
    run(architecture,words({0x00058503,0x00008067}),mask-127,"RISC-V signed byte load",[width](InterpState& s){s.setRegister(riscv::kXn(11),0x3000,width);s.memory().writeByte(0x3000,0x80);});
    run(architecture,words({0x0005c503,0x00008067}),0x80,"RISC-V unsigned byte load",[width](InterpState& s){s.setRegister(riscv::kXn(11),0x3000,width);s.memory().writeByte(0x3000,0x80);});
    run(architecture,words({0x00a5a023,0x0005a503,0x00150513,0x00008067}),8,"RISC-V load/store roundtrip",[width](InterpState& s){s.setRegister(riscv::kXn(10),7,width);s.setRegister(riscv::kXn(11),0x3000,width);});
    run(architecture,words({0x02c5d533,0x00008067}),mask,"RISC-V unsigned division by zero",[width](InterpState& s){s.setRegister(riscv::kXn(11),42,width);s.setRegister(riscv::kXn(12),0,width);});
    run(architecture,words({0x02c5e533,0x00008067}),42,"RISC-V signed remainder by zero",[width](InterpState& s){s.setRegister(riscv::kXn(11),42,width);s.setRegister(riscv::kXn(12),0,width);});
    const u64 minimum=u64{1}<<(width*8-1);
    run(architecture,words({0x02c5c533,0x00008067}),minimum,"RISC-V signed division overflow",[width,minimum,mask](InterpState& s){s.setRegister(riscv::kXn(11),minimum,width);s.setRegister(riscv::kXn(12),mask,width);});
    for(u64 value:{u64{0},u64{1}})
        run(architecture,words({0x00050863,0x00700513,0x00008067,0x00000013,0x00900513,0x00008067}),value?7:9,
            "RISC-V conditional branch",[width,value](InterpState& s){s.setRegister(riscv::kXn(10),value,width);});
    if(width==8)run(architecture,words({0x0005051b,0x00008067}),0xffffffff80000000,"RV64 ADDIW sign-extends low word",[](InterpState& s){s.setRegister(riscv::kXn(10),0x1234567880000000,8);});
}
}
int main(){
    armContracts();riscvContracts(Arch::kRiscV32);riscvContracts(Arch::kRiscV64);
    std::cout<<"Native ISA lift/execute/decompile contracts: "<<checks<<" checks, "<<failures<<" failures\n";
    return failures?1:0;
}
