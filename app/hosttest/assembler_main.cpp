#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>
#include <unistd.h>

#include "mint/patch/assembler.h"
#include "mint/session.h"

using namespace mint;
namespace {
size_t checks = 0;
void require(bool condition, const char* message) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "assembler: %s\n", message); std::exit(1); }
}
std::vector<u8> compiled(Arch arch, const std::string& text, Address pc = 0x1000) {
    std::vector<u8> bytes;
    const Status status = assemble(arch, pc, text, &bytes);
    if (!status.ok()) std::fprintf(stderr, "source: %s\n%s\n", text.c_str(), status.toString().c_str());
    require(status.ok(), "assembly succeeds"); require(!bytes.empty() && bytes.size() <= 1024, "bounded nonempty output");
    return bytes;
}
void expected(Arch arch, const std::string& text, std::initializer_list<u8> bytes, Address pc = 0x1000) {
    require(compiled(arch, text, pc) == std::vector<u8>(bytes), "exact expected instruction encoding");
}
void rejected(Arch arch, const std::string& text, Address pc = 0x1000) {
    std::vector<u8> bytes{0xde, 0xad, 0xbe, 0xef};
    const Status status = assemble(arch, pc, text, &bytes);
    if(status.ok())std::fprintf(stderr,"unexpectedly accepted rejection fixture arch=%u pc=0x%llx: %s\n",static_cast<unsigned>(arch),static_cast<unsigned long long>(pc),text.c_str());
    require(!status.ok(), "bad source rejected");
    require(bytes == std::vector<u8>({0xde, 0xad, 0xbe, 0xef}), "failed assembly is atomic");
}
u32 word(const std::vector<u8>& bytes, size_t at) {
    return static_cast<u32>(bytes[at]) | (static_cast<u32>(bytes[at+1]) << 8) |
        (static_cast<u32>(bytes[at+2]) << 16) | (static_cast<u32>(bytes[at+3]) << 24);
}
u64 emulateA64Move(const std::vector<u8>& bytes, unsigned width) {
    u64 value = 0;
    for (size_t at = 0; at < bytes.size(); at += 4) {
        const u32 insn = word(bytes, at), operation = (insn >> 29) & 3;
        const unsigned shift = ((insn >> 21) & 3) * 16;
        const u64 part = static_cast<u64>((insn >> 5) & 65535) << shift;
        if (operation == 2) value = part; // MOVZ
        else if (operation == 0) value = ~part; // MOVN
        else if (operation == 3) value = (value & ~(u64(65535) << shift)) | part;
        else require(false, "only move-wide operations in mov expansion");
        if (width == 32) value &= 0xffffffffu;
    }
    return value;
}
u64 emulateRvLi(const std::vector<u8>& bytes, bool wide) {
    u64 value = 0;
    for (size_t at = 0; at < bytes.size(); at += 4) {
        const u32 insn = word(bytes, at);
        require((insn & 0x7f) == 0x13, "li expansion uses base integer immediate encoding");
        const unsigned funct3 = (insn >> 12) & 7;
        if (funct3 == 0) {
            const i64 immediate = (insn >> 31) ? static_cast<i64>(insn >> 20) - 4096 : static_cast<i64>(insn >> 20);
            if (((insn >> 15) & 31) == 0) value = 0;
            value += static_cast<u64>(immediate);
        } else if (funct3 == 1) value <<= (insn >> 20) & (wide ? 63 : 31);
        else require(false, "li expansion opcode understood");
        if (!wide) value &= 0xffffffffu;
    }
    return value;
}
void a64Tests() {
    expected(Arch::kAArch64, "nop; ret", {0x1f,0x20,0x03,0xd5,0xc0,0x03,0x5f,0xd6});
    expected(Arch::kAArch64, "Start: mov x0,#7; b End; nop; End: ret", {0xe0,0x00,0x80,0xd2,0x02,0x00,0x00,0x14,0x1f,0x20,0x03,0xd5,0xc0,0x03,0x5f,0xd6});
    expected(Arch::kAArch64, "mov x0,sp; mov sp,x1", {0xe0,0x03,0x00,0x91,0x3f,0x00,0x00,0x91});
    expected(Arch::kAArch64, "mov x0,x1; add x0,x1,#2; sub sp,sp,#16; cmp x0,#3", {0xe0,0x03,0x01,0xaa,0x20,0x08,0x00,0x91,0xff,0x43,0x00,0xd1,0x1f,0x0c,0x00,0xf1});
    expected(Arch::kAArch64, "str x0,[sp,#8]; ldr w1,[x2,#4]", {0xe0,0x07,0x00,0xf9,0x41,0x04,0x40,0xb9});
    expected(Arch::kAArch64, "b.eq 0x1008; cbnz w1,0x1000", {0x40,0x00,0x00,0x54,0xe1,0xff,0xff,0x35});
    expected(Arch::kAArch64, "mov x0,#0", {0x00,0x00,0x80,0xd2});
    expected(Arch::kAArch64, "mov x0,#-1", {0x00,0x00,0x80,0x92});
    for (u64 value : {u64(0),u64(1),u64(0xffff),u64(0x12345678),u64(0x123456789abcdef0),~u64(0),u64(0x8000000000000000)}) {
        require(emulateA64Move(compiled(Arch::kAArch64, "mov x3," + std::to_string(value)), 64) == value, "A64 full-width mov expansion preserves value");
    }
    require(emulateA64Move(compiled(Arch::kAArch64, "mov w4,0x89abcdef"), 32) == 0x89abcdefu, "32-bit move expansion width");
    compiled(Arch::kAArch64, "b 0x7fffffc", 0); rejected(Arch::kAArch64, "b 0x8000000", 0);
    compiled(Arch::kAArch64, "b 0", 0x8000000); rejected(Arch::kAArch64, "b 0", 0x8000004);
    rejected(Arch::kAArch64, "nop", 0x1001); rejected(Arch::kAArch64, "b 0x1002");
    rejected(Arch::kAArch64, "mov w0,0x100000000"); rejected(Arch::kAArch64, "add x0,x1,#4096");
    rejected(Arch::kAArch64, "movz w0,#1,lsl #32"); rejected(Arch::kAArch64, "ldr x0,[sp,#3]");
    rejected(Arch::kAArch64, "mov sp,xzr"); rejected(Arch::kAArch64, "add x0,x1,w2");
}
void x86Tests(bool wide) {
    const Arch arch = wide ? Arch::kX86_64 : Arch::kX86_32;
    expected(arch, "nop; ret; int3; ud2", {0x90,0xc3,0xcc,0x0f,0x0b});
    expected(arch, "mov eax,7; jmp Done; nop; Done:ret", {0xb8,7,0,0,0,0xe9,1,0,0,0,0x90,0xc3});
    expected(arch, "xor eax,eax; add eax,1; cmp eax,0x100", {0x31,0xc0,0x83,0xc0,1,0x81,0xf8,0,1,0,0});
    expected(arch, "here: call here; je here", {0xe8,0xfb,0xff,0xff,0xff,0x0f,0x84,0xf5,0xff,0xff,0xff});
    expected(arch, "ret 8", {0xc2,8,0});
    if (wide) {
        expected(arch, "mov rax,9; mov r9,rax; push r9; pop r8", {0x48,0xc7,0xc0,9,0,0,0,0x49,0x89,0xc1,0x41,0x51,0x41,0x58});
        expected(arch, "mov rax,0x1122334455667788", {0x48,0xb8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11});
        expected(arch, "xor r9,r8; call r9", {0x4d,0x31,0xc1,0x41,0xff,0xd1});
        rejected(arch, "add rax,0xffffffff"); rejected(arch, "mov rax,eax");
    } else {
        expected(arch, "push eax; pop ebx; call eax", {0x50,0x5b,0xff,0xd0});
        rejected(arch, "mov rax,7"); rejected(arch, "jmp 0x100000000", 0xfffffff0);
    }
    rejected(arch, "mov eax,0x100000000"); rejected(arch, "mov eax,[ebx+eax*3]");
    compiled(arch, "jmp 0x80000004", 0); rejected(arch, "jmp 0x80000005", 0);
    rejected(arch, "jmp -1");
}
void extendedTests(){
    expected(Arch::kAArch64,"stp x29,x30,[sp,#-16]!; ldp x29,x30,[sp],#16",{0xfd,0x7b,0xbf,0xa9,0xfd,0x7b,0xc1,0xa8});
    expected(Arch::kAArch64,"and x0,x1,x2; eor w3,w4,w5; mul x0,x1,x2",{0x20,0,2,0x8a,0x83,0,5,0x4a,0x20,0x7c,2,0x9b});
    expected(Arch::kAArch64,"adr x0,0x1008; tbz x1,#32,0x1000",{0x40,0,0,0x10,0xe1,0xff,7,0xb6});
    expected(Arch::kX86_64,"mov rax,[rbx+rcx*4+8]",{0x48,0x8b,0x44,0x8b,8});
    expected(Arch::kX86_64,"mov [r12+8],r9",{0x4d,0x89,0x4c,0x24,8});
    expected(Arch::kX86_64,"lea r10,[r13+r8*8-16]",{0x4f,0x8d,0x54,0xc5,0xf0});
    expected(Arch::kX86_32,"mov eax,[ebx]; add dword ptr [esp+4],1",{0x8b,3,0x83,0x44,0x24,4,1});
    expected(Arch::kX86_64,"mov rax,[rel Data]; ret; Data: .quad 0x1122334455667788",{0x48,0x8b,5,1,0,0,0,0xc3,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11});
    expected(Arch::kX86_64,".byte 1,2; .align 4,0x90; .word 0x12345678; .short -1",{1,2,0x90,0x90,0x78,0x56,0x34,0x12,0xff,0xff});
    std::vector<u8> output;require(assembleWithSymbols(Arch::kX86_64,0x1000,"call external; .quad external+4",{{"external",0x2000}},&output).ok(),"external symbols resolve direct branch and absolute data fixups");require(output==std::vector<u8>({0xe8,0xfb,0x0f,0,0,4,0x20,0,0,0,0,0,0}),"external symbol fixups retain exact64 bits");
    rejected(Arch::kX86_64,"mov rax,[rax+rsp*2]");rejected(Arch::kX86_64,"mov rax,[rax+2147483648]");rejected(Arch::kAArch64,".byte 0; nop");rejected(Arch::kX86_64,".align 3");rejected(Arch::kX86_64,".byte 256");rejected(Arch::kX86_64,".org 0xfff");rejected(Arch::kX86_64,".quad missing");
    expected(Arch::kArm32,"adds.eq r0,r1,#2; mov.ne r2,r3; ands r4,r5,r6",{2,0,0x91,0x02,3,0x20,0xa0,0x11,6,0x40,0x15,0xe0});
    expected(Arch::kRiscV64,"c.nop; c.li a0,7; c.mv a1,a0; c.add a0,a1; c.jr ra",{1,0,0x1d,0x45,0xaa,0x85,0x2e,0x95,0x82,0x80});
    expected(Arch::kRiscV32,"Here: c.j Here; c.beqz s0,Here",{1,0xa0,0x7d,0xdc});
    expected(Arch::kRiscV64,"c.lw s0,4(s1); c.sw s0,4(s1); c.ld s0,8(s1); c.sd s0,8(s1)",{0xc0,0x40,0xc0,0xc0,0x80,0x64,0x80,0xe4});
    rejected(Arch::kRiscV64,"c.li zero,1");rejected(Arch::kRiscV64,"c.li a0,32");rejected(Arch::kRiscV64,"c.lw a0,3(a1)");rejected(Arch::kArm32,"movs r0,0x12345678");
}
void armTests() {
    expected(Arch::kArm32, "mov r0,#7; b Done; nop; Done:ret", {7,0,0xa0,0xe3,0,0,0,0xea,0,0xf0,0x20,0xe3,0x1e,0xff,0x2f,0xe1});
    expected(Arch::kArm32, "add r0,r1,#2; sub sp,sp,#16; cmp r0,#3", {2,0,0x81,0xe2,0x10,0xd0,0x4d,0xe2,3,0,0x50,0xe3});
    expected(Arch::kArm32, "mov r0,0xabcd1234", {0x34,0x02,0x01,0xe3,0xcd,0x0b,0x4a,0xe3});
    expected(Arch::kArm32, "ldr r0,[sp,#4]; str r1,[r2,#-8]", {4,0,0x9d,0xe5,8,0x10,0x02,0xe5});
    expected(Arch::kArm32, "here:beq here", {0xfe,0xff,0xff,0x0a});
    rejected(Arch::kArm32, "nop", 0x1002); rejected(Arch::kArm32, "b 0x1002");
    rejected(Arch::kArm32, "mov pc,#7"); rejected(Arch::kArm32, "add r0,r1,#0x12345678");
    rejected(Arch::kArm32, "ldr r0,[r1,#4096]"); rejected(Arch::kArm32, "nop", 0x100000000);
}
void thumbTests() {
    expected(Arch::kThumb, "movs r0,#7; b Done; nop; Done:ret", {7,0x20,0,0xe0,0,0xbf,0x70,0x47});
    expected(Arch::kThumb, "bl 0x1004", {0,0xf0,0,0xf8});
    expected(Arch::kThumb, "again:bl again", {0xff,0xf7,0xfe,0xff});
    expected(Arch::kThumb, "mov r0,#0x1234", {0x41,0xf2,0x34,0x20});
    expected(Arch::kThumb, "mov r0,sp; add sp,#16; sub sp,#16; adds r0,#1; cmp r0,r1", {0x68,0x46,4,0xb0,0x84,0xb0,1,0x30,0x88,0x42});
    expected(Arch::kThumb, "str r0,[sp,#8]; ldr r1,[r2,#4]", {2,0x90,0x51,0x68});
    rejected(Arch::kThumb, "nop", 0x1001); rejected(Arch::kThumb, "b 0x1003");
    rejected(Arch::kThumb, "b 0x2000"); rejected(Arch::kThumb, "adds r8,#1");
    rejected(Arch::kThumb, "movs r0,#256"); rejected(Arch::kThumb, "sub r0,#1");
    rejected(Arch::kThumb, "ldr r0,[sp,#2]");
}
void rvTests(bool wide) {
    const Arch arch = wide ? Arch::kRiscV64 : Arch::kRiscV32;
    expected(arch, "li a0,7; j Done; nop; Done:ret", {0x13,0x05,0x70,0,0x6f,0,0x80,0,0x13,0,0,0,0x67,0x80,0,0});
    expected(arch, "addi sp,sp,-16; sw a0,12(sp); lw a1,12(sp)", {0x13,0x01,0x01,0xff,0x23,0x26,0xa1,0,0x83,0x25,0xc1,0});
    expected(arch, "beq a0,a1,0x1008; mv a0,a1", {0x63,0x04,0xb5,0,0x13,0x85,0x05,0});
    expected(arch, "here:jal ra,here", {0xef,0,0,0});
    expected(arch, "jalr zero,ra,0", {0x67,0x80,0,0});
    for (u64 value : {u64(0),u64(2047),u64(2048),u64(0x12345678),u64(0xffffffff)}) {
        require(emulateRvLi(compiled(arch, "li a3," + std::to_string(value)), wide) == value, "RISC-V li preserves positive value");
    }
    require(emulateRvLi(compiled(arch, "li a3,-1"), wide) == (wide ? ~u64(0) : u64(0xffffffff)), "RISC-V signed li");
    if (wide) {
        for (u64 value : {u64(0x123456789abcdef0),u64(0x7fffffffffffffff),u64(0x8000000000000000),~u64(0)}) require(emulateRvLi(compiled(arch, "li s0," + std::to_string(value)), true) == value, "RV64 extreme li overflow-safe expansion");
        compiled(arch, "ld a0,0(sp); sd a0,8(sp); addiw a0,a0,-1");
    } else { rejected(arch, "ld a0,0(sp)"); rejected(arch, "li a0,0x100000000"); }
    compiled(arch, "j 0xffffe", 0); rejected(arch, "j 0x100000", 0);
    rejected(arch, "nop", 0x1001); rejected(arch, "j 0x1001");
    rejected(arch, "addi a0,a0,2048"); rejected(arch, wide ? "slli a0,a0,64" : "slli a0,a0,32");
    rejected(arch, "sw a0,2048(sp)"); rejected(arch, "li x32,7");
}
void bounds() {
    rejected(Arch::kUnknown, "nop"); rejected(Arch::kDalvik, "nop");
    rejected(Arch::kAArch64, ""); rejected(Arch::kAArch64, "OnlyLabel:");
    rejected(Arch::kAArch64, "b missing"); rejected(Arch::kAArch64, "same:nop; same:ret");
    rejected(Arch::kX86_64, "mov eax,1,,2"); rejected(Arch::kAArch64, ".unknown 0xd503201f");
    expected(Arch::kAArch64, ".word 0xd503201f", {0x1f,0x20,0x03,0xd5});
    rejected(Arch::kAArch64, "nop; definitely_not_instruction");
    rejected(Arch::kX86_64, std::string("nop\0ret",7)); rejected(Arch::kX86_64, std::string(65537,' '));
    rejected(Arch::kX86_64, "nop", kNoAddress); rejected(Arch::kX86_64, "nop;nop", kNoAddress-1);
    rejected(Arch::kX86_32, "nop;nop", 0xffffffffu);
    std::string nops; for (unsigned i=0;i<1024;++i) nops += "nop;";
    require(compiled(Arch::kX86_64,nops).size()==1024, "byte/instruction limit accepted exactly");
    rejected(Arch::kX86_64,nops+"nop");
    expected(Arch::kX86_64, " MOV EAX, 7 // retained immediate\n RET", {0xb8,7,0,0,0,0xc3});
    for (Arch arch : {Arch::kAArch64,Arch::kX86_64,Arch::kX86_32,Arch::kArm32,Arch::kThumb,Arch::kRiscV32,Arch::kRiscV64}) require(assemblerSyntax(arch).find("1024") != std::string::npos, "syntax/help describes bounded supported assembler");
}
void sessionSymbolNamespaces(){
    struct Owned {
        std::vector<std::string> paths;
        ~Owned(){for(const auto& path:paths){unlink(path.c_str());unlink((path+".analysis").c_str());}}
        std::string fresh(bool absent=false){std::string path="/private/tmp/mint-assembler-symbols-XXXXXX";const int fd=mkstemp(path.data());require(fd>=0,"reserve owned assembler fixture");close(fd);paths.push_back(path);if(absent)unlink(path.c_str());return path;}
    } owned;
    std::vector<elf::Sym> entries(1);std::string strings(1,'\0');
    const auto symbol=[&](const std::string& name,Address value){elf::Sym entry{};entry.name=strings.size();entry.value=value;entry.shndx=1;entry.info=0x10;strings+=name;strings+='\0';entries.push_back(entry);};
    for(unsigned i=0;i<5000;++i)symbol("unused_"+std::to_string(i),0x1010);
    symbol("wanted",0x1020);symbol("clash",0x1010);symbol("clash",0x1020);symbol("same",0x1020);symbol("same",0x1020);symbol("$x.1",0x1000);symbol("demo.c",0x1000);
    const size_t symbolAt=0x180,stringsAt=symbolAt+entries.size()*sizeof(elf::Sym),sectionsAt=(stringsAt+strings.size()+7)&~size_t(7);
    std::vector<u8> file(sectionsAt+4*sizeof(elf::Shdr),0);elf::Ehdr header{};std::memcpy(header.ident,elf::kMagic,4);header.ident[elf::kEiClass]=elf::kElfClass64;header.ident[elf::kEiData]=elf::kElfData2Lsb;header.ident[6]=1;header.type=elf::kEtExec;header.machine=elf::kEmX86_64;header.version=1;header.entry=0x1000;header.phoff=sizeof(header);header.ehsize=sizeof(header);header.phentsize=sizeof(elf::Phdr);header.phnum=1;header.shoff=sectionsAt;header.shentsize=sizeof(elf::Shdr);header.shnum=4;
    std::memcpy(file.data(),&header,sizeof(header));elf::Phdr segment{};segment.type=elf::kPtLoad;segment.flags=elf::kPfR|elf::kPfX;segment.offset=0x100;segment.vaddr=0x1000;segment.filesz=segment.memsz=0x40;segment.align=1;std::memcpy(file.data()+header.phoff,&segment,sizeof(segment));file[0x100]=0xc3;file[0x110]=file[0x120]=0xc3;
    elf::Shdr sections[4]{};sections[1].type=elf::kShtProgBits;sections[1].flags=elf::kShfAlloc|elf::kShfExecInstr;sections[1].addr=0x1000;sections[1].offset=0x100;sections[1].size=0x40;sections[1].addralign=1;sections[2].type=elf::kShtStrTab;sections[2].offset=stringsAt;sections[2].size=strings.size();sections[2].addralign=1;sections[3].type=elf::kShtSymTab;sections[3].offset=symbolAt;sections[3].size=entries.size()*sizeof(elf::Sym);sections[3].entsize=sizeof(elf::Sym);sections[3].link=2;sections[3].info=1;sections[3].addralign=8;
    std::memcpy(file.data()+sectionsAt,sections,sizeof(sections));std::memcpy(file.data()+symbolAt,entries.data(),entries.size()*sizeof(elf::Sym));std::memcpy(file.data()+stringsAt,strings.data(),strings.size());const auto input=owned.fresh();{std::ofstream output(input,std::ios::binary);output.write(reinterpret_cast<const char*>(file.data()),file.size());require(output.good(),"write real ELF symbol namespace fixture");}
    Session session;require(session.openPath(input).ok()&&session.attachProject(owned.fresh(true)).ok()&&session.analyze().ok(),"analyze actual ELF with more than4096 unrelated names");require(session.image().symbols().size()>4096,"large external inventory preserved by loader");std::string bytes;
    require(session.assembleAt(0x1000,"nop // $x.1 demo.c unused_0",false,&bytes).ok()&&bytes=="90","standalone nop ignores invalid metadata names and unrelated large inventory");
    require(session.assembleAt(0x1000,"call unused_4999",false,&bytes).ok()&&bytes=="e8 0b 00 00 00","referenced late symbol is not lost through arbitrary first4096 truncation");
    require(session.assembleAt(0x1000,"call wanted",false,&bytes).ok()&&bytes=="e8 1b 00 00 00","unique original symbol uses exact address");require(session.assembleAt(0x1000,"call same",false,&bytes).ok()&&bytes=="e8 1b 00 00 00","duplicate original names at same address remain unambiguous");
    bytes="unchanged";require(!session.assembleAt(0x1000,"call clash",false,&bytes).ok()&&bytes=="unchanged","differently addressed duplicate symbols cannot invent first-or-last target");require(!session.assembleAt(0x1000,"call $x.1",false,&bytes).ok()&&!session.assembleAt(0x1000,"call demo.c",false,&bytes).ok(),"explicit unexpressible metadata names fail instead of coercion");
    require(session.editAnnotation(0x1000,"name","wanted").ok()&&!session.assembleAt(0x1000,"call wanted",false,&bytes).ok(),"user/original name address conflict remains explicitly unresolved");require(session.assembleAt(0x1000,"nop",true,&bytes).ok(),"irrelevant ambiguous names never block standalone patch publication");
    const std::string thisFile=__FILE__,demoPath=thisFile.substr(0,thisFile.find_last_of('/'))+"/../src/main/assets/libmintdemo.so";Session demo;require(demo.openPath(demoPath).ok()&&demo.attachProject(owned.fresh(true)).ok()&&demo.analyze().ok(),"analyze actual shipped Android demo symbol table");bool mapping=false;for(const auto& sym:demo.image().symbols())mapping|=sym.name=="$x.1";require(mapping,"shipped demo supplies exact offending invalid mapping symbol");require(!demo.analyzer().functions().empty(),"shipped demo exposes actual function for patching");const Address entry=demo.analyzer().functions().front().entry;require(demo.assembleAt(entry,"nop",true,&bytes).ok()&&bytes=="1f 20 03 d5","actual shipped demo permits standalone NOP despite mapping symbols");
}
}  // namespace
int main() {
    a64Tests(); x86Tests(true); x86Tests(false);extendedTests(); armTests(); thumbTests(); rvTests(false); rvTests(true); bounds();sessionSymbolNamespaces();
    std::fprintf(stderr, "assembler: %zu checks passed\n",checks); return 0;
}
