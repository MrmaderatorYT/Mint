import argparse, pathlib, subprocess, tempfile
parser=argparse.ArgumentParser(description="Regenerate ARM/Thumb NEON raw-machine fixtures")
parser.add_argument("--clang",required=True)
parser.add_argument("--objcopy")
args=parser.parse_args()
clang=args.clang
objcopy=args.objcopy or str(pathlib.Path(clang).with_name('llvm-objcopy'))
cases=[]
def add(kind,lanes,types,widths=(8,16),extra=0):
 for size in widths:
  regs=('d0','d2','d4') if size==8 else ('q0','q1','q2')
  for lane in lanes:
   for typ in types:
    suffix=typ+str(lane*8) if typ else str(lane*8)
    mnemonic=kind+'.'+suffix
    if kind in ('vabs','vneg','vrev16','vrev32','vrev64'): asm=f'{mnemonic} {regs[0]}, {regs[1]}'
    elif kind=='vdup':asm=f'{mnemonic} {regs[0]}, r0'
    elif kind=='vext':asm=f'{mnemonic} {regs[0]}, {regs[1]}, {regs[2]}, #{extra}'
    elif kind in ('vshl','vshr','vsra') and extra>=0:asm=f'{mnemonic} {regs[0]}, {regs[1]}, #{extra if extra or kind=="vshl" else lane*8}'
    else:asm=f'{mnemonic} {regs[0]}, {regs[1]}, {regs[2]}'
    cases.append(dict(name=f'{kind}_{size}_{typ}{lane}_{extra}',asm=asm,kind=kind,lane=lane,size=size,signed=typ=='s',extra=extra,dest=0,left=16,right=32))
add('vadd',(1,2,4,8),('i',));add('vsub',(1,2,4,8),('i',))
for op in ('vmul','vmla','vmls'):add(op,(1,2,4),('i',))
for op in ('vmin','vmax','vcgt','vcge'):add(op,(1,2,4),('s','u'))
for op in ('vceq','vtst'):add(op,(1,2,4),('i',))
for op in ('vclt','vcle'):add(op,(1,2,4),('s','u'))
for op in ('vabs','vneg'):add(op,(1,2,4),('s',))
for op in ('vshl','vshr','vsra'):
 for amount in (1,0):
  add(op,(1,2,4,8),('i',) if op=='vshl' else ('s','u'),extra=amount)
 if op=='vshl':add(op,(1,2,4,8),('s','u'),extra=-1)
add('vdup',(1,2,4),('',))
for group in (2,4,8):add(f'vrev{group*8}',tuple(n for n in (1,2,4) if n<group),('',))
for offset in range(8):add('vext',(1,),('',),extra=offset)
for offset in range(8,16):add('vext',(1,),('',),widths=(16,),extra=offset)
for kind in ('vbsl','vbit','vbif'):
 for size in (8,16):
  regs=('d0','d2','d4') if size==8 else ('q0','q1','q2')
  cases.append(dict(name=f'{kind}_{size}',asm=f'{kind} {regs[0]},{regs[1]},{regs[2]}',kind=kind,lane=1,size=size,signed=False,extra=0,dest=0,left=16,right=32))
# Aliased operands are independent source snapshots, including the high bank.
for base in list(cases):
 if base['kind'] in ('vadd','vmla','vext','vbsl','vshl') and base['extra'] in (1,3,-1) and base['lane'] in (1,8):
  for which,offset in ((1,16),(2,32)):
   item=base.copy();dest=('d2' if which==1 else 'd4') if item['size']==8 else ('q1' if which==1 else 'q2')
   item['asm']=item['asm'].replace('d0',dest,1).replace('q0',dest,1);item['dest']=offset;item['name']+=f'_alias{which}';cases.append(item)
for size in (8,16):
 cases.append(dict(name=f'high_vadd_{size}',asm='vadd.i8 d31,d29,d30' if size==8 else 'vadd.i8 q15,q13,q14',kind='vadd',lane=1,size=size,signed=False,extra=0,dest=248 if size==8 else 240,left=232 if size==8 else 208,right=240 if size==8 else 224))
# Compare-to-zero is a distinct operand form.
for op in ('vceq','vcgt','vcge','vclt','vcle'):
 for size in (8,16):
  reg='d' if size==8 else 'q';left='d2' if size==8 else 'q1'
  cases.append(dict(name=f'{op}_zero_{size}',asm=f'{op}.s32 {reg}0,{left},#0',kind=op,lane=4,size=size,signed=True,extra=0,dest=0,left=16,right=-1))
for asm in ('vqadd.s8 q0,q1,q2','vmul.p8 q0,q1,q2','vadd.f32 q0,q1,q2','vmla.i16 q0,q1,d4[2]'):
 cases.append(dict(name='unsupported_'+str(len(cases)),asm=asm,kind='unsupported',lane=1,size=16,signed=False,extra=0,dest=0,left=16,right=32))
# Deduplicate syntax, preserving first reference descriptor.
cases=list({c['asm']:c for c in cases}.values())
with tempfile.TemporaryDirectory() as tmp:
 tmp=pathlib.Path(tmp)
 for mode in ('arm','thumb'):
  source='.syntax unified\n.fpu neon-vfpv4\n.'+mode+'\n.text\n'
  for c in cases:
   d=c['dest']//8
   source+=c['asm']+f'\nvmov r0,r1,d{d}\nbx lr\n'
  (tmp/'source.s').write_text(source)
  subprocess.run([clang,'--target=armv7a-linux-gnueabi','-c',str(tmp/'source.s'),'-o',str(tmp/'source.o')],check=True)
  subprocess.run([objcopy,'-O','binary','--only-section=.text',str(tmp/'source.o'),str(tmp/'source.bin')],check=True)
  data=(tmp/'source.bin').read_bytes();length=12 if mode=='arm' else 10
  assert len(data)==length*len(cases),(mode,len(data),length*len(cases))
  for n,c in enumerate(cases):c[mode]=data[n*length:(n+1)*length]
 lines=['// Generated from the source spellings below by NDK Clang 28.2; ARMv7 NEON-VFPv4.',
 'struct NeonCase {const char* name;const char* assembly;const char* operation;u8 lane,size;bool signedData;int extra,destination,left,right;std::vector<u8> arm,thumb;};',
 'const std::vector<NeonCase> cases={']
 for c in cases:
  enc=lambda mode:'{'+','.join(f'0x{x:02x}' for x in c[mode])+'}'
  lines.append('    {"'+c['name']+'","'+c['asm']+'","'+c['kind']+'",'+f"{c['lane']},{c['size']},{str(c['signed']).lower()},{c['extra']},{c['dest']},{c['left']},{c['right']},"+enc('arm')+','+enc('thumb')+'},')
 lines.append('};')
 pathlib.Path(__file__).with_name('arm_neon_encodings.h').write_text('\n'.join(lines)+'\n')
print(len(cases),'generated encoding pairs')
