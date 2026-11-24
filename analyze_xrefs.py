#!/usr/bin/env python3
import sys, struct, subprocess
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM
p=sys.argv[1]
data=open(p,'rb').read()
# ELF64 little-endian section table
eh=struct.unpack_from('<16sHHIQQQIHHHHHH',data,0)
shoff, shentsize, shnum, shstrndx=eh[6],eh[11],eh[12],eh[13]
secs=[]
for i in range(shnum):
 o=shoff+i*shentsize
 name,typ,flags,addr,off,size,link,info,align,entsize=struct.unpack_from('<IIQQQQIIQQ',data,o)
 secs.append((name,typ,flags,addr,off,size))
st=secs[shstrndx]; names=data[st[4]:st[4]+st[5]]
def cstr(b,o):
 e=b.find(b'\0',o); return b[o:e].decode(errors='replace')
sec={cstr(names,s[0]):s for s in secs}
text=sec['.text']; ro=sec['.rodata']
targets=['Native_BuyCurrency','Native_BuyPremiumCurrency','Native_BuyTlsCurrency','SetCurrencyData','ResetCurrency','SpendBits','SpendGems','SoftCurrency','HardCurrency','Total_Currency_Soft','Total_Currency_Hard','bits_amount','gems_amount','bits_limit','gems_limit','PlayerData','MLP_Save']
target_va={}
for name in targets:
 needle=name.encode()+b'\0'
 pos=data.find(needle,ro[4],ro[4]+ro[5])
 if pos>=0: target_va[name]=ro[3]+pos-ro[4]
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
code=data[text[4]:text[4]+text[5]]
ins=list(md.disasm(code,text[3]))
hits=[]
for i,x in enumerate(ins):
 if x.mnemonic!='adrp' or len(x.operands)<2 or x.operands[1].type!=ARM64_OP_IMM: continue
 page=x.operands[1].imm
 for j in range(i+1,min(i+7,len(ins))):
  y=ins[j]
  if y.mnemonic in ('b','bl','br','blr','ret'): break
  if y.mnemonic=='add' and len(y.operands)>=3 and y.operands[2].type==ARM64_OP_IMM:
   va=page+y.operands[2].imm
   for n,t in target_va.items():
    if va==t: hits.append((i,n,va)); break
out=open('report/currency-xrefs.txt','w')
out.write('Target strings and virtual addresses:\\n')
for n,v in target_va.items(): out.write(f'{n}: 0x{v:x}\\n')
out.write('\\nDisassembly around references (±32 instructions):\\n')
seen=set()
for i,n,va in hits:
 key=(i,n)
 if key in seen: continue
 seen.add(key); out.write(f'\\n===== {n} @ 0x{va:x}, code 0x{ins[i].address:x} =====\\n')
 for x in ins[max(0,i-32):min(len(ins),i+33)]:
  out.write(f'0x{x.address:x}: {x.mnemonic} {x.op_str}\\n')
out.close()
print(f'Found {len(hits)} direct ADRP+ADD string references across {len(target_va)} targets')
