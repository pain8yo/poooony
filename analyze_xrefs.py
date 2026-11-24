#!/usr/bin/env python3
import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM

p = sys.argv[1]
data = open(p, "rb").read()
eh = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
shoff, shentsize, shnum, shstrndx = eh[6], eh[11], eh[12], eh[13]
secs = []
for i in range(shnum):
    o = shoff + i * shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, o)
    secs.append((name, typ, flags, addr, off, size))
st = secs[shstrndx]
names = data[st[4]:st[4] + st[5]]
def cstr(buf, off):
    end = buf.find(b"\\0", off)
    return buf[off:end].decode(errors="replace")
sec = {cstr(names, s[0]): s for s in secs}
text_sec, ro = sec[".text"], sec[".rodata"]
targets = [
    "Native_BuyCurrency", "Native_BuyPremiumCurrency", "Native_BuyTlsCurrency",
    "SetCurrencyData", "ResetCurrency", "SpendBits", "SpendGems",
    "SoftCurrency", "HardCurrency", "Total_Currency_Soft",
    "Total_Currency_Hard", "Spent_Currency_Soft", "Spent_Currency_Hard",
    "bits_amount", "gems_amount", "bits_limit", "gems_limit",
    "PlayerData", "MLP_Save", "mlp_save_prime.dat"
]
target_va = {}
for name in targets:
    needle = name.encode() + b"\\0"
    pos = data.find(needle, ro[4], ro[4] + ro[5])
    if pos >= 0:
        target_va[name] = ro[3] + pos - ro[4]
by_va = {v: n for n, v in target_va.items()}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
code = data[text_sec[4]:text_sec[4] + text_sec[5]]
ins = list(md.disasm(code, text_sec[3]))
hits = []
for i, x in enumerate(ins):
    if x.mnemonic != "adrp" or len(x.operands) < 2:
        continue
    if x.operands[1].type != ARM64_OP_IMM:
        continue
    page = x.operands[1].imm
    page_reg = x.operands[0].reg
    for j in range(i + 1, min(i + 9, len(ins))):
        y = ins[j]
        if y.mnemonic in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"):
            break
        if len(y.operands) >= 3 and y.mnemonic == "add":
            a, b, c = y.operands[:3]
            if a.type == ARM64_OP_REG and b.type == ARM64_OP_REG and c.type == ARM64_OP_IMM and b.reg == page_reg:
                va = page + c.imm
                if va in by_va:
                    hits.append((i, j, by_va[va], va, "ADRP+ADD"))
                    break
        if len(y.operands) >= 2 and y.mnemonic.startswith("ldr"):
            dst, mem = y.operands[:2]
            if mem.type == ARM64_OP_MEM and mem.mem.base == page_reg:
                va = page + mem.mem.disp
                if va in by_va:
                    hits.append((i, j, by_va[va], va, "ADRP+LDR"))
                    break
with open("report/currency-xrefs.txt", "w") as out:
    out.write("Target strings and virtual addresses:\\n")
    for name, va in target_va.items():
        out.write(f"{name}: 0x{va:x}\\n")
    out.write(f"\\nDecoded {len(ins)} instructions; found {len(hits)} references.\\n")
    seen = set()
    for i, j, name, va, kind in hits:
        key = (i, j, name)
        if key in seen:
            continue
        seen.add(key)
        out.write(f"\\n===== {name} @ 0x{va:x} ({kind}), code 0x{ins[i].address:x} =====\\n")
        for x in ins[max(0, i - 24):min(len(ins), j + 25)]:
            out.write(f"0x{x.address:x}: {x.mnemonic} {x.op_str}\\n")
print(f"Decoded {len(ins)} instructions; found {len(hits)} ADRP-based references across {len(target_va)} target strings")
