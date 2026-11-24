#!/usr/bin/env python3
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM

path = sys.argv[1]
with open(path, "rb") as f:
    elf = ELFFile(f)
    text_sec = elf.get_section_by_name(".text")
    ro = elf.get_section_by_name(".rodata")
    if text_sec is None or ro is None:
        raise SystemExit("Required ELF sections .text/.rodata not found")
    ro_data = ro.data()
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
        pos = ro_data.find(name.encode() + b"\0")
        if pos >= 0:
            target_va[name] = ro["sh_addr"] + pos
    text_addr = text_sec["sh_addr"]
    code = text_sec.data()

by_va = {v: n for n, v in target_va.items()}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
ins = list(md.disasm(code, text_addr))
hits = []
for i, x in enumerate(ins):
    if x.mnemonic != "adrp" or len(x.operands) < 2 or x.operands[1].type != ARM64_OP_IMM:
        continue
    page, page_reg = x.operands[1].imm, x.operands[0].reg
    for j in range(i + 1, min(i + 9, len(ins))):
        y = ins[j]
        if y.mnemonic in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"):
            break
        if y.mnemonic == "add" and len(y.operands) >= 3:
            a, b, c = y.operands[:3]
            if a.type == ARM64_OP_REG and b.type == ARM64_OP_REG and c.type == ARM64_OP_IMM and b.reg == page_reg:
                va = page + c.imm
                if va in by_va:
                    hits.append((i, j, by_va[va], va, "ADRP+ADD"))
                    break
        if y.mnemonic.startswith("ldr") and len(y.operands) >= 2:
            mem = y.operands[1]
            if mem.type == ARM64_OP_MEM and mem.mem.base == page_reg:
                va = page + mem.mem.disp
                if va in by_va:
                    hits.append((i, j, by_va[va], va, "ADRP+LDR"))
                    break

with open("report/currency-xrefs.txt", "w") as out:
    out.write("Target strings and virtual addresses:\n")
    for name, va in target_va.items():
        out.write(f"{name}: 0x{va:x}\n")
    out.write(f"\nDecoded {len(ins)} instructions; found {len(hits)} references.\n")
    seen = set()
    for i, j, name, va, kind in hits:
        key = (i, j, name)
        if key in seen:
            continue
        seen.add(key)
        out.write(f"\n===== {name} @ 0x{va:x} ({kind}), code 0x{ins[i].address:x} =====\n")
        for x in ins[max(0, i - 24):min(len(ins), j + 25)]:
            out.write(f"0x{x.address:x}: {x.mnemonic} {x.op_str}\n")
print(f"Decoded {len(ins)} instructions; found {len(hits)} ADRP-based references across {len(target_va)} target strings")
