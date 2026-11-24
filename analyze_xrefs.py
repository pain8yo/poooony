#!/usr/bin/env python3
import sys
from collections import deque
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
history = deque(maxlen=25)
pending = []
hits = []
decoded = 0
for x in md.disasm(code, text_addr):
    decoded += 1
    history.append(x)
    keep = []
    for page, reg, age in pending:
        age += 1
        if age <= 8:
            y = x
            found = None
            if y.mnemonic == "add" and len(y.operands) >= 3:
                a, b, c = y.operands[:3]
                if a.type == ARM64_OP_REG and b.type == ARM64_OP_REG and c.type == ARM64_OP_IMM and b.reg == reg:
                    found = page + c.imm
            elif y.mnemonic.startswith("ldr") and len(y.operands) >= 2:
                mem = y.operands[1]
                if mem.type == ARM64_OP_MEM and mem.mem.base == reg:
                    found = page + mem.mem.disp
            if found in by_va:
                hits.append((by_va[found], found, x.address, list(history)))
            elif y.mnemonic not in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"):
                keep.append((page, reg, age))
    pending = keep
    if x.mnemonic == "adrp" and len(x.operands) >= 2 and x.operands[1].type == ARM64_OP_IMM:
        pending.append((x.operands[1].imm, x.operands[0].reg, 0))

with open("report/currency-xrefs.txt", "w") as out:
    out.write("Target strings and virtual addresses:\n")
    for name, va in target_va.items():
        out.write(f"{name}: 0x{va:x}\n")
    out.write(f"\nDecoded {decoded} instructions; found {len(hits)} references.\n")
    seen = set()
    for name, va, addr, context in hits:
        key = (name, addr)
        if key in seen:
            continue
        seen.add(key)
        out.write(f"\n===== {name} @ 0x{va:x}, reference instruction 0x{addr:x} =====\n")
        for x in context:
            out.write(f"0x{x.address:x}: {x.mnemonic} {x.op_str}\n")
print(f"Decoded {decoded} instructions; found {len(hits)} ADRP-based references across {len(target_va)} target strings")
