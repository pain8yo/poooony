#!/usr/bin/env python3
import sys, re
from collections import deque
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

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
        "Native_FreeGemsAdsFromHUD", "Native_FreeCoinsAdsFromHUD", "Native_BuyPopCurrency",
        "Native_ModifyShardCost", "Native_SpendShardsPressed",
        "SetCurrencyData", "ResetCurrency", "SpendBits", "SpendGems",
        "SoftCurrency", "HardCurrency", "Total_Currency_Soft",
        "Total_Currency_Hard", "Spent_Currency_Soft", "Spent_Currency_Hard",
        "bits_amount", "gems_amount", "bits_limit", "gems_limit",
        "PlayerData", "PaidCash", "MLP_Save", "mlp_save_prime.dat",
        "Currency", "currency", "cash", "coins", "Bits", "Gems",
        "SoftCost", "HardCost", "CurrencyCount", "CurrencyName",
        "FreeCash", "FreeCoins", "SetCurrencyIcon"
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
history = deque(maxlen=40)
pending = []
hits = []
decoded = 0
ranges = [
    (0x240000,0x240090),(0x240700,0x240800),(0x243e00,0x244300),
    (0x2854c0,0x285600),(0x287740,0x2877d0),(0x860d80,0x860e20),
    (0x2a7900,0x2a8000),(0x562200,0x562500),
    (0x6a8400,0x6a8c80),(0x6d0000,0x6d0400)
]
region_lines = {a:[] for a,b in ranges}
call_sites = {0x240750:[], 0x28550c:[]}
def imm(s):
    s = s.strip().lstrip("#")
    return int(s, 0)
for addr, size, mnemonic, op_str in md.disasm_lite(code, text_addr):
    decoded += 1
    line = f"0x{addr:x}: {mnemonic} {op_str}"
    for a,b in ranges:
        if a <= addr < b:
            region_lines[a].append(line)
    if mnemonic == "bl":
        try:
            dest = imm(op_str)
            if dest in call_sites:
                call_sites[dest].append((addr, list(history)))
        except ValueError:
            pass
    history.append(line)
    keep = []
    for page, reg, age in pending:
        age += 1
        if age > 8:
            continue
        found = None
        parts = [p.strip() for p in op_str.split(",")]
        if mnemonic == "add" and len(parts) >= 3 and parts[1] == reg:
            try:
                found = page + imm(parts[2])
            except ValueError:
                pass
        elif mnemonic.startswith("ldr") and len(parts) >= 2:
            m = re.search(r"\[\s*(x\d+|w\d+)\s*,\s*(#[^\]]+)\]", parts[1])
            if m and m.group(1) == reg:
                try:
                    found = page + imm(m.group(2))
                except ValueError:
                    pass
        if found in by_va:
            hits.append((by_va[found], found, addr, list(history)))
        elif mnemonic not in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"):
            keep.append((page, reg, age))
    pending = keep
    if mnemonic == "adrp":
        m = re.match(r"(x\d+|w\d+)\s*,\s*(#[^ ]+)", op_str)
        if m:
            try:
                pending.append((imm(m.group(2)), m.group(1), 0))
            except ValueError:
                pass

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
        out.write("\n".join(context) + "\n")
with open("report/currency-regions.txt", "w") as out:
    for a,b in ranges:
        out.write(f"\n===== region 0x{a:x}-0x{b:x} =====\n")
        out.write("\n".join(region_lines[a]) + "\n")
with open("report/currency-call-sites.txt", "w") as out:
    for dest, sites in call_sites.items():
        out.write(f"\n===== BL xrefs to 0x{dest:x}: {len(sites)} =====\n")
        for addr, context in sites:
            out.write(f"\n-- call at 0x{addr:x} --\n")
            out.write("\n".join(context) + "\n")
print(f"Decoded {decoded} instructions; found {len(hits)} ADRP-based references across {len(target_va)} target strings")
