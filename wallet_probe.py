#!/usr/bin/env python3
"""Focused ARM64 wallet xref probe for libMyPonyWorld.so.

This is an evidence collector, not a patcher: it resolves ADRP+ADD/LDR references
to wallet-related strings, prints the full instruction context, and lists nearby
stores with their base register and displacement. It deliberately does not guess
a currency object offset or modify the binary.
"""
import argparse
import re
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

TERMS = (
    "Native_BuyCurrency", "Native_BuyPremiumCurrency", "Native_BuyTlsCurrency",
    "SetCurrencyData", "ResetCurrency", "SpendBits", "SpendGems",
    "SoftCurrency", "HardCurrency", "Total_Currency_Soft",
    "Total_Currency_Hard", "Spent_Currency_Soft", "Spent_Currency_Hard",
    "bits_amount", "gems_amount", "bits_limit", "gems_limit",
    "PlayerData", "Currency", "currency", "Bits", "Gems",
    "SoftCost", "HardCost", "CurrencyCount", "FreeCash", "FreeCoins",
)

def imm(s):
    s = s.strip().lstrip("#")
    return int(s, 0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--context", type=int, default=18)
    ap.add_argument("--out", default="report/wallet-probe.txt")
    args = ap.parse_args()

    with open(args.elf, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".text")
        ro = elf.get_section_by_name(".rodata")
        if sec is None or ro is None:
            raise SystemExit("ELF must contain .text and .rodata")
        code, base = sec.data(), sec["sh_addr"]
        rd, rbase = ro.data(), ro["sh_addr"]

    targets = {}
    for term in TERMS:
        needle = term.encode()
        start = 0
        while True:
            p = rd.find(needle, start)
            if p < 0:
                break
            targets[rbase + p] = term
            start = p + 1

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    ins = list(md.disasm(code, base))
    by_addr = {x.address: i for i, x in enumerate(ins)}
    refs = defaultdict(list)
    # Register -> (ADRP page, instruction index); retain until overwritten.
    pages = {}
    for i, x in enumerate(ins):
        m, op = x.mnemonic, x.op_str
        parts = [p.strip() for p in op.split(",")]
        if m == "adrp" and len(parts) == 2:
            try:
                pages[parts[0]] = (imm(parts[1]), i)
            except ValueError:
                pages.pop(parts[0], None)
        elif m == "add" and len(parts) >= 3 and parts[1] in pages:
            try:
                va = pages[parts[1]][0] + imm(parts[2])
                if va in targets:
                    refs[va].append((i, "ADRP+ADD"))
            except ValueError:
                pass
        elif m.startswith("ldr") and len(parts) >= 2:
            mm = re.search(r"\\[\\s*(x\\d+|w\\d+)\\s*,\\s*(#[^\\]]+)\\]", parts[1])
            if mm and mm.group(1) in pages:
                try:
                    va = pages[mm.group(1)][0] + imm(mm.group(2))
                    if va in targets:
                        refs[va].append((i, "ADRP+LDR"))
                except ValueError:
                    pass
        # A destination register is redefined by most data-processing/load ops.
        if parts and m not in ("cmp", "cmn", "tst", "str", "stp", "stur", "bl", "b"):
            dest = parts[0]
            if dest in pages and m not in ("adrp",):
                pages.pop(dest, None)

    lines = []
    lines.append(f"ELF: {args.elf}")
    lines.append(f".text VA=0x{base:x}, bytes={len(code)}, instructions={len(ins)}")
    lines.append(f".rodata VA=0x{rbase:x}, bytes={len(rd)}, wallet strings={len(targets)}")
    lines.append(f"Resolved references={sum(map(len, refs.values()))}")
    for va, name in sorted(targets.items(), key=lambda kv: (kv[1].lower(), kv[0])):
        hits = refs.get(va, [])
        lines.append(f"\n### {name} @ 0x{va:x} — {len(hits)} xref(s)")
        for idx, kind in hits:
            lo, hi = max(0, idx-args.context), min(len(ins), idx+args.context+1)
            lines.append(f"\n-- {kind}; reference at 0x{ins[idx].address:x} --")
            for j in range(lo, hi):
                x = ins[j]
                mark = ">>" if j == idx else "  "
                lines.append(f"{mark} 0x{x.address:x}: {x.mnemonic} {x.op_str}")
    # Store inventory around all functions containing wallet-string references.
    func_stores = set()
    for hits in refs.values():
        for idx, _ in hits:
            for x in ins[max(0,idx-80):min(len(ins),idx+80)]:
                if x.mnemonic.startswith(("str","stp","stur")):
                    func_stores.add((x.address,x.mnemonic,x.op_str))
    lines.append("\n### Nearby store instructions (context only; offsets are not presumed wallet fields)")
    for addr,m,op in sorted(func_stores):
        lines.append(f"0x{addr:x}: {m} {op}")
    with open(args.out, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
    print(f"wallet-probe: {len(targets)} strings, {sum(map(len,refs.values()))} references, {len(func_stores)} nearby stores -> {args.out}")

if __name__ == "__main__":
    main()
