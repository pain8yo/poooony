# Android 11.5.0o APK inspection (2026-11-25)

## Input package

- Uploaded file: `com.gameloft.android.ANMP.GloftPOHM-1150015_arm64-v8a.xapk`
- XAPK SHA-256: `9008ae89bc31a3319315dbf786e1b7ef0f2575c2f65d95f1c6f778e38da9f285`
- Package: `com.gameloft.android.ANMP.GloftPOHM`
- Split APKs: `base.apk`, `split_config.arm64_v8a.apk`, `split_config.xxhdpi.apk`
- Native library: `lib/arm64-v8a/libMyPonyWorld.so`, 25,022,024 bytes
- Library SHA-256: `887653e267b0c06b34dc8250de1194744ce6a424eb6299c5b1721ee8c88d0dbd`
- ELF: 64-bit AArch64, Android API 21+, stripped, BuildID `1ee78c4005d9767767de1126aa1fcfa592b7fb4b`

The extracted native library is byte-for-byte identical to the existing repository file `libMyPonyWorld.so` (Git blob SHA-1 `2f25d2a4d9e1be4f172a7d4f8c25360eafc69a2a`). Therefore the native binary itself is already present in this repository; the full 111 MB XAPK was not uploaded through the available GitHub connector.

## Confirmed strings and code references

The native binary contains these exact NUL-terminated strings in `.rodata`:

| String | VA |
|---|---:|
| `bits_amount` | `0x116221a` |
| `gems_amount` | `0x1162226` |
| `bits_limit` | `0x1162276` |
| `gems_limit` | `0x1162281` |
| `Native_GetInventory` | `0x11638ef` |
| `Native_BuyCurrency` | `0x1165c84` |
| `Native_BuyPremiumCurrency` | `0x1165c97` |
| `SetCurrencyData` | `0x117b2ca` |
| `ResetCurrency` | `0x117aa91` |
| `SpendBits` | `0x117aac2` |
| `SpendGems` | `0x117aae8` |

AArch64 ADRP/ADD references to `bits_amount` and `gems_amount` occur in the code around `0x243ea8–0x243f18`. In that sequence the strings are passed to helper routines, and returned 32-bit values are stored at offsets `+0x210` and `+0x214` from the object held in `x19`. This establishes a concrete data-loading path for the two currency fields, but does **not** yet prove that these are writable live-wallet fields or that modifying them will persist.

The `bits_limit` and `gems_limit` strings are referenced around `0x24418c–0x2441f8`; values are written to object-relative storage in that path as well.

The strings `Native_BuyCurrency` and `Native_BuyPremiumCurrency` are registered/referenced around `0x2a799c–0x2a79c0` and `0x2a91d4–0x2a91e8`. These are script/native bridge registration paths, not proof that invoking them grants currency.

## Important correction / status

- The strings are real, but they are not exported C functions. The ELF dynamic symbol table does not expose native functions named `Native_BuyCurrency`, `Native_BuyPremiumCurrency`, or `SetCurrency`.
- The earlier claim that a usable `SetCurrency` function had been identified was too strong; no such confirmed callable function has been established.
- No patch has been applied to the APK or the installed game.
- No account, save, server endpoint, or currency balance has been modified.
- A functional currency modification still requires tracing the object and write path, determining whether wallet values are locally authoritative or server-restored, and validating persistence safely. The current evidence is insufficient to produce a working mod APK.

## Reproduction commands

```sh
unzip -p split_config.arm64_v8a.apk lib/arm64-v8a/libMyPonyWorld.so > libMyPonyWorld.so
readelf -h libMyPonyWorld.so
readelf -Ws libMyPonyWorld.so
strings -a -n 5 libMyPonyWorld.so
llvm-objdump -d libMyPonyWorld.so
```
