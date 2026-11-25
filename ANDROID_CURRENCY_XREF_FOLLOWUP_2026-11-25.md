# Follow-up: currency loader and native bridge registration

Date: 2026-11-25
Input: the user-provided XAPK 11.5.0o, split `split_config.arm64_v8a.apk`.

## Verified loader path

The AArch64 routine beginning at VA `0x243e50` reads the wallet-like configuration keys:

- `bits_amount` at VA `0x116221a`
- `gems_amount` at VA `0x1162226`

At `0x243ea8–0x243ee0`, the routine passes the `bits_amount` key through the game's configuration accessor helpers and stores the resulting 32-bit value at `[x19 + 0x210]`.

At `0x243ee4–0x243f18`, it does the same for `gems_amount`, storing the 32-bit value at `[x19 + 0x214]`.

The surrounding routine also loads other configuration fields and builds two dynamic integer arrays at object offsets `+0x220` and `+0x238`. The object is therefore a configuration/data object, not yet proven to be the live player wallet.

## Native bridge registration

A routine around `0x2a9190–0x2a92xx` passes a sequence of string names to a registration helper at `0x2c7090`. Two entries are:

- `Native_BuyCurrency` at VA `0x1165c84`
- `Native_BuyPremiumCurrency` at VA `0x1165c97`

This proves the names are registered with the script/native bridge. The target native function pointers are not resolved by this string-only registration sequence; no safe callable entry point has been identified yet.

## Other currency-related names

Exact strings in `.rodata`:

- `ResetCurrency` VA `0x117aa91`
- `SpendBits` VA `0x117aac2`
- `SpendGems` VA `0x117aae8`
- `SetCurrencyData` VA `0x117b2ca`

The routine around `0x1dd1f4–0x1dd2c4` constructs/registers static string objects for `SetCurrencyData` and other keys. This is not itself evidence of a write operation.

## What this establishes—and what it does not

Established:
1. The Android 11.5.0o native library contains real configuration keys for bits and gems.
2. It has a loader path that reads those keys into a C++ object at offsets +0x210 and +0x214.
3. It registers currency-related native bridge names.

Not established:
1. That +0x210/+0x214 are the active in-game balance fields.
2. That changing these values survives a server refresh or save/load.
3. The implementation address/signature of a working setter.
4. A safe patch point for a working mod APK.

No binary patch or APK rebuild has been made. This report intentionally does not label a nonfunctional APK as a currency mod.
