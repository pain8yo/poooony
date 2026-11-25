# GBox no-root currency-modification route — 2026-11-25

## User's intended workflow

The target is the already-installed MLP 11.5.0o instance inside GBox, which the user reports has loaded the same cloud profile as the tablet's native installation. Do not create or install a second modified MLP APK. Keep the native tablet installation untouched until cloud sync is deliberately tested.

## New finding: no-root memory editing is a documented mode

GameGuardian's own documentation says it can work in limited mode without root through a virtual environment, provided **both the game and GameGuardian are installed/launched inside that same virtual environment**. It explicitly warns that not all features work and compatibility depends on the virtual-space implementation and firmware.

Source: https://docs.gameguardian.net/help.html (section “Work without root”).

This directly supports testing GBox as the execution container rather than assuming Android root is mandatory. It does not yet prove GBox supports the process/memory hooks GameGuardian needs.

## GBox installation behavior

GBox's official help says apps can be installed inside GBox by turning off “Install to Device” in Settings / Advanced Settings. Its official channel announced APK/APKS/XAPK import support in GBox 1.5.3.8.

Sources:
- https://hms.kb.help/how-to-clone-or-install-app-inside-gbox/
- https://t.me/s/gboxlab/144

The user's earlier attempt to open an XAPK with an external installer did not test GBox's own import path. Avoid repeating that same external-installer flow. The already-existing GBox MLP clone should remain in place.

## Reverse-engineering evidence already established for MLP 11.5.0o

Repository reports:
- ANDROID_11_5_0O_APK_ANALYSIS_2026-11-25.md
- ANDROID_CURRENCY_XREF_FOLLOWUP_2026-11-25.md

Confirmed native library strings include:
- Native_GetInventory
- Native_BuyCurrency
- Native_BuyPremiumCurrency
- ResetCurrency
- SpendBits
- SpendGems
- SetCurrencyData
- bits_amount / gems_amount

The loader at VA 0x243e50 reads bits_amount and gems_amount into object fields +0x210 and +0x214. This object is not yet proven to be the live wallet. Native bridge registration names are known, but their function pointers/signatures are not yet resolved. No safe direct native setter is established.

## Test plan (non-destructive first)

1. Preserve the native tablet MLP install and its current local data.
2. Use the existing GBox MLP instance as the target; do not create another MLP copy.
3. Test whether GBox can host GameGuardian as an in-container app, with both apps running in GBox. GameGuardian must be the app's no-root/virtual-space mode; installing GG only on the host Android side is not equivalent.
4. If GBox exposes the MLP process to GG, first perform a read-only value-identification test on a reversible, ordinary in-game balance change. Do not freeze/write values until the correct representation and process are confirmed.
5. If memory editing works, test persistence only within GBox and confirm the balance after a full game restart.
6. Do not trigger cloud upload from the experimental GBox instance until local persistence is proven. Cloud sync may overwrite the native save or the server may reject/normalize modified values.
7. If GBox does not expose the process or GG reports unsupported process/daemon errors, treat that as a GBox compatibility failure, not proof that root is required on Android generally. At that point trace GBox-specific support or move to a different compatible virtual space only with the user's approval.

## Current status

- A no-root virtual-environment method is documented by GameGuardian.
- GBox has documented in-container installation/import mechanisms.
- Compatibility between GBox and GameGuardian on this Huawei/Android setup is **not yet tested**.
- No currency has been changed; no save/cloud data has been modified.
- No standalone companion APK is being represented as functional until an actual read/write channel to the GBox-hosted game is demonstrated.
