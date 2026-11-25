# GameGuardian 102.0 APK inspection and GBox compatibility assessment
Date: 2026-11-25

## Retrieved user-uploaded APK

Recovered from the user's ChatGPT Library; no re-upload required.

- File: `GameGuardian-102.0.apk`
- Size: 17,597,919 bytes (17.6 MB)
- SHA-256: `60a7760873ca00cc5eb7c24b8a3eefd85ea4cf37356882e7b12b39f7df276ad5`
- APK contains `classes.dex`, binary AndroidManifest.xml, resources, and 774 ZIP entries.
- Manifest strings identify app/version as GameGuardian 102.0; application package base string is `catch_.me_.if_.you_.can_` (GG uses randomized package identity during its self-reinstall flow).
- DEX contains ARM64 support strings and GameGuardian memory APIs, including `gg.searchNumber`, `gg.getResults`, `gg.editAll`, `gg.dumpMemory`, `gg.copyMemory`, `gg.processResume`.
- DEX includes a no-root/virtual-space implementation path and daemon/bootstrap code. It also includes root-probe/fallback paths.
- No `lib/` native-library directory is packaged in this APK. Do not mistake strings mentioning `lib/arm64-v8a/libAndroid.so` for an embedded file; the ZIP has no such entry.

## Official GameGuardian no-root requirements

Official documentation explicitly says limited no-root operation is possible through a virtual environment; **both GameGuardian and the game must be installed inside that same virtual environment**. Some features are unavailable. The first launch that performs GameGuardian's randomized self-reinstall must happen outside the virtual environment; after that, add the randomized GG app to the virtual environment.

Official source: https://docs.gameguardian.net/help.html ("Work without root").

The official Russian no-root page also warns that compatibility is not universal, some virtual spaces/firmware fail, and errors 105/106 or an absent target process indicate that the no-root environment is unsupported on that setup:
https://gameguardian.ru/noroot.html

## Assessment for this exact setup

Known:
- User's tablet: Huawei MatePad 11.5S 2026, Android 12 / EMUI 15, non-root.
- Target game: MLP 11.5.0o, package `com.gameloft.android.ANMP.GloftPOHM`, already installed and running as a GBox-hosted clone.
- GG APK version 102.0 has the required memory-search/edit API and an implemented virtual-environment/no-root path.
- No root is required in principle if the virtual space successfully hosts both applications and exposes the game's process.

Not yet provable from static APK analysis:
- Whether GBox on this Huawei firmware exposes the MLP process to GG's no-root daemon.
- Whether GG can attach to this specific GBox instance.
- Whether MLP's currency values are locally writable and persist, or are restored by Gameloft cloud/server state.

GBox is not named among the explicitly tested examples in GG's official docs. Thus compatibility must be determined by a live process-list/attach test in GBox; APK inspection cannot honestly certify it.

## Correct non-destructive test sequence

1. Keep the native tablet MLP installation untouched.
2. If GG 102.0 has not yet completed its first-run self-reinstall, install and launch the uploaded APK once in the host Android environment and complete its randomized-package installation. Do not grant root.
3. Add the resulting randomized GameGuardian app into the existing GBox environment. Do not create another MLP clone.
4. Ensure the existing MLP clone and GG are both inside the same GBox space. Start GG from GBox, then launch the already-existing MLP clone from GBox.
5. Open GG's process selector. The first compatibility checkpoint is whether `com.gameloft.android.ANMP.GloftPOHM` (or the GBox-wrapped process representing it) appears.
6. If it appears, select it and verify that GG reports a usable process/memory map. Do not write values yet. If it does not appear, or GG reports errors 105/106, record the exact error: this establishes a GBox/firmware no-root incompatibility, not a problem with the APK file.
7. Only after successful attach, do a reversible read-only value search in GBox. Currency mutation and cloud sync are separate later tests. Do not upload experimental state to the shared cloud profile before local persistence and server behavior are understood.

## Current result

- The exact user-uploaded GG 102.0 APK was recovered and statically inspected.
- It contains the required GameGuardian search/edit functionality and a no-root virtual-environment code path.
- The user's proposed GBox method is technically plausible and is the correct path to test.
- **GBox compatibility is not yet verified** because this environment cannot launch apps on the user's tablet or inspect GBox's live process list.
- No values, saves, or cloud account state were modified.
