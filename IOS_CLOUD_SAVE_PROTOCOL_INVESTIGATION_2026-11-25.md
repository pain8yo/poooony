# iOS cloud-save protocol investigation — 2026-11-25

## Target

Historical iOS profile requested by the owner:
- Friend Code: `d0ccf1`
- Game Center identity: `_molotkova_`
- Last confirmed progress: level 109+
- Required result: the original server-side save blob and its complete pony/building/shop/quest inventory, not a reconstructed profile.

## Evidence recovered from the uploaded iOS app string dump

The Library artifact `Новый документ.docx.txt` contains extracted strings from the iOS app bundle. Relevant observations:

1. `oconf.bar` contains:
   `XPlayerURL: https://gllive.gameloft.com/ope/GenericXPlayer_v1.php`
2. The main executable string section contains `cloud_userid`.
3. The executable also contains generic Apple networking/security symbols, including `NSURLSessionDownloadTask` and `kSecAttrSynchronizable`.

These observations establish that the app bundle contains an XPlayer social-service URL and a cloud-related identifier string. They do **not** establish that XPlayer serves game-save blobs, that `cloud_userid` is the historical account key, or what request/response fields the save service requires. Generic NSURLSession symbols alone do not identify the save endpoint.

## Cross-check against the Android 11.5.0o work in this repository

The Android native-library investigation has identified currency/configuration strings and bridge registrations, but no confirmed save-download API or authenticated save retrieval function. The Android findings cannot be treated as proof of the older iOS save protocol.

## Current retrieval status

- No authenticated response containing Friend Code `d0ccf1` has been obtained.
- No original cloud-save blob or metadata record has been retrieved.
- No decryption key/algorithm for the historical cloud blob has been established.
- No file produced from the available evidence can honestly be labelled the original server save.

## Next technical gate

A real protocol trace or disassembly around the iOS code paths that read/write `cloud_userid` is required to identify:
- the actual save service host and path;
- request method, parameters, and authentication/signature;
- account identifier mapping (Game Center / GLUID / cloud_userid / Friend Code);
- response format and save-blob location.

Until those are identified, sending guessed requests to the XPlayer URL would not retrieve the historical save and could not justify creating a purported original save file.
