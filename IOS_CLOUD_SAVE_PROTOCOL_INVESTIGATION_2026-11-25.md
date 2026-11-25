# iOS cloud-save server investigation — 2026-11-25

## Target profile

- Historical Friend Code: `d0ccf1`
- Original platform: iOS
- Game Center identity: `_molotkova_`
- Last proven progress: level 109+
- Required output: the historical server-side cloud save with the original pony/building/shop/quest inventory, not a reconstructed profile.

## Server endpoint

The iOS app configuration dump contains this configured endpoint in `oconf.bar`:

`https://gllive.gameloft.com/ope/GenericXPlayer_v1.php`

For this investigation, this is treated as the game's cloud-save server endpoint, as identified by the account owner. The endpoint's presence is confirmed in the app configuration. The exact operation names, request fields, authentication/signature, account-ID mapping, and response/blob format still need to be recovered from the client implementation or a captured request.

## Related client-side evidence

The extracted iOS executable strings include `cloud_userid`, and generic networking symbols such as `NSURLSessionDownloadTask`. This is useful evidence for locating the client code path, but does not by itself reveal the wire protocol.

The public GLLib XPlayer reference documents a login/registration flow (`sendLogin` / `handleLogin`) and a player-data parameter. It is a lead for understanding the XPlayer protocol, not proof of the exact MLP save request fields.

## Current retrieval status

- The configured server endpoint has been identified.
- No successful authenticated request for Friend Code `d0ccf1` has yet been made.
- No response containing the historical save metadata or blob has been retrieved.
- The exact mapping between Friend Code, Game Center identity, `cloud_userid`, and any GLUID is not yet established.
- The historical blob's encoding/encryption and matching key have not been established.
- No file produced so far can honestly be labelled the original cloud save.

## Required protocol extraction

Inspect the iOS executable around references to:
- `cloud_userid`
- `GenericXPlayer_v1.php`
- request construction and form/POST serialization
- response parsing and save download/upload callbacks
- Game Center identity and account registration/login mapping

Recover the actual request contract before attempting the read operation for the historical account. Do not send guessed write, overwrite, migration, or delete operations. Preserve any existing local save and current account.
