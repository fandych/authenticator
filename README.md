# FUN Authenticator

A native HarmonyOS phone port based on the behavior and backup format of [Stratum Authenticator](https://github.com/stratumauth/app). This project targets phones and tablets; the upstream Wear OS companion is not included.

## Features

- TOTP and HOTP using SHA-1, SHA-256, or SHA-512, plus mOTP, Steam Guard, and Yandex OTP.
- Manual setup, QR scanning, and account QR display for `otpauth://`, `motp://`, and Google Authenticator migration URIs.
- HarmonyOS-styled account lists, native settings rows, adaptive colors, category and action menus, and sorting.
- Search, categories, custom ordering, default/compact/tile views, code grouping, dark mode, and tap-to-copy with toast feedback.
- Android's 793-light/237-dark service icon catalog, Stratum icon-pack import and management, account icon selection, and custom image icons.
- Direct backup import from andOTP, FreeOTP, FreeOTP+, Aegis, Bitwarden, Ente Auth, Proton Authenticator, WinAuth, 2FAS, KeePass, LastPass, TOTP Authenticator, Authenticator Plus, and URI-list files.
- Encrypted FUN `.funbackup` export and restore using Argon2id/AES-GCM; legacy `.authpro` and Stratum backups remain available as separate import paths.
- Backup imports merge with the local vault; an existing authenticator with the same secret is updated rather than deleting unrelated local records.
- Offline code generation. No Internet permission is requested.

FUN backups use a versioned, app-specific encrypted envelope. Argon2id retains its 64 MiB/three-iteration/four-lane parameters and uses the native Rust binding for faster derivation. Legacy backup JSON parsing runs in HarmonyOS TaskPool, and legacy PBKDF2 uses the asynchronous CryptoKit API.

Account data is stored in the application's private preferences area. HarmonyOS system backup/restore is disabled so that secrets are not included in an unencrypted system backup. The app encrypts exported backups; it does not currently encrypt the local preferences file with a separate user password.

## Known gaps

This is not yet a one-to-one port of every upstream screen and converter. Wear OS and password/biometric database protection are not included yet. The four import entries that Android presents as web guides (Google Authenticator, Authy, Steam, and Blizzard) open their respective guides; Google migration QR import is supported directly.

Authenticator Plus imports use its SQLCipher v3 parameter profile through HarmonyOS RelationalStore. A real Android export is still needed to verify interoperability with that encrypted database format.

## Build and tests

The project-level `build-profile.json5` is local-only because it contains signing configuration. Copy `build-profile.json5.example` to `build-profile.json5`, then configure signing in DevEco Studio under **Project Structure > Signing Configs**. Do not commit certificates, keystores, or the generated local build profile.

Install dependencies with DevEco Studio's OHPM, then build the native HarmonyOS package:

```powershell
$env:DEVECO_SDK_HOME = 'C:\Program Files\Huawei\DevEco Studio\sdk'
& 'C:\Program Files\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.bat' assembleHap
```

The Hypium local test target can be compiled with:

```powershell
& 'C:\Program Files\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.bat' --mode module -p module=entry@default -p product=default -p isLocalTest=true -p unitTestMode=true UnitTestBuild
```

To run the `ohosTest` Hypium suite on a connected emulator without a signing profile:

```powershell
$env:DEVECO_SDK_HOME = 'C:\Program Files\Huawei\DevEco Studio\sdk'
& 'C:\Program Files\Huawei\DevEco Studio\tools\hvigor\bin\hvigorw.bat' --mode module -p module=entry@ohosTest -p product=default assembleHap
$hdc = 'C:\Program Files\Huawei\DevEco Studio\sdk\default\openharmony\toolchains\hdc.exe'
& $hdc -t 127.0.0.1:5555 install -r 'entry\build\default\outputs\ohosTest\entry-ohosTest-unsigned.hap'
& $hdc -t 127.0.0.1:5555 shell aa test -b com.fandy.authenticator -s unittest OpenHarmonyTestRunner -m entry_test -s timeout 360000
```

The test HAP and unsigned main HAP are for local emulator testing only. Native HarmonyOS builds produce HAP packages, not Android APKs.

## Paired URI import verification

A locally generated synthetic TOTP URI was imported through Android's `otpauth://` `ACTION_VIEW` deep link and the HarmonyOS editor's Advanced URI parser. Issuer, username, SHA-1, six digits, and the 30-second period matched; the codes also matched within the same 30-second UTC window. The synthetic entries were removed afterward, Android screenshot protection was restored, and the pre-existing HarmonyOS emulator test record was preserved.

## License and attribution

This port follows the upstream project's GPL-3.0 license. See [LICENSE](./LICENSE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md). Any public binary distribution must include the complete corresponding source and applicable notices.
