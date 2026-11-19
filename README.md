# Password Protection — Android development preview

Native Kotlin / Jetpack Compose. Shared Kotlin Multiplatform domain module (JVM and, on macOS, iOS targets). **Not production-ready, not security audited. Do not enter real passwords until the Android build, lifecycle, recovery and independent security tests pass.**

## Screenshots

Captured on an Android 15 (API 35) emulator using synthetic demo data from an isolated `uireview` build (the delivered app retains `FLAG_SECURE` to block screen capture). See [docs/UI-UPDATE.md](docs/UI-UPDATE.md) for recent UI & recovery notes.

| Screen | Preview |
| --- | --- |
| Onboarding — Welcome | [01-onboarding-welcome.png](docs/ui-review/01-onboarding-welcome.png) |
| Onboarding — Backup & Recovery | [02-onboarding-recovery.png](docs/ui-review/02-onboarding-recovery.png) |
| Create Vault | [03-create-vault.png](docs/ui-review/03-create-vault.png) |
| Vault List (Light) | [04-vault-list.png](docs/ui-review/04-vault-list.png) |
| Add / Edit Item | [05-add-edit-item.png](docs/ui-review/05-add-edit-item.png) |
| Item Details | [06-item-details.png](docs/ui-review/06-item-details.png) |
| Settings Hub | [07-settings-hub.png](docs/ui-review/07-settings-hub.png) |
| Backup & Recovery | [08-backup-restore.png](docs/ui-review/08-backup-restore.png) |
| Locked Home Screen | [09-locked-home.png](docs/ui-review/09-locked-home.png) |
| Vault List (Dark) | [10-dark-theme-vault.png](docs/ui-review/10-dark-theme-vault.png) |

## Open on macOS

Open this folder in Android Studio. Use JDK 17 and Android SDK 35. The bundled Gradle wrapper pins Gradle 8.11.1 and verifies its distribution checksum. With the Android command-line tools available, install the required SDK packages with `sdkmanager 'platforms;android-35' 'build-tools;35.0.0'`. Set `ANDROID_HOME` to that SDK directory, or configure `sdk.dir` in an untracked `local.properties` file. Sync and run the `app` debug configuration on Android 11+.

From the project root, run the following checks.

```sh
./gradlew :shared:smokeTest :app:assembleDebug :app:lintDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`. Install on a selected test device with `adb -s <serial> install -r app/build/outputs/apk/debug/app-debug.apk`, then launch `com.passwordprotection.vault/.MainActivity`.

On 19 November 2026, the wrapper build and JVM smoke suite passed on this Mac with JDK 17 and SDK 35. Android lint reported zero errors and zero warnings. `:app:testDebugUnitTest` currently reports `NO-SOURCE`. The development preview still requires the security and device validation described below.

### Emulator baseline

Ad hoc scripted checks passed on an Android 15 / API 35 emulator using synthetic data.

- Standard-mode creation, PIN unlock, add/edit, password generation, masked secrets, history clearing, and locking after a completed background transition.
- Explicit free Pro upgrade/downgrade with Basic manual backup access retained.
- Encrypted export through the system file picker, verification of the saved file with its matching recovery key, wrong-key rejection, and disabled restore into a nonempty vault.
- Restore into an empty vault, then recovery after clearing the preview's synthetic app data and creating a new Maximum-mode vault.
- Actual Argon2id execution, wrong-passphrase rejection, successful retry, and absence of the dummy title and username in the local encrypted vault file.

These emulator checks are separate from the committed JVM smoke suite. Physical-device biometrics, the Android 11+ lifecycle matrix, known cryptographic vectors, interrupted-write tests, and independent security review remain pending. SDK 35 and the test AVD were staged under `/private/tmp` for this run. Follow the SDK setup above for a lasting local installation.

## Included in source

- Local encrypted vault and device-credential/strong-biometric authentication (time-bound Android Keystore key, with a bounded lifecycle guard for device-credential fallback transitions and Keystore invalidation diagnostics).
- Optional strong passphrase at creation (Argon2id, additional authenticated wrapping layer) plus authenticated mode switching and passphrase rotation (`rekey`).
- Passwords, secure notes, add/edit/delete, search, categories, favourites, random password and word-based passphrase generators, password history and history deletion.
- Per-record in-memory session sealing (`SessionVault`), device lock/background protection, `FLAG_SECURE`, clipboard marking and best-effort delayed clear, exclusion from system backup; no `INTERNET` permission or analytics.
- Manual authenticated encrypted export and restore into an empty vault, plus a verified-backup reset/recovery flow for invalidated keys or replacing an existing vault. Recovery keys are supported in both canonical base64url and 33-word mnemonic recovery kit formats; no plaintext export.
- Multiplatform domain logic and v1 JSON vault serialization (`VaultCodec`) in `:shared`.
- Debug-only Basic/Pro switch with explicit free upgrade/downgrade. No billing. Basic retains backup/export and restore. Pro adds offline short/reused-password checks, non-destructive recovery verification, and automatic verified local encrypted snapshots using an independent wrapped backup key (max 5 retained).

## Still to build / validate

- Real Google Drive appDataFolder integration, OAuth consent/client configuration, and remote backup retention. No fake cloud integration or network permission in this preview. Plan a separate network-enabled application variant.
- Full iOS application and iOS AES-GCM/Argon2id cryptography plus cross-platform backup interoperability tests.
- Production entitlement and billing (free upgrade is debug-only). Accessibility, full autofill/IME suppression verification, UI polishing, and full security testing.
- Physical-device validation of the Android 11+ lifecycle matrix (biometric vs. device credential fallback) and Keystore hardware security levels; the 10-second Keystore authorization window is a deliberate preview implementation, not per-operation biometric binding.
- Even with `SessionVault` sealing inactive entries in memory, managed JVM strings for active UI fields and unlocked transient materialization cannot be reliably wiped. Do not rely on this against root, malicious IMEs/accessibility or a compromised OS.
- Hardened cryptographic format review, known Argon2id vector tests, atomic file crash tests, backup write cancellation, authentication invalidation, strong passphrase retry, malformed import, and power-loss tests. Old backups can contain deleted entries.

## JVM smoke test

Run `./gradlew :shared:smokeTest` to compile and execute the existing suite with the project's Kotlin version. This task needs JDK 17 and the Android SDK for project configuration. It compiles the shared core and the portable AEAD implementation, keeping the Android UI and Keystore outside its scope.

Alternatively, with a standalone Kotlin compiler installed, run the original commands.

```sh
kotlinc shared/src/commonMain/kotlin/com/passwordprotection/core/Vault.kt app/src/main/java/com/passwordprotection/vault/Aead.kt tests/Smoke.kt -include-runtime -d /tmp/passwordprotection-smoke.jar
java -jar /tmp/passwordprotection-smoke.jar
```

Tests cover core model, password/passphrase generators, 33-word recovery kit, multiplatform JSON codec and validation, `SessionVault` sealing, AES-GCM backup roundtrip, randomized ciphertext, incorrect key, tamper rejection, truncation and AAD mismatch. They do not cover Android Keystore, Argon2id dependency execution, Compose or Android storage.
