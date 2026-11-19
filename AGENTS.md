# Repository Guidelines

## Project Structure

- `app/src/main/java/com/passwordprotection/vault/` contains the Android Compose UI, device authentication, encrypted storage, and backup encoding and cryptography. The manifest and resources live under `app/src/main/`.
- `shared/src/commonMain/kotlin/com/passwordprotection/core/` contains platform-independent vault rules, models, and password generation. Keep Android APIs in `app`.
- `tests/Smoke.kt` is the standalone JVM smoke suite. See `docs/SECURITY-AND-PRODUCT.md` for the threat model and release gates.

## Build and Run

Use JDK 17 and Android SDK 35. The Gradle wrapper pins version 8.11.1. From the repository root, run `./gradlew :app:assembleDebug` to build the debug APK and `./gradlew :app:lintDebug` for Android lint. To launch it, sync in Android Studio and run the `app` debug configuration on an Android 11+ emulator or device.

## Coding Style

Follow the official Kotlin style configured in `gradle.properties`. Use four spaces, `UpperCamelCase` for types and Compose UI functions, `lowerCamelCase` for other functions and properties, and lowercase package names. Name files after their main type or purpose, such as `Vault.kt` or `BoundedRead.kt`.

## Testing

Run `./gradlew :shared:smokeTest` from the repository root. Alternatively, use `kotlinc` and Java directly.

```sh
kotlinc shared/src/commonMain/kotlin/com/passwordprotection/core/Vault.kt \
  app/src/main/java/com/passwordprotection/vault/Aead.kt \
  tests/Smoke.kt -include-runtime -d /tmp/passwordprotection-smoke.jar
java -jar /tmp/passwordprotection-smoke.jar
```

The suite uses Kotlin `check` assertions for vault behavior, password generation, and authenticated backup handling. The project has no configured coverage threshold. Use Android device tests for changes to Keystore, lifecycle locking, Argon2id, or storage. Use synthetic credentials and recovery keys throughout validation.

## Commits and Pull Requests

This checkout has no Git history to establish a convention. Use short imperative commit subjects and keep changes focused. In pull requests, describe the change, list checks run and any skipped validation, link the relevant issue if available, and include screenshots with dummy data for visible UI changes.

## Security and Recovery

Review the threat model before changing authentication, cryptography, or backup formats. Keep the offline build free of `INTERNET` permission. Preserve free manual encrypted export and recovery, authenticate imports before parsing payloads, and restore only into an empty vault. Keep vault data, credentials, and recovery keys out of logs and commits.
