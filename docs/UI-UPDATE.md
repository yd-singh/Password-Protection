# UI and recovery update — 19 November 2026

The introduction now explains the everyday problem the app solves, what a vault is, and why a backup needs a separate recovery phrase. The four-page technical guide is replaced by two shorter pages. Settings and buttons use plain language; Android key-storage diagnostics remain available under Technical details.

The vault uses a compact toolbar, shorter search field, denser entry rows, direct password copy, and a floating Add item action. Editing keeps Save visible, collapses extra details, validates the name beside its field, and confirms before discarding changes. It explains that leaving the app locks the vault and clears unfinished edits. Routine confirmations use temporary snackbars.

Backup creation is a full-screen flow: save the file, keep its numbered recovery words, then acknowledge the matching file/key pair. The alternative compact code is optional. File saving, provider readback, and an actual recovery test are described separately. Recovery test timestamps now use dedicated preferences; legacy timestamps that could represent provider readback are intentionally not carried forward.

## Restore navigation regression

Opening Android’s file picker locks the vault. Previously, the chosen backup stayed in memory but unlocking returned to the vault list, hiding the recovery input in Settings.

A selected backup now produces a persistent explanation on the locked screen. Both phone-only and passphrase unlock install the session through the same function, which resumes the Backup & recovery page when an import is pending. The recovery field appears first, above backup creation controls, and accepts multiple lines. Cancel restore clears the selected backup.

## Validation

- `:app:assembleDebug`, `:app:lintDebug`, and `:shared:smokeTest` pass. Android lint reports no issues.
- Ad hoc API 35 emulator checks with synthetic data: onboarding, vault creation, generated login, direct copy, inline name validation, Android Back from details, discard confirmation, backup file saving, all 33 numbered recovery words, acknowledgement gating, background locking, matching recovery-key verification, and rejection of a wrong recovery key without changing the vault.
- Revised light-theme green, blue, and amber text exceed 4.5:1 on white and the elevated surface. Primary button text inherits its proper content color; custom lock and selection controls have at least 48dp targets.
- The delivered app retains `FLAG_SECURE`; its merged manifest has no INTERNET permission. Encryption formats and authentication requirements are unchanged.

Screenshots in `ui-review/` use only synthetic data from an isolated emulator-only package. That temporary preview permits screen capture; the delivered APK does not. The attached user photo and recovery phrases are not included in the repository.

The exact file-picker regression passed: choose a saved file, see the persistent locked-screen explanation, unlock, enter the phrase directly without navigating or scrolling, and complete a successful recovery test. See `ui-review/04-restore-after-unlock.png` and `ui-review/02-vault.png`.

Changing system text size recreates the activity and locks the vault, discarding the in-memory file selection. Full large-text recovery, physical-device biometrics, TalkBack testing, and the complete device/lifecycle release matrix remain outside this UI pass.

## Consistent home navigation

The main header now always reads Password Protection. How this app works is visible on both the locked home screen and the unlocked vault home, including an empty vault. Settings sits alongside the guide link on the unlocked home. Reopening the guide after creating a vault uses Close/Done rather than asking the user to set up a vault again. Earlier screenshots above predate this header adjustment.
