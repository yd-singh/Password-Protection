package com.passwordprotection.vault

import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Snackbar
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.passwordprotection.core.Entry
import com.passwordprotection.core.Generator
import com.passwordprotection.core.Kind
import com.passwordprotection.core.SecureRandomSource
import com.passwordprotection.core.Vault
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Date
import java.util.UUID
import kotlinx.coroutines.delay

enum class SettingsPage { HUB, CLOUD_SYNC, MANUAL_BACKUP, LOCK_MODE, HEALTH_AND_SNAPSHOTS }

class MainActivity : FragmentActivity() {
    private lateinit var storage: Storage
    private var key: ByteArray? = null
    private var pendingOpened: Storage.Opened? = null
    private var pendingPrepared: Storage.Prepared? = null
    private var sessionVault by mutableStateOf<SessionVault?>(null)
    private var passphraseRequired by mutableStateOf(false)
    private var created by mutableStateOf(false)
    private var showGuide by mutableStateOf(false)
    private var keyInvalidated by mutableStateOf(false)
    private var securityStatus by mutableStateOf<SecurityStatus?>(null)
    private var snapshots by mutableStateOf<List<SnapshotInfo>>(emptyList())
    private var message by mutableStateOf("")
    private var messageIsError by mutableStateOf(false)
    private var busy by mutableStateOf(false)
    private var authInFlight = false
    private var generation by mutableIntStateOf(0)
    private var failed = 0
    private var nextAttempt = 0L
    private var pendingExport: ByteArray? = null // ciphertext only
    private var pendingExportRevision = -1L
    private var pendingImport by mutableStateOf<ByteArray?>(null) // ciphertext only
    private var recoveryKey by mutableStateOf<String?>(null)
    private var recoveryKit by mutableStateOf<String?>(null)
    private var recoveryIsSnapshotSetup by mutableStateOf(false)
    private var backupFileSaved by mutableStateOf(false)
    private var exportPickerActive = false
    private var pendingCloudSyncBlob: ByteArray? = null // ciphertext only
    private var pendingCloudSyncRevision = -1L
    private var pendingRecoveryKeyAfterLink: String? = null
    private var pendingRecoveryKitAfterLink: String? = null
    private var syncUriString by mutableStateOf("")
    private var syncMode by mutableStateOf("")
    private var syncDisplayName by mutableStateOf("")
    private var lastCloudSync by mutableLongStateOf(0L)
    private var lastCloudSyncRevision by mutableLongStateOf(-1L)
    private var cloudSyncError by mutableStateOf("")
    private var syncInProgress by mutableStateOf(false)
    private var setupMaximum by mutableStateOf(false)
    private var setupPass by mutableStateOf("")
    private var setupConfirmation by mutableStateOf("")
    private var setupShowPass by mutableStateOf(false)
    private var themeMode by mutableStateOf(ThemeMode.SYSTEM)
    private var settings by mutableStateOf(false)
    private var settingsPage by mutableStateOf(SettingsPage.HUB)
    private var pro by mutableStateOf(false)
    private var lastExport by mutableLongStateOf(0L)
    private var lastExportRevision by mutableLongStateOf(-1L)
    private var lastVerified by mutableLongStateOf(0L)
    private var lastVerifiedRevision by mutableLongStateOf(-1L)
    private val rng = SecureRandom()
    private val handler = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("nonsecret-settings", MODE_PRIVATE) }
    private val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL

    private val exporter = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        exportPickerActive = false
        val bytes = pendingExport
        val exportedRev = pendingExportRevision
        if (uri != null && bytes != null) {
            try {
                contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: error("No output stream")
                val now = System.currentTimeMillis()
                lastExport = now
                lastExportRevision = exportedRev
                prefs.edit {
                    putLong("lastExport", now)
                    putLong("lastExportRevision", exportedRev)
                }
                backupFileSaved = true
                showStatus("Backup file saved. Next, keep the recovery phrase that opens it.")
            } catch (_: Exception) {
                showStatus("Backup write failed. Keep your older backups safe.", isError = true)
            }
        }
        if (recoveryKey == null) {
            clearBackupExportState()
        }
    }

    private val importer = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            try {
                pendingImport = contentResolver.openInputStream(uri)?.use { stream -> stream.readBounded(16_777_216) }
                    ?: error("Unable to read")
                if (sessionVault != null) {
                    settings = true
                    settingsPage = SettingsPage.MANUAL_BACKUP
                }
                showStatus(if (sessionVault == null) "Backup selected. Unlock your vault to enter its recovery phrase." else "Backup selected. Enter its recovery phrase below.")
            } catch (_: Exception) {
                showStatus("Backup file could not be read.", isError = true)
            }
        }
    }

    private val cloudFileLinker = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        exportPickerActive = false
        if (uri != null) {
            runCatching {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            val name = queryDisplayName(uri, "password-protection-sync.ppvault")
            syncUriString = uri.toString()
            syncMode = "file"
            syncDisplayName = name
            cloudSyncError = ""
            prefs.edit {
                putString("syncUri", syncUriString)
                putString("syncMode", syncMode)
                putString("syncName", syncDisplayName)
                putString("cloudSyncError", "")
            }
            val stagedBlob = pendingCloudSyncBlob
            val stagedRev = pendingCloudSyncRevision
            pendingCloudSyncBlob = null
            pendingCloudSyncRevision = -1L
            if (stagedBlob != null) {
                writeCloudBlobAsync(
                    blob = stagedBlob,
                    revision = stagedRev,
                    targetUri = uri,
                    mode = "file",
                    displayName = name,
                    announceSuccess = true
                )
            } else {
                performCloudSync(announceSuccess = true)
            }
            if (pendingRecoveryKeyAfterLink != null) {
                recoveryKey = pendingRecoveryKeyAfterLink
                recoveryKit = pendingRecoveryKitAfterLink
                pendingRecoveryKeyAfterLink = null
                pendingRecoveryKitAfterLink = null
                recoveryIsSnapshotSetup = true
                backupFileSaved = true
            }
        } else {
            pendingCloudSyncBlob?.fill(0)
            pendingCloudSyncBlob = null
            pendingCloudSyncRevision = -1L
            pendingRecoveryKeyAfterLink = null
            pendingRecoveryKitAfterLink = null
            showStatus("Automatic backup setup cancelled.")
        }
    }

    private val cloudFolderLinker = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        exportPickerActive = false
        if (uri != null) {
            runCatching {
                contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            val name = queryDisplayName(uri, "Linked Sync Folder")
            syncUriString = uri.toString()
            syncMode = "tree"
            syncDisplayName = name
            cloudSyncError = ""
            prefs.edit {
                putString("syncUri", syncUriString)
                putString("syncMode", syncMode)
                putString("syncName", syncDisplayName)
                putString("cloudSyncError", "")
            }
            val stagedBlob = pendingCloudSyncBlob
            val stagedRev = pendingCloudSyncRevision
            pendingCloudSyncBlob = null
            pendingCloudSyncRevision = -1L
            if (stagedBlob != null) {
                writeCloudBlobAsync(
                    blob = stagedBlob,
                    revision = stagedRev,
                    targetUri = uri,
                    mode = "tree",
                    displayName = name,
                    announceSuccess = true
                )
            } else {
                performCloudSync(announceSuccess = true)
            }
            if (pendingRecoveryKeyAfterLink != null) {
                recoveryKey = pendingRecoveryKeyAfterLink
                recoveryKit = pendingRecoveryKitAfterLink
                pendingRecoveryKeyAfterLink = null
                pendingRecoveryKitAfterLink = null
                recoveryIsSnapshotSetup = true
                backupFileSaved = true
            }
        } else {
            pendingCloudSyncBlob?.fill(0)
            pendingCloudSyncBlob = null
            pendingCloudSyncRevision = -1L
            pendingRecoveryKeyAfterLink = null
            pendingRecoveryKitAfterLink = null
            showStatus("Backup folder setup cancelled.")
        }
    }

    private val screenOff = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            lock(clearPendingBackup = true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        storage = Storage(this)
        created = storage.exists()
        showGuide = !prefs.getBoolean("onboardingComplete", false)
        pro = BuildConfig.DEBUG && prefs.getBoolean("testPro", false)
        lastExport = prefs.getLong("lastExport", 0L)
        lastExportRevision = prefs.getLong("lastExportRevision", -1L)
        lastVerified = prefs.getLong("recoveryCheckedAt", 0L)
        lastVerifiedRevision = prefs.getLong("recoveryCheckedRevision", -1L)
        syncUriString = prefs.getString("syncUri", "") ?: ""
        syncMode = prefs.getString("syncMode", "") ?: ""
        syncDisplayName = prefs.getString("syncName", "") ?: ""
        lastCloudSync = prefs.getLong("lastCloudSync", 0L)
        lastCloudSyncRevision = prefs.getLong("lastCloudSyncRevision", -1L)
        cloudSyncError = prefs.getString("cloudSyncError", "") ?: ""
        themeMode = runCatching { ThemeMode.valueOf(prefs.getString("themeMode", "SYSTEM") ?: "SYSTEM") }
            .getOrDefault(ThemeMode.SYSTEM)
        refreshStatus()
        ContextCompat.registerReceiver(
            this,
            screenOff,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        setContent {
            VaultTheme(themeMode) {
                val isDark = VaultThemeColors.isDark
                SideEffect {
                    WindowCompat.getInsetsController(window, window.decorView).isAppearanceLightStatusBars = !isDark
                }
                Surface(Modifier.fillMaxSize(), color = VaultThemeColors.BgDeep) {
                    androidx.compose.runtime.key(generation) {
                        Screen()
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (!authInFlight) {
            if (!created && !busy) return
            val keepBackupDialog = recoveryKey != null || exportPickerActive || pendingCloudSyncBlob != null
            lock(clearPendingBackup = !keepBackupDialog)
        }
    }

    override fun onDestroy() {
        lock(clearPendingBackup = true)
        unregisterReceiver(screenOff)
        super.onDestroy()
    }

    private fun showStatus(text: String, isError: Boolean = false) {
        message = text
        messageIsError = isError
    }

    private fun dismissGuide() {
        showGuide = false
        prefs.edit { putBoolean("onboardingComplete", true) }
    }

    private fun updateThemeMode(mode: ThemeMode) {
        themeMode = mode
        prefs.edit { putString("themeMode", mode.name) }
    }

    private fun refreshStatus() {
        val status = storage.securityStatus()
        securityStatus = status
        keyInvalidated = status.keyHealth == KeyHealth.INVALIDATED
        snapshots = storage.listSnapshots()
    }

    private fun installSession(newVault: Vault) {
        val next = SessionVault(newVault)
        sessionVault?.close()
        sessionVault = next
        // The system file picker locks the vault. Resume recovery after either unlock mode.
        if (pendingImport != null) {
            settings = true
            settingsPage = SettingsPage.MANUAL_BACKUP
        }
    }

    private fun clearPrepared() {
        pendingPrepared?.let {
            it.key.fill(0)
            it.payload.fill(0)
        }
        pendingPrepared = null
    }

    private fun clearOpened() {
        pendingOpened?.payload?.fill(0)
        pendingOpened = null
        passphraseRequired = false
    }

    private fun clearBackupExportState() {
        exportPickerActive = false
        recoveryKey = null
        recoveryKit = null
        recoveryIsSnapshotSetup = false
        backupFileSaved = false
        pendingExport?.fill(0)
        pendingExport = null
        pendingExportRevision = -1L
        pendingCloudSyncBlob?.fill(0)
        pendingCloudSyncBlob = null
        pendingCloudSyncRevision = -1L
        pendingRecoveryKeyAfterLink = null
        pendingRecoveryKitAfterLink = null
    }

    private fun lock(clearPendingBackup: Boolean = true) {
        val hadPendingAsync = authInFlight || pendingPrepared != null || pendingOpened != null || busy
        authInFlight = false
        key?.fill(0)
        key = null
        sessionVault?.close()
        sessionVault = null
        if (clearPendingBackup) {
            clearBackupExportState()
            setupPass = ""
            setupConfirmation = ""
            setupShowPass = false
            setupMaximum = false
        }
        settings = false
        settingsPage = SettingsPage.HUB
        if (created) showGuide = false
        clearOpened()
        clearPrepared()
        busy = false
        if (clearPendingBackup || hadPendingAsync) {
            generation++
        }
        if (::storage.isInitialized) refreshStatus()
    }

    private fun authenticate(title: String, onFailure: () -> Unit = {}, action: () -> Unit) {
        if (BiometricManager.from(this).canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            busy = false
            onFailure()
            showStatus("Please set up a phone PIN, pattern, or fingerprint in Android Settings first.", isError = true)
            return
        }
        val authGeneration = generation
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Password Protection · Offline Vault")
            .setAllowedAuthenticators(authenticators)
            .build()
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    authInFlight = false

                    fun completeAuth() {
                        if (authGeneration != generation || isDestroyed || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                            busy = false
                            onFailure()
                            showStatus("Unlock interrupted because the app moved to the background. Please try again.", isError = true)
                            lock()
                            return
                        }
                        try {
                            action()
                        } catch (e: KeyInvalidatedException) {
                            lock()
                            keyInvalidated = true
                            showStatus(
                                e.message ?: "Your phone's lock key was reset. Use a verified backup file to recover.",
                                isError = true
                            )
                        } catch (_: Exception) {
                            showStatus(
                                "Unlock failed. Do not delete your app data — you can restore from an encrypted backup if needed.",
                                isError = true
                            )
                            lock()
                        } finally {
                            busy = false
                        }
                    }

                    if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                        completeAuth()
                    } else {
                        var attempts = 0
                        val waitResume = object : Runnable {
                            override fun run() {
                                if (authGeneration != generation || isDestroyed) {
                                    busy = false
                                    onFailure()
                                    return
                                }
                                if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || attempts >= 10) {
                                    completeAuth()
                                } else {
                                    attempts++
                                    handler.postDelayed(this, 100L)
                                }
                            }
                        }
                        handler.postDelayed(waitResume, 100L)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    authInFlight = false
                    busy = false
                    onFailure()
                    showStatus("Phone verification was cancelled or unavailable.", isError = true)
                    if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                        lock()
                    }
                }
            }
        )
        authInFlight = true
        try {
            prompt.authenticate(info)
        } catch (_: Exception) {
            authInFlight = false
            busy = false
            onFailure()
            showStatus("Phone verification prompt could not be opened.", isError = true)
        }
    }

    private fun setup(pass: String?) {
        if (busy || created) return
        if (pass != null && pass.length < 16) {
            showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
            return
        }
        busy = true
        val ticket = generation
        val chars = pass?.toCharArray()
        Thread {
            val result = runCatching { storage.prepare(chars) }
            chars?.fill('\u0000')
            runOnUiThread {
                if (ticket != generation || isDestroyed) {
                    result.getOrNull()?.let {
                        it.key.fill(0)
                        it.payload.fill(0)
                    }
                    return@runOnUiThread
                }
                val p = result.getOrElse {
                    busy = false
                    showStatus("Could not prepare vault encryption.", isError = true)
                    return@runOnUiThread
                }
                pendingPrepared = p
                try {
                    storage.createDeviceKeyIfNeeded()
                    authenticate("Create secure vault", { clearPrepared() }) {
                        val prepared = pendingPrepared ?: error("Setup interrupted. Retry.")
                        val newVault = storage.create(prepared)
                        key = prepared.key.copyOf()
                        installSession(newVault)
                        created = true
                        keyInvalidated = false
                        setupPass = ""
                        setupConfirmation = ""
                        setupShowPass = false
                        setupMaximum = false
                        clearPrepared()
                        refreshStatus()
                        showStatus("Vault created. Add your first item, then save a backup.")
                    }
                } catch (_: Exception) {
                    clearPrepared()
                    busy = false
                    showStatus("Couldn’t set up the vault with your phone lock. Please try again.", isError = true)
                }
            }
        }.start()
    }

    private fun unlock() {
        if (busy) return
        busy = true
        showStatus("")
        authenticate("Unlock vault") {
            val opened = storage.deviceUnlock()
            if (opened.mode == "maximum") {
                pendingOpened = opened
                passphraseRequired = true
            } else {
                val k = try {
                    storage.openKey(opened, null)
                } finally {
                    opened.payload.fill(0)
                }
                try {
                    installSession(storage.decrypt(k, opened))
                    key = k
                    keyInvalidated = false
                    refreshStatus()
                } catch (e: Exception) {
                    k.fill(0)
                    throw e
                }
            }
        }
    }

    private fun unlockPassphrase(pass: String) {
        if (busy || System.currentTimeMillis() < nextAttempt) {
            showStatus("Too many attempts. Wait a moment before retrying.", isError = true)
            return
        }
        val opened = pendingOpened ?: return
        busy = true
        val ticket = generation
        val chars = pass.toCharArray()
        // Copy encrypted inner wrapper; lifecycle cancellation prevents late unlock.
        val copy = opened.copy(payload = opened.payload.copyOf())
        Thread {
            val result = runCatching {
                val k = storage.openKey(copy, chars)
                try {
                    k to storage.decrypt(k, copy)
                } catch (e: Exception) {
                    k.fill(0)
                    throw e
                }
            }
            chars.fill('\u0000')
            copy.payload.fill(0)
            runOnUiThread {
                if (ticket != generation || isDestroyed) {
                    result.getOrNull()?.first?.fill(0)
                    return@runOnUiThread
                }
                busy = false
                result.onSuccess { (k, v) ->
                    key = k
                    installSession(v)
                    clearOpened()
                    failed = 0
                    nextAttempt = 0
                    keyInvalidated = false
                    refreshStatus()
                    showStatus("")
                }.onFailure {
                    failed++
                    nextAttempt = System.currentTimeMillis() + (1000L shl failed.coerceAtMost(5))
                    showStatus("Incorrect master passphrase or damaged vault. Try again in a moment.", isError = true)
                }
            }
        }.start()
    }

    private fun commit(transform: (Vault) -> Vault): Boolean {
        val k = key ?: return false
        val sv = sessionVault ?: return false
        val full = sv.materialize()
        val newVault = transform(full)
        return try {
            storage.save(k, newVault)
            installSession(newVault)
            refreshStatus()
            if (syncUriString.isNotEmpty()) {
                performCloudSync(announceSuccess = false)
            }
            true
        } catch (_: Exception) {
            showStatus("Save failed. Your previous vault state was safely kept.", isError = true)
            false
        }
    }

    private fun copySecret(value: String, labelName: String = "Value") {
        val clipboard = getSystemService(ClipboardManager::class.java)
        val label = "vault-" + UUID.randomUUID().toString()
        val clip = ClipData.newPlainText(label, value)
        clip.description.extras = android.os.PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        clipboard.setPrimaryClip(clip)
        showStatus("$labelName copied. The app will try to clear it after 30 seconds.")
        handler.postDelayed({
            try {
                if (clipboard.primaryClipDescription?.label?.toString() == label) {
                    clipboard.clearPrimaryClip()
                }
            } catch (_: Exception) {
            }
        }, 30_000)
    }

    private fun newBackup() {
        if (sessionVault == null || busy) return
        busy = true
        authenticate("Verify identity to create backup") {
            val activeSv = sessionVault ?: return@authenticate
            val v = activeSv.materialize()
            val rk = PortableBackup.recoveryKey()
            val bytes = Codec.encode(v)
            try {
                pendingExport = PortableBackup.export(rk, bytes)
                pendingExportRevision = v.revision
                recoveryKey = PortableBackup.encodeKey(rk)
                recoveryKit = PortableBackup.encodeKit(rk)
                recoveryIsSnapshotSetup = false
                backupFileSaved = false
            } finally {
                rk.fill(0)
                bytes.fill(0)
            }
        }
    }

    private fun verifyBackup(code: String) {
        val sv = sessionVault ?: return
        val blob = pendingImport ?: return
        try {
            val k = PortableBackup.decodeFlexibleKey(code)
            val bytes = try {
                PortableBackup.restore(k, blob)
            } finally {
                k.fill(0)
            }
            val restored = try {
                Codec.decode(bytes)
            } finally {
                bytes.fill(0)
            }
            val current = sv.materialize()
            val matches = restored.entries.toSet() == current.entries.toSet() && restored.keepHistory == current.keepHistory
            if (matches) {
                val now = System.currentTimeMillis()
                lastVerified = now
                lastVerifiedRevision = current.revision
                prefs.edit {
                    putLong("recoveryCheckedAt", now)
                    putLong("recoveryCheckedRevision", current.revision)
                }
                showStatus("Backup test passed: file decrypted and matches every item in your vault.")
            } else {
                showStatus("Backup test passed: file decrypts, but contains older items. Save a fresh backup to stay up to date.")
            }
        } catch (_: Exception) {
            showStatus("Backup test failed. Double-check your 33-word recovery phrase or compact code.", isError = true)
        }
    }

    private fun restore(code: String) {
        val blob = pendingImport ?: return
        val sv = sessionVault ?: return
        val v = sv.redactedVault
        if (v.entries.isNotEmpty()) {
            showStatus("Your vault already has items. Use 'Replace Current Vault' to overwrite it after verification.", isError = true)
            return
        }
        try {
            val k = PortableBackup.decodeFlexibleKey(code)
            val bytes = try {
                PortableBackup.restore(k, blob)
            } finally {
                k.fill(0)
            }
            val restored = try {
                Codec.decode(bytes)
            } finally {
                bytes.fill(0)
            }
            if (commit { restored.copy(revision = it.revision + 1) }) {
                val now = System.currentTimeMillis()
                val newRev = sessionVault?.redactedVault?.revision ?: (v.revision + 1)
                lastVerified = now
                lastVerifiedRevision = newRev
                prefs.edit {
                    putLong("recoveryCheckedAt", now)
                    putLong("recoveryCheckedRevision", newRev)
                }
                pendingImport = null
                showStatus("Backup restored into your vault (${restored.entries.size} items).")
            }
        } catch (_: Exception) {
            showStatus("Restore failed: incorrect recovery phrase/code, unsupported file, or corrupted backup.", isError = true)
        }
    }

    private fun resetAndRecover(code: String, pass: String?, onVerified: () -> Unit = {}) {
        if (busy) return
        val blob = pendingImport ?: return
        if (pass != null && pass.length < 16) {
            showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
            return
        }
        val restored = try {
            val k = PortableBackup.decodeFlexibleKey(code)
            val bytes = try {
                PortableBackup.restore(k, blob)
            } finally {
                k.fill(0)
            }
            try {
                Codec.decode(bytes)
            } finally {
                bytes.fill(0)
            }
        } catch (_: Exception) {
            showStatus("Backup verification failed. Check the file and recovery phrase; your existing vault was not changed.", isError = true)
            return
        }
        onVerified()

        busy = true
        val ticket = generation
        val chars = pass?.toCharArray()
        Thread {
            val result = runCatching { storage.prepare(chars) }
            chars?.fill('\u0000')
            runOnUiThread {
                if (ticket != generation || isDestroyed) {
                    result.getOrNull()?.let {
                        it.key.fill(0)
                        it.payload.fill(0)
                    }
                    return@runOnUiThread
                }
                val p = result.getOrElse {
                    busy = false
                    showStatus("Could not prepare recovered vault.", isError = true)
                    return@runOnUiThread
                }
                pendingPrepared = p
                authenticate("Verify identity to restore verified backup", { clearPrepared() }) {
                    val prepared = pendingPrepared ?: error("Recovery interrupted. Retry.")
                    storage.resetToEmptyVault(prepared)
                    val newKey = prepared.key.copyOf()
                    val finalVault = restored.copy(revision = restored.revision.coerceAtLeast(0L) + 1L)
                    try {
                        storage.save(newKey, finalVault)
                    } catch (e: Exception) {
                        newKey.fill(0)
                        throw e
                    }
                    key?.fill(0)
                    key = newKey
                    installSession(finalVault)
                    created = true
                    keyInvalidated = false
                    pendingImport = null
                    settings = false
                    clearPrepared()
                    val now = System.currentTimeMillis()
                    lastVerified = now
                    lastVerifiedRevision = finalVault.revision
                    prefs.edit {
                        putLong("recoveryCheckedAt", now)
                        putLong("recoveryCheckedRevision", finalVault.revision)
                    }
                    refreshStatus()
                    showStatus("Vault recovered and restored (${finalVault.entries.size} items).")
                }
            }
        }.start()
    }

    private fun changeProtectionMode(pass: String?) {
        if (busy || sessionVault == null) return
        if (pass != null && pass.length < 16) {
            showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
            return
        }
        busy = true
        val ticket = generation
        val chars = pass?.toCharArray()
        Thread {
            val result = runCatching { storage.prepare(chars) }
            chars?.fill('\u0000')
            runOnUiThread {
                if (ticket != generation || isDestroyed) {
                    result.getOrNull()?.let {
                        it.key.fill(0)
                        it.payload.fill(0)
                    }
                    return@runOnUiThread
                }
                val p = result.getOrElse {
                    busy = false
                    showStatus("Could not prepare new lock mode.", isError = true)
                    return@runOnUiThread
                }
                pendingPrepared = p
                authenticate("Verify identity to change lock mode", { clearPrepared() }) {
                    val prepared = pendingPrepared ?: error("Lock mode update interrupted. Retry.")
                    val oldKey = key ?: error("Vault is locked.")
                    val sv = sessionVault ?: error("Vault is locked.")
                    val full = sv.materialize()
                    storage.rekey(oldKey, prepared, full)
                    val replacementKey = prepared.key.copyOf()
                    oldKey.fill(0)
                    key = replacementKey
                    clearPrepared()
                    refreshStatus()
                    showStatus(
                        if (prepared.mode == "maximum") {
                            "Unlock updated: phone lock plus a separate vault passphrase."
                        } else {
                            "Unlock updated: use your phone lock."
                        }
                    )
                }
            }
        }.start()
    }

    private fun rotateBackupKey(title: String, statusText: String) {
        if (busy || sessionVault == null) return
        busy = true
        authenticate(title) {
            val k = key ?: error("Vault is locked.")
            val sv = sessionVault ?: error("Vault is locked.")
            val full = sv.materialize()
            val bk = storage.configureBackupKey(k)
            try {
                recoveryKey = PortableBackup.encodeKey(bk)
                recoveryKit = PortableBackup.encodeKit(bk)
                recoveryIsSnapshotSetup = true
                backupFileSaved = true
            } finally {
                bk.fill(0)
            }
            storage.writeVerifiedSnapshot(k, full)
            refreshStatus()
            if (syncUriString.isNotEmpty()) {
                performCloudSync(announceSuccess = false)
            }
            showStatus(statusText)
        }
    }

    private fun enableSnapshots() {
        if (!pro) return
        rotateBackupKey("Verify identity to enable restore points", "Automatic device restore points enabled and verified.")
    }

    private fun queryDisplayName(uri: Uri, fallback: String): String {
        return runCatching {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) cursor.getString(idx)?.takeIf { it.isNotBlank() } else null
                } else {
                    null
                }
            }
        }.getOrNull() ?: uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: fallback
    }

    private fun writeStream(uri: Uri, bytes: ByteArray) {
        val stream = runCatching { contentResolver.openOutputStream(uri, "wt") }.getOrNull()
            ?: runCatching { contentResolver.openOutputStream(uri, "w") }.getOrNull()
            ?: contentResolver.openOutputStream(uri)
            ?: error("No output stream")
        stream.use {
            it.write(bytes)
            it.flush()
        }
    }

    private fun writeCloudBlobAsync(
        blob: ByteArray,
        revision: Long,
        targetUri: Uri,
        mode: String,
        displayName: String,
        announceSuccess: Boolean
    ) {
        syncInProgress = true
        Thread {
            val result = runCatching {
                val docUri = if (mode == "tree") {
                    val parentDocUri = DocumentsContract.buildDocumentUriUsingTree(
                        targetUri,
                        DocumentsContract.getTreeDocumentId(targetUri)
                    )
                    DocumentsContract.createDocument(
                        contentResolver,
                        parentDocUri,
                        "application/octet-stream",
                        "password-protection-rev$revision.ppvault"
                    ) ?: error("Could not create document in linked folder")
                } else {
                    targetUri
                }
                writeStream(docUri, blob)
                val readBack = contentResolver.openInputStream(docUri)?.use { it.readBounded(16_777_216) }
                    ?: error("Readback stream unavailable")
                require(readBack.contentEquals(blob)) { "Cloud sync readback verification mismatch" }
            }
            blob.fill(0)
            runOnUiThread {
                if (isDestroyed) return@runOnUiThread
                syncInProgress = false
                result.onSuccess {
                    val now = System.currentTimeMillis()
                    lastCloudSync = now
                    lastCloudSyncRevision = revision
                    lastExport = now
                    lastExportRevision = revision
                    cloudSyncError = ""
                    prefs.edit {
                        putLong("lastCloudSync", now)
                        putLong("lastCloudSyncRevision", revision)
                        putLong("lastExport", now)
                        putLong("lastExportRevision", revision)
                        putString("cloudSyncError", "")
                    }
                    if (announceSuccess) {
                        showStatus("Backup saved to $displayName. Your file provider handles uploading; test recovery separately.")
                    }
                }.onFailure {
                    val err = "Couldn’t save the backup. Check the file location or choose it again."
                    cloudSyncError = err
                    prefs.edit { putString("cloudSyncError", err) }
                    if (announceSuccess) {
                        showStatus(err, isError = true)
                    }
                }
            }
        }.start()
    }

    private fun setupOrLinkCloudSync(useFolder: Boolean) {
        val sv = sessionVault ?: return
        val k = key ?: return
        if (busy) return
        val launchPicker = {
            exportPickerActive = true
            try {
                if (useFolder) {
                    cloudFolderLinker.launch(null)
                } else {
                    cloudFileLinker.launch("password-protection-sync.ppvault")
                }
            } catch (_: Exception) {
                exportPickerActive = false
                pendingCloudSyncBlob?.fill(0)
                pendingCloudSyncBlob = null
                pendingCloudSyncRevision = -1L
                pendingRecoveryKeyAfterLink = null
                pendingRecoveryKitAfterLink = null
                showStatus("Could not open system file picker.", isError = true)
            }
        }
        if (!storage.securityStatus().hasBackupKey) {
            busy = true
            authenticate("Confirm it’s you to set up automatic backup") {
                val activeKey = key ?: error("Vault is locked.")
                val activeSv = sessionVault ?: error("Vault is locked.")
                val full = activeSv.materialize()
                val bk = storage.configureBackupKey(activeKey)
                try {
                    pendingRecoveryKeyAfterLink = PortableBackup.encodeKey(bk)
                    pendingRecoveryKitAfterLink = PortableBackup.encodeKit(bk)
                } finally {
                    bk.fill(0)
                }
                runCatching { storage.writeVerifiedSnapshot(activeKey, full) }
                pendingCloudSyncBlob?.fill(0)
                val blob = storage.exportWithBackupKey(activeKey, full)
                storage.verifyWithBackupKey(activeKey, blob, full)
                pendingCloudSyncBlob = blob
                pendingCloudSyncRevision = full.revision
                refreshStatus()
                launchPicker()
            }
        } else {
            val full = sv.materialize()
            pendingCloudSyncBlob?.fill(0)
            val blob = storage.exportWithBackupKey(k, full)
            storage.verifyWithBackupKey(k, blob, full)
            pendingCloudSyncBlob = blob
            pendingCloudSyncRevision = full.revision
            launchPicker()
        }
    }

    private fun performCloudSync(announceSuccess: Boolean) {
        if (syncUriString.isEmpty()) return
        val k = key ?: return
        val sv = sessionVault ?: return
        if (!storage.securityStatus().hasBackupKey) return
        val full = sv.materialize()
        val blob = try {
            storage.exportWithBackupKey(k, full).also {
                storage.verifyWithBackupKey(k, it, full)
            }
        } catch (_: Exception) {
            val err = "Couldn’t open the backup key. Unlock your vault and try again."
            cloudSyncError = err
            prefs.edit { putString("cloudSyncError", err) }
            if (announceSuccess) showStatus(err, isError = true)
            return
        }
        writeCloudBlobAsync(
            blob = blob,
            revision = full.revision,
            targetUri = syncUriString.toUri(),
            mode = syncMode.ifEmpty { "file" },
            displayName = syncDisplayName.ifEmpty { "Linked Cloud File" },
            announceSuccess = announceSuccess
        )
    }

    private fun unlinkCloudSync() {
        if (syncUriString.isNotEmpty()) {
            runCatching {
                contentResolver.releasePersistableUriPermission(
                    syncUriString.toUri(),
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
        }
        syncUriString = ""
        syncMode = ""
        syncDisplayName = ""
        lastCloudSync = 0L
        lastCloudSyncRevision = -1L
        cloudSyncError = ""
        prefs.edit {
            remove("syncUri")
            remove("syncMode")
            remove("syncName")
            remove("lastCloudSync")
            remove("lastCloudSyncRevision")
            remove("cloudSyncError")
        }
        showStatus("Automatic backup disconnected. Existing backup files were kept.")
    }

    private fun loadCloudSyncFileToTest() {
        if (syncUriString.isEmpty() || syncMode != "file") return
        try {
            pendingImport = contentResolver.openInputStream(syncUriString.toUri())?.use { it.readBounded(16_777_216) }
                ?: error("Unable to read linked cloud file")
            showStatus("Backup loaded from $syncDisplayName. Enter its recovery phrase to test or restore it.")
        } catch (_: Exception) {
            showStatus("Couldn’t open the backup. Choose its file location again.", isError = true)
        }
    }

    private fun createSnapshotNow() {
        if (!pro || busy || sessionVault == null) return
        val k = key ?: return
        val sv = sessionVault ?: return
        try {
            val full = sv.materialize()
            val snap = storage.writeVerifiedSnapshot(k, full)
            if (snap != null) {
                refreshStatus()
                showStatus("Verified restore point saved (${snap.name}).")
            } else {
                showStatus("Automatic restore points are turned off.")
            }
        } catch (_: Exception) {
            showStatus("Restore point verification failed.", isError = true)
        }
    }

    @Composable
    private fun Screen() {
        if (showGuide) {
            OnboardingGuide(
                onFinish = { dismissGuide() },
                onSkip = { dismissGuide() },
                isReturningUser = created
            )
            return
        }

        val sv = sessionVault
        LaunchedEffect(message, messageIsError) {
            if (message.isNotEmpty() && !messageIsError) {
                delay(4_000)
                showStatus("")
            }
        }
        BackHandler(enabled = settings && recoveryKey == null) {
            if (settingsPage == SettingsPage.HUB) settings = false else settingsPage = SettingsPage.HUB
        }
        Box(Modifier.fillMaxSize().background(VaultThemeColors.BgDeep).systemBarsPadding().imePadding()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                    ShieldBadgeIcon(modifier = Modifier.size(28.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "Password Protection",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                    if (sv != null) {
                        LockVaultButton(onClick = { lock(clearPendingBackup = true) }, label = "Lock", compact = true)
                    }
                }

                if (message.isNotEmpty() && messageIsError) {
                    val bannerColor = VaultThemeColors.AccentDanger
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = bannerColor.copy(alpha = 0.12f),
                        border = BorderStroke(1.dp, bannerColor.copy(alpha = 0.45f))
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = message,
                                style = MaterialTheme.typography.bodySmall,
                                color = VaultThemeColors.TextPrimary,
                                modifier = Modifier.weight(1f)
                            )
                            TextButton(onClick = { showStatus("") }) {
                                Text("OK", color = bannerColor)
                            }
                        }
                    }
                }

                if (sv == null) {
                    HomeActions(showSettings = false)
                    LockedScreen()
                } else if (settings) {
                    Settings(sv)
                } else {
                    VaultScreen(sv)
                }
            }

            if (message.isNotEmpty() && !messageIsError && recoveryKey == null) {
                Snackbar(
                    modifier = Modifier.align(Alignment.BottomCenter).padding(16.dp),
                    action = { TextButton(onClick = { showStatus("") }) { Text("Dismiss") } }
                ) { Text(message) }
            }
        }
        RecoveryKeyDialog()
    }

    @Composable
    private fun HomeActions(showSettings: Boolean) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { showGuide = true }) { Text("How this app works") }
            Spacer(Modifier.weight(1f))
            if (showSettings) {
                TextButton(onClick = { settingsPage = SettingsPage.HUB; settings = true }) {
                    Text("Settings")
                }
            }
        }
    }

    @Composable
    private fun LockedScreen() {
        val status = securityStatus ?: storage.securityStatus()
        var pass by remember { mutableStateOf("") }
        var showPass by remember { mutableStateOf(false) }
        var recoveryCode by remember { mutableStateOf("") }
        var showRecoveryCode by remember { mutableStateOf(false) }
        var recoveryPass by remember { mutableStateOf("") }
        var recoveryConfirm by remember { mutableStateOf("") }
        var showRecoveryPass by remember { mutableStateOf(false) }
        var recoveryMaximum by remember { mutableStateOf(false) }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (!created) {
                SectionCard(
                    title = "Set up your vault",
                    subtitle = "A vault is a locked space for your passwords and private notes. Choose how to open it.",
                    badgeText = null
                ) {
                    SelectableOptionCard(
                        selected = !setupMaximum,
                        title = "Use my phone lock",
                        description = "Open with your fingerprint or phone PIN. Someone who knows your phone PIN can also open your vault.",
                        badgeText = "RECOMMENDED",
                        badgeColor = VaultThemeColors.AccentEmerald,
                        onClick = { setupMaximum = false }
                    )
                    SelectableOptionCard(
                        selected = setupMaximum,
                        title = "Add a separate passphrase",
                        description = "Use your phone lock, then a separate phrase of at least 16 characters. You’ll need to remember this phrase each time.",
                        badgeText = "EXTRA LOCK",
                        badgeColor = VaultThemeColors.AccentCyan,
                        onClick = { setupMaximum = true }
                    )

                    if (setupMaximum) {
                        HorizontalDivider(color = VaultThemeColors.BorderSubtle)
                        VaultSecretField(
                            value = setupPass,
                            onValueChange = { setupPass = it },
                            label = "Vault passphrase (16+ characters)",
                            visible = setupShowPass,
                            onToggleVisible = { setupShowPass = !setupShowPass },
                            placeholder = "Use a strong phrase or generate 6 words"
                        )
                        val progress = (setupPass.length / 16f).coerceIn(0f, 1f)
                        val ready = setupPass.length >= 16
                        Text(
                            text = if (ready) "Length ready (${setupPass.length} characters)" else "${setupPass.length} / 16 minimum characters",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (ready) VaultThemeColors.AccentEmerald else VaultThemeColors.AccentAmber
                        )
                        LinearProgressIndicator(
                            progress = { progress },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(5.dp)
                                .clip(RoundedCornerShape(50)),
                            color = if (ready) VaultThemeColors.AccentEmerald else VaultThemeColors.AccentAmber,
                            trackColor = VaultThemeColors.BgElevated
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    val generated = Generator.passphrase(SecureRandomSource(rng::nextInt))
                                    setupPass = generated
                                    setupConfirmation = generated
                                    setupShowPass = true
                                },
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(10.dp),
                                border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                            ) {
                                Text("Suggest 6 words", color = VaultThemeColors.AccentCyan)
                            }
                            if (setupPass.isNotEmpty()) {
                                OutlinedButton(
                                    onClick = { copySecret(setupPass, "Vault passphrase") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(10.dp),
                                    border = BorderStroke(1.dp, VaultThemeColors.AccentEmerald.copy(alpha = 0.5f))
                                ) {
                                    Text("Copy phrase", color = VaultThemeColors.AccentEmerald)
                                }
                            }
                        }
                        VaultSecretField(
                            value = setupConfirmation,
                            onValueChange = { setupConfirmation = it },
                            label = "Confirm vault passphrase",
                            visible = setupShowPass
                        )
                    }

                    Button(
                        onClick = {
                            if (setupMaximum && setupPass != setupConfirmation) {
                                showStatus("Vault passphrases do not match.", isError = true)
                            } else if (setupMaximum && setupPass.length < 16) {
                                showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
                            } else {
                                setup(if (setupMaximum) setupPass else null)
                            }
                        },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = VaultThemeColors.AccentEmerald,
                            contentColor = VaultThemeColors.OnAccentDark
                        )
                    ) {
                        Text("Create vault")
                    }
                }

                SectionCard(
                    title = "Moving from another phone?",
                    subtitle = "Create your vault above, then choose Restore from backup. Your saved items will be added to this new vault.",
                    badgeText = null
                ) {
                    Text(
                        "You’ll need your backup file and its recovery phrase — the words that unlock that particular copy. We can’t recover these for you.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            } else if (passphraseRequired) {
                SectionCard(
                    title = "Enter your vault passphrase",
                    subtitle = "Your phone lock has been checked. Now enter the separate phrase you chose for this vault.",
                    badgeText = "STEP 2 OF 2",
                    badgeColor = VaultThemeColors.AccentCyan
                ) {
                    VaultSecretField(
                        value = pass,
                        onValueChange = { pass = it },
                        label = "Vault passphrase",
                        visible = showPass,
                        onToggleVisible = { showPass = !showPass }
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                pass = ""
                                lock()
                            },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Text("Cancel")
                        }
                        Button(
                            onClick = {
                                unlockPassphrase(pass)
                                pass = ""
                                showPass = false
                            },
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = VaultThemeColors.AccentEmerald,
                                contentColor = VaultThemeColors.OnAccentDark
                            )
                        ) {
                            Text("Unlock Vault")
                        }
                    }
                }
            } else {
                if (keyInvalidated) {
                    SectionCard(
                        title = "Your phone’s lock has changed",
                        subtitle = "Android can no longer open this vault with the previous phone lock. You’ll need a backup to recover your items.",
                        badgeText = "RECOVERY NEEDED",
                        badgeColor = VaultThemeColors.AccentAmber,
                        borderColor = VaultThemeColors.AccentAmber.copy(alpha = 0.6f)
                    ) {
                        Text(
                            "Your passwords cannot be unlocked with the old key. Restore your entries safely using an encrypted .ppvault backup file and its recovery phrase below.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }

                if (pendingImport != null && !keyInvalidated) {
                    SectionCard(
                        title = "Your backup is ready to open",
                        subtitle = "Unlock your vault first. Then you’ll go straight to the recovery phrase field."
                    ) {
                        TextButton(onClick = { pendingImport = null; showStatus("") }) { Text("Cancel restore") }
                    }
                }
                SectionCard(
                    title = "Welcome back",
                    subtitle = if (status.mode == "maximum") {
                        "Use your phone lock, then enter your vault passphrase."
                    } else {
                        "Your passwords are locked. Use your phone lock to open them."
                    },
                    badgeText = null
                ) {
                    Text(
                        "Your vault locks when you leave the app or turn off the screen.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Button(
                        onClick = { unlock() },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = VaultThemeColors.AccentEmerald,
                            contentColor = VaultThemeColors.OnAccentDark
                        )
                    ) {
                        Text("Unlock vault")
                    }
                }

                if (keyInvalidated) {
                    SectionCard(
                        title = "Restore From Encrypted Backup",
                        subtitle = "Your current vault is only replaced after your backup file and recovery phrase pass verification.",
                        badgeText = "SAFE RECOVERY",
                        badgeColor = VaultThemeColors.AccentAmber
                    ) {
                        Text(
                            "1. Pick your .ppvault backup file\n2. Enter your 33-word recovery phrase or compact code\n3. Choose protection mode & restore",
                            style = MaterialTheme.typography.bodySmall
                        )
                        OutlinedButton(
                            onClick = { importer.launch(arrayOf("*/*")) },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                        ) {
                            Text(
                                if (pendingImport == null) "Choose Backup File (.ppvault)" else "Backup File Loaded · Choose Different File",
                                color = VaultThemeColors.AccentCyan
                            )
                        }
                        if (pendingImport != null) {
                            VaultSecretField(
                                value = recoveryCode,
                                onValueChange = { recoveryCode = it },
                                label = "Recovery phrase or code",
                                visible = showRecoveryCode,
                                onToggleVisible = { showRecoveryCode = !showRecoveryCode }
                            )
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { recoveryMaximum = !recoveryMaximum }
                            ) {
                                Switch(
                                    checked = recoveryMaximum,
                                    onCheckedChange = { recoveryMaximum = it },
                                    colors = SwitchDefaults.colors(checkedTrackColor = VaultThemeColors.AccentEmerald)
                                )
                                Spacer(Modifier.width(10.dp))
                                Text("Add master passphrase to restored vault", style = MaterialTheme.typography.bodyMedium)
                            }
                            if (recoveryMaximum) {
                                VaultSecretField(
                                    value = recoveryPass,
                                    onValueChange = { recoveryPass = it },
                                    label = "New vault passphrase (16+ characters)",
                                    visible = showRecoveryPass,
                                    onToggleVisible = { showRecoveryPass = !showRecoveryPass }
                                )
                                VaultSecretField(
                                    value = recoveryConfirm,
                                    onValueChange = { recoveryConfirm = it },
                                    label = "Confirm vault passphrase",
                                    visible = showRecoveryPass
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                OutlinedButton(
                                    onClick = {
                                        pendingImport = null
                                        recoveryCode = ""
                                        recoveryPass = ""
                                        recoveryConfirm = ""
                                    },
                                    enabled = !busy,
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp),
                                    border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                                ) {
                                    Text("Cancel")
                                }
                                Button(
                                    onClick = {
                                        if (recoveryMaximum && recoveryPass != recoveryConfirm) {
                                            showStatus("Vault passphrases do not match.", isError = true)
                                        } else if (recoveryMaximum && recoveryPass.length < 16) {
                                            showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
                                        } else {
                                            resetAndRecover(recoveryCode, if (recoveryMaximum) recoveryPass else null) {
                                                recoveryCode = ""
                                                recoveryPass = ""
                                                recoveryConfirm = ""
                                            }
                                        }
                                    },
                                    enabled = !busy,
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = VaultThemeColors.AccentEmerald,
                                        contentColor = VaultThemeColors.OnAccentDark
                                    )
                                ) {
                                    Text("Verify & Restore")
                                }
                            }
                        }
                    }
                }
            }

            if (busy) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        color = VaultThemeColors.AccentEmerald,
                        strokeWidth = 2.5.dp
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("Please wait…", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }

    @Composable
    private fun ColumnScope.VaultScreen(sv: SessionVault) {
        val v = sv.redactedVault
        var query by remember { mutableStateOf("") }
        var activeFilter by remember { mutableStateOf("ALL") }
        var currentId by remember { mutableStateOf<String?>(null) }
        var editing by remember { mutableStateOf(false) }

        val openedEntry = remember(currentId, v.revision, sv) {
            currentId?.let { id -> runCatching { sv.openEntry(id) }.getOrNull() }
        }

        BackHandler(enabled = openedEntry != null && !editing && recoveryKey == null) { currentId = null }
        if (editing) {
            val e = openedEntry ?: remember { Entry(UUID.randomUUID().toString(), "") }
            EntryEditor(
                e = e,
                isNew = openedEntry == null,
                cancel = {
                    editing = false
                    currentId = null
                },
                save = { updated ->
                    if (commit { it.save(updated, System.currentTimeMillis()) }) {
                        editing = false
                        currentId = null
                        showStatus("Item saved.")
                    }
                }
            )
        } else if (openedEntry != null) {
            EntryDetails(
                e = openedEntry,
                back = { currentId = null },
                edit = { editing = true },
                delete = {
                    if (commit { it.delete(openedEntry.id) }) {
                        currentId = null
                        showStatus("Item deleted from vault.")
                    }
                },
                clearHistory = {
                    if (commit { it.save(openedEntry.copy(history = emptyList()), System.currentTimeMillis()) }) {
                        currentId = null
                        showStatus("Previous password history cleared.")
                    }
                }
            )
        } else {
            HomeActions(showSettings = true)
            val backupNeedsAttention = v.entries.isNotEmpty() && (lastExport == 0L || lastExportRevision != v.revision)
            val categories = remember(v.entries) {
                v.entries.map { it.category.trim() }.filter { it.isNotEmpty() }.distinct().sorted()
            }

            if (backupNeedsAttention) {
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .clickable {
                            settingsPage = SettingsPage.MANUAL_BACKUP
                            settings = true
                        },
                    shape = RoundedCornerShape(12.dp),
                    color = VaultThemeColors.AccentAmber.copy(alpha = 0.10f),
                    border = BorderStroke(1.dp, VaultThemeColors.AccentAmber.copy(alpha = 0.45f))
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (lastExport == 0L) {
                                "No backup yet. Save a copy in case you lose your phone."
                            } else {
                                "Changes since your last backup. Save a fresh copy."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = VaultThemeColors.AccentAmber,
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("Back up", style = MaterialTheme.typography.labelLarge, color = VaultThemeColors.AccentAmber)
                    }
                }
            }

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search vault") },
                singleLine = true,
                trailingIcon = if (query.isNotEmpty()) {
                    {
                        TextButton(onClick = { query = "" }) {
                            Text("Clear", color = VaultThemeColors.AccentCyan)
                        }
                    }
                } else {
                    null
                },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = vaultFieldColors(),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled = false)
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val chipColors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = VaultThemeColors.AccentEmerald.copy(alpha = 0.18f),
                    selectedLabelColor = VaultThemeColors.AccentEmerald,
                    containerColor = VaultThemeColors.BgSurface,
                    labelColor = VaultThemeColors.TextSecondary
                )
                FilterChip(
                    selected = activeFilter == "ALL",
                    onClick = { activeFilter = "ALL" },
                    label = { Text("All (${v.entries.size})") },
                    colors = chipColors,
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = activeFilter == "ALL",
                        borderColor = VaultThemeColors.BorderSubtle,
                        selectedBorderColor = VaultThemeColors.AccentEmerald.copy(alpha = 0.6f)
                    )
                )
                FilterChip(
                    selected = activeFilter == "FAVORITES",
                    onClick = { activeFilter = if (activeFilter == "FAVORITES") "ALL" else "FAVORITES" },
                    label = { Text("★ Favourites") },
                    colors = chipColors,
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = activeFilter == "FAVORITES",
                        borderColor = VaultThemeColors.BorderSubtle,
                        selectedBorderColor = VaultThemeColors.AccentEmerald.copy(alpha = 0.6f)
                    )
                )
                FilterChip(
                    selected = activeFilter == "LOGINS",
                    onClick = { activeFilter = if (activeFilter == "LOGINS") "ALL" else "LOGINS" },
                    label = { Text("Logins") },
                    colors = chipColors,
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = activeFilter == "LOGINS",
                        borderColor = VaultThemeColors.BorderSubtle,
                        selectedBorderColor = VaultThemeColors.AccentEmerald.copy(alpha = 0.6f)
                    )
                )
                FilterChip(
                    selected = activeFilter == "NOTES",
                    onClick = { activeFilter = if (activeFilter == "NOTES") "ALL" else "NOTES" },
                    label = { Text("Notes") },
                    colors = chipColors,
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = activeFilter == "NOTES",
                        borderColor = VaultThemeColors.BorderSubtle,
                        selectedBorderColor = VaultThemeColors.AccentEmerald.copy(alpha = 0.6f)
                    )
                )
                categories.forEach { cat ->
                    val tag = "CAT:$cat"
                    FilterChip(
                        selected = activeFilter == tag,
                        onClick = { activeFilter = if (activeFilter == tag) "ALL" else tag },
                        label = { Text(cat) },
                        colors = chipColors,
                        border = FilterChipDefaults.filterChipBorder(
                            enabled = true,
                            selected = activeFilter == tag,
                            borderColor = VaultThemeColors.BorderSubtle,
                            selectedBorderColor = VaultThemeColors.AccentEmerald.copy(alpha = 0.6f)
                        )
                    )
                }
            }

            val baseMatches = v.search(query, favoritesOnly = activeFilter == "FAVORITES")
            val filtered = when {
                activeFilter == "LOGINS" -> baseMatches.filter { it.kind == Kind.PASSWORD }
                activeFilter == "NOTES" -> baseMatches.filter { it.kind == Kind.NOTE }
                activeFilter.startsWith("CAT:") -> {
                    val targetCat = activeFilter.removePrefix("CAT:")
                    baseMatches.filter { it.category.trim().equals(targetCat, ignoreCase = true) }
                }
                else -> baseMatches
            }

            if (v.entries.isEmpty()) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    SectionCard(
                        title = "One less password to remember",
                        subtitle = "Add a login or a private note. Your vault stays on this phone unless you choose to save a backup.",
                        badgeText = null
                    ) {
                        Button(
                            onClick = {
                                currentId = null
                                editing = true
                            },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = VaultThemeColors.AccentEmerald,
                                contentColor = VaultThemeColors.OnAccentDark
                            )
                        ) {
                            Text("Add your first item")
                        }
                        OutlinedButton(
                            onClick = {
                                settingsPage = SettingsPage.MANUAL_BACKUP
                                settings = true
                            },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Text("Restore From a Backup File", color = VaultThemeColors.AccentCyan)
                        }
                    }
                }
            } else if (filtered.isEmpty()) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    SectionCard(
                        title = "No Matching Items",
                        subtitle = "No saved entries match your current search or filter."
                    ) {
                        OutlinedButton(
                            onClick = {
                                query = ""
                                activeFilter = "ALL"
                            },
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Text("Reset filters", color = VaultThemeColors.AccentCyan)
                        }
                        TextButton(onClick = { currentId = null; editing = true }) { Text("Add item") }
                    }
                }
            } else {
                Box(Modifier.weight(1f)) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = 88.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        items(filtered, key = { it.id }) { entry ->
                            val isNote = entry.kind == Kind.NOTE
                            val badgeColor = when {
                                entry.favorite -> VaultThemeColors.AccentAmber
                                isNote -> VaultThemeColors.AccentCyan
                                else -> VaultThemeColors.AccentEmerald
                            }
                            val badgeLabel = when {
                                entry.favorite -> "★"
                                isNote -> "NOTE"
                                else -> entry.title.take(1).uppercase()
                            }
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(14.dp))
                                    .clickable { currentId = entry.id },
                                shape = RoundedCornerShape(14.dp),
                                color = VaultThemeColors.BgSurface,
                                border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(10.dp))
                                            .background(badgeColor.copy(alpha = 0.14f))
                                            .border(1.dp, badgeColor.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                                            .padding(horizontal = 10.dp, vertical = 8.dp),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            text = badgeLabel,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = badgeColor
                                        )
                                    }
                                    Column(
                                        modifier = Modifier.weight(1f),
                                        verticalArrangement = Arrangement.spacedBy(5.dp)
                                    ) {
                                        Text(entry.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        val sub = if (isNote) {
                                            "Note"
                                        } else {
                                            listOf(entry.username, entry.website)
                                                .filter { it.isNotBlank() }
                                                .joinToString(" · ")
                                                .ifEmpty { "Login credential" }
                                        }
                                        Text(sub, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    }
                                    if (!isNote) {
                                        TextButton(
                                            modifier = Modifier.semantics { contentDescription = "Copy password for ${entry.title}" },
                                            onClick = { sv.openEntry(entry.id)?.let { copySecret(it.password, "Password") } }
                                        ) { Text("Copy") }
                                    }
                                }
                            }
                        }
                    }
                    ExtendedFloatingActionButton(
                        onClick = { currentId = null; editing = true },
                        modifier = Modifier.align(Alignment.BottomEnd).padding(8.dp),
                        containerColor = VaultThemeColors.AccentEmerald,
                        contentColor = VaultThemeColors.OnAccentDark
                    ) { Text("+ Add item") }
                }
            }
        }
    }

    @Composable
    private fun EntryEditor(e: Entry, isNew: Boolean, cancel: () -> Unit, save: (Entry) -> Unit) {
        var title by remember { mutableStateOf(e.title) }
        var username by remember { mutableStateOf(e.username) }
        var password by remember { mutableStateOf(e.password) }
        var website by remember { mutableStateOf(e.website) }
        var notes by remember { mutableStateOf(e.notes) }
        var category by remember { mutableStateOf(e.category) }
        var favorite by remember { mutableStateOf(e.favorite) }
        var note by remember { mutableStateOf(e.kind == Kind.NOTE) }
        var show by remember { mutableStateOf(false) }

        var showOptional by remember { mutableStateOf(e.category.isNotBlank() || (!note && e.notes.isNotBlank())) }
        var confirmDiscard by remember { mutableStateOf(false) }
        var attemptedSave by remember { mutableStateOf(false) }
        val dirty = title != e.title || username != e.username || password != e.password ||
            website != e.website || notes != e.notes || category != e.category || favorite != e.favorite || note != (e.kind == Kind.NOTE)
        val requestCancel = { if (dirty) confirmDiscard = true else cancel() }
        val saveItem = {
            attemptedSave = true
            if (title.isNotBlank()) {
                save(e.copy(title = title.trim(), username = if (note) "" else username,
                    password = if (note) "" else password, website = if (note) "" else website,
                    notes = notes, category = category.trim(), favorite = favorite,
                    kind = if (note) Kind.NOTE else Kind.PASSWORD))
            }
        }
        BackHandler(enabled = recoveryKey == null) { requestCancel() }
        if (confirmDiscard) {
            AlertDialog(
                onDismissRequest = { confirmDiscard = false },
                title = { Text("Discard your changes?") },
                text = { Text("Your changes haven’t been saved.") },
                confirmButton = { TextButton(onClick = cancel) { Text("Discard changes") } },
                dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") } }
            )
        }
        val quickCategories = listOf("Personal", "Work", "Finance", "Shopping", "Social")
        Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = requestCancel) { Text("Cancel") }
                Text(if (isNew) "Add item" else "Edit item", modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                Button(onClick = saveItem) { Text("Save") }
            }
            Text("Save before switching apps. Leaving the app locks your vault and clears unsaved changes.", style = MaterialTheme.typography.bodySmall)
            Column(
                modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                SectionCard(
                    title = if (isNew) "New Vault Item" else "Edit Vault Item",
                    subtitle = null
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().selectableGroup(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        val loginSelected = !note
                        Surface(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .heightIn(min = 48.dp).selectable(selected = !note, role = Role.RadioButton, onClick = { note = false }),
                            shape = RoundedCornerShape(10.dp),
                            color = if (loginSelected) VaultThemeColors.AccentEmerald.copy(alpha = 0.16f) else VaultThemeColors.BgElevated,
                            border = BorderStroke(
                                1.dp,
                                if (loginSelected) VaultThemeColors.AccentEmerald else VaultThemeColors.BorderSubtle
                            )
                        ) {
                            Text(
                                "Login",
                                style = MaterialTheme.typography.labelLarge,
                                color = if (loginSelected) VaultThemeColors.AccentEmerald else VaultThemeColors.TextSecondary,
                                modifier = Modifier.padding(vertical = 10.dp, horizontal = 12.dp)
                            )
                        }
                        Surface(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .heightIn(min = 48.dp).selectable(selected = note, role = Role.RadioButton, onClick = { note = true }),
                            shape = RoundedCornerShape(10.dp),
                            color = if (note) VaultThemeColors.AccentCyan.copy(alpha = 0.16f) else VaultThemeColors.BgElevated,
                            border = BorderStroke(
                                1.dp,
                                if (note) VaultThemeColors.AccentCyan else VaultThemeColors.BorderSubtle
                            )
                        ) {
                            Text(
                                "Note",
                                style = MaterialTheme.typography.labelLarge,
                                color = if (note) VaultThemeColors.AccentCyan else VaultThemeColors.TextSecondary,
                                modifier = Modifier.padding(vertical = 10.dp, horizontal = 12.dp)
                            )
                        }
                    }

                    VaultTextField(
                        value = title,
                        onValueChange = { title = it },
                        label = "Name",
                        error = if (attemptedSave && title.isBlank()) "Give this item a name so you can find it later." else null,
                        placeholder = "e.g. Email, Bank, Home Wi-Fi"
                    )

                    if (!note) {
                        VaultTextField(
                            value = username,
                            onValueChange = { username = it },
                            label = "Username or Email",
                            placeholder = "name@example.com"
                        )
                        VaultSecretField(
                            value = password,
                            onValueChange = { password = it },
                            label = "Password",
                            visible = show,
                            onToggleVisible = { show = !show }
                        )

                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = VaultThemeColors.BgElevated,
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                val strengthLabel = when {
                                    password.isEmpty() -> "Enter or generate a strong password"
                                    password.length < 12 -> "Short (${password.length} chars) — aim for 12+"
                                    else -> "${password.length} characters · length only"
                                }
                                val strengthColor = when {
                                    password.isEmpty() -> VaultThemeColors.TextSecondary
                                    password.length < 12 -> VaultThemeColors.AccentAmber
                                    else -> VaultThemeColors.AccentEmerald
                                }
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Text("Create a password", style = MaterialTheme.typography.titleSmall)
                                }
                                Text(strengthLabel, style = MaterialTheme.typography.bodySmall, color = strengthColor)
                                Text("Random: harder to guess. Words: easier to type. Use a different password for every account.", style = MaterialTheme.typography.bodySmall)
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    OutlinedButton(
                                        onClick = { password = Generator.password(SecureRandomSource(rng::nextInt)) },
                                        modifier = Modifier.weight(1f),
                                        shape = RoundedCornerShape(10.dp),
                                        border = BorderStroke(1.dp, VaultThemeColors.AccentEmerald.copy(alpha = 0.5f))
                                    ) {
                                        Text("Random password", color = VaultThemeColors.AccentEmerald)
                                    }
                                    OutlinedButton(
                                        onClick = { password = Generator.passphrase(SecureRandomSource(rng::nextInt)) },
                                        modifier = Modifier.weight(1f),
                                        shape = RoundedCornerShape(10.dp),
                                        border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                                    ) {
                                        Text("6 words", color = VaultThemeColors.AccentCyan)
                                    }
                                }
                            }
                        }

                        VaultTextField(
                            value = website,
                            onValueChange = { website = it },
                            label = "Website (optional)",
                            placeholder = "https://example.com",
                            keyboardType = KeyboardType.Uri
                        )
                    }

                    if (!note) {
                        TextButton(onClick = { showOptional = !showOptional }) {
                            Text(if (showOptional) "Hide extra details" else "Add notes, category or favourite")
                        }
                    }
                    if (note || showOptional) {
                        VaultTextField(
                            value = notes,
                            onValueChange = { notes = it },
                            label = if (note) "Private Note Content" else "Notes (optional)",
                            placeholder = "Recovery details, account numbers, or private text",
                            singleLine = false
                        )

                        VaultTextField(
                            value = category,
                            onValueChange = { category = it },
                            label = "Category (optional)",
                            placeholder = "Personal, Work, Finance..."
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            quickCategories.forEach { cat ->
                                val selected = category.trim().equals(cat, ignoreCase = true)
                                FilterChip(
                                    selected = selected,
                                    onClick = { category = if (selected) "" else cat },
                                    label = { Text(cat) },
                                    colors = FilterChipDefaults.filterChipColors(
                                        selectedContainerColor = VaultThemeColors.AccentCyan.copy(alpha = 0.16f),
                                        selectedLabelColor = VaultThemeColors.AccentCyan,
                                        containerColor = VaultThemeColors.BgElevated,
                                        labelColor = VaultThemeColors.TextSecondary
                                    ),
                                    border = FilterChipDefaults.filterChipBorder(
                                        enabled = true,
                                        selected = selected,
                                        borderColor = VaultThemeColors.BorderSubtle,
                                        selectedBorderColor = VaultThemeColors.AccentCyan.copy(alpha = 0.6f)
                                    )
                                )
                            }
                        }

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { favorite = !favorite },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Switch(
                                checked = favorite,
                                onCheckedChange = { favorite = it },
                                colors = SwitchDefaults.colors(checkedTrackColor = VaultThemeColors.AccentAmber)
                            )
                            Spacer(Modifier.width(10.dp))
                            Text("Add to favourites", style = MaterialTheme.typography.bodyMedium)
                        }

                    }
                }
            }
        }
    }

    @Composable
    private fun EntryDetails(e: Entry, back: () -> Unit, edit: () -> Unit, delete: () -> Unit, clearHistory: () -> Unit) {
        var show by remember { mutableStateOf(false) }
        var historyVisible by remember { mutableStateOf(false) }
        var confirmDelete by remember { mutableStateOf(false) }
        var confirmHistory by remember { mutableStateOf(false) }

        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(
                    onClick = back,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                ) {
                    Text("← Back to Vault")
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (e.favorite) SecurityPill("★ FAVOURITE", VaultThemeColors.AccentAmber)
                    if (e.category.isNotBlank()) SecurityPill(e.category, VaultThemeColors.AccentCyan)
                }
            }

            SectionCard(
                title = e.title,
                subtitle = if (e.modifiedAt > 0L) {
                    "Last updated ${DateFormat.getDateTimeInstance().format(Date(e.modifiedAt))}"
                } else {
                    null
                },
                badgeText = if (e.kind == Kind.NOTE) "PRIVATE NOTE" else "LOGIN",
                badgeColor = if (e.kind == Kind.NOTE) VaultThemeColors.AccentCyan else VaultThemeColors.AccentEmerald
            ) {
                if (e.kind == Kind.PASSWORD) {
                    if (e.username.isNotBlank()) {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = VaultThemeColors.BgElevated,
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text("Username / Email", style = MaterialTheme.typography.labelSmall)
                                    Text(e.username, style = MaterialTheme.typography.bodyMedium)
                                }
                                TextButton(onClick = { copySecret(e.username, "Username") }) {
                                    Text("Copy", color = VaultThemeColors.AccentCyan)
                                }
                            }
                        }
                    }

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = VaultThemeColors.BgElevated,
                        border = BorderStroke(1.dp, VaultThemeColors.AccentEmerald.copy(alpha = 0.35f))
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text("Password", style = MaterialTheme.typography.labelSmall)
                            Text(
                                text = if (show) e.password else "••••••••••••",
                                style = VaultMonoStyle,
                                fontWeight = FontWeight.Medium
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                OutlinedButton(
                                    onClick = { show = !show },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(10.dp),
                                    border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                                ) {
                                    Text(if (show) "Hide" else "Show")
                                }
                                Button(
                                    onClick = { copySecret(e.password, "Password") },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(10.dp),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = VaultThemeColors.AccentEmerald,
                                        contentColor = VaultThemeColors.OnAccentDark
                                    )
                                ) {
                                    Text("Copy Password")
                                }
                            }
                            Text(
                                "Copied passwords are marked private. The app tries to clear them from the clipboard after 30 seconds.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }

                    if (e.website.isNotBlank()) {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = VaultThemeColors.BgElevated,
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text("Website", style = MaterialTheme.typography.labelSmall)
                                Text(e.website, style = MaterialTheme.typography.bodyMedium, color = VaultThemeColors.AccentCyan)
                            }
                        }
                    }
                }

                if (e.notes.isNotBlank()) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = VaultThemeColors.BgElevated,
                        border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text("Notes", style = MaterialTheme.typography.labelSmall)
                            Text(e.notes, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }

                if (e.history.isNotEmpty()) {
                    HorizontalDivider(color = VaultThemeColors.BorderSubtle)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { historyVisible = !historyVisible }) {
                            Text(
                                if (historyVisible) "Hide Previous Passwords" else "Previous Passwords (${e.history.size})",
                                color = VaultThemeColors.AccentCyan
                            )
                        }
                        TextButton(onClick = { confirmHistory = true }) {
                            Text("Clear History", color = VaultThemeColors.AccentAmber)
                        }
                    }
                    if (historyVisible) {
                        e.history.forEach { previous ->
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(10.dp),
                                color = VaultThemeColors.BgElevated,
                                border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        DateFormat.getDateTimeInstance().format(Date(previous.changedAt)),
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.weight(1f)
                                    )
                                    TextButton(onClick = { copySecret(previous.value, "Previous password") }) {
                                        Text("Copy Old", color = VaultThemeColors.AccentCyan)
                                    }
                                }
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = edit,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = VaultThemeColors.AccentEmerald,
                            contentColor = VaultThemeColors.OnAccentDark
                        )
                    ) {
                        Text("Edit Item")
                    }
                    OutlinedButton(
                        onClick = { confirmDelete = true },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, VaultThemeColors.AccentDanger.copy(alpha = 0.6f))
                    ) {
                        Text("Delete", color = VaultThemeColors.AccentDanger)
                    }
                }
            }
        }

        if (confirmDelete) {
            AlertDialog(
                onDismissRequest = { confirmDelete = false },
                containerColor = VaultThemeColors.BgSurface,
                title = { Text("Delete this item?") },
                text = { Text("It will be removed from your vault right away. Any older backup files you already saved may still contain it.") },
                confirmButton = {
                    TextButton(onClick = delete) {
                        Text("Delete", color = VaultThemeColors.AccentDanger)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
                }
            )
        }
        if (confirmHistory) {
            AlertDialog(
                onDismissRequest = { confirmHistory = false },
                containerColor = VaultThemeColors.BgSurface,
                title = { Text("Clear previous passwords?") },
                text = { Text("This deletes the saved old passwords for this item from your vault. Older backup files may still contain them.") },
                confirmButton = {
                    TextButton(onClick = clearHistory) {
                        Text("Clear", color = VaultThemeColors.AccentAmber)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { confirmHistory = false }) { Text("Cancel") }
                }
            )
        }
    }

    @Composable
    private fun Settings(sv: SessionVault) {
        val v = sv.redactedVault
        val status = securityStatus ?: storage.securityStatus()
        var code by remember { mutableStateOf("") }
        var showImportCode by remember { mutableStateOf(false) }
        var showModeEditor by remember { mutableStateOf(false) }
        var nextMaximum by remember(status.mode) { mutableStateOf(status.mode == "maximum") }
        var nextPass by remember { mutableStateOf("") }
        var nextConfirm by remember { mutableStateOf("") }
        var showNextPass by remember { mutableStateOf(false) }
        var confirmResetRestore by remember { mutableStateOf(false) }
        var showSecurityDetails by remember { mutableStateOf(false) }

        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(
                    onClick = {
                        if (settingsPage == SettingsPage.HUB) {
                            settings = false
                        } else {
                            settingsPage = SettingsPage.HUB
                        }
                    },
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                ) {
                    Text(if (settingsPage == SettingsPage.HUB) "← Back to Vault" else "← Back to Settings")
                }

            }

            if (settingsPage == SettingsPage.HUB) {
                val cloudBadge = when {
                    syncInProgress -> "SAVING"
                    syncUriString.isEmpty() -> "NOT SET"
                    cloudSyncError.isNotEmpty() -> "ERROR"
                    lastCloudSync > 0L && lastCloudSyncRevision == v.revision -> "COPY SAVED"
                    else -> "CHANGES TO SAVE"
                }
                val cloudColor = when {
                    syncInProgress -> VaultThemeColors.AccentCyan
                    syncUriString.isEmpty() -> VaultThemeColors.TextSecondary
                    cloudSyncError.isNotEmpty() -> VaultThemeColors.AccentDanger
                    lastCloudSync > 0L && lastCloudSyncRevision == v.revision -> VaultThemeColors.AccentEmerald
                    else -> VaultThemeColors.AccentAmber
                }
                SettingsNavCard(
                    title = "Automatic backup",
                    subtitle = if (syncUriString.isEmpty()) {
                        "Save a locked copy when your vault changes. Choose Drive or another file location."
                    } else {
                        "Linked: $syncDisplayName"
                    },
                    statusText = cloudBadge,
                    statusColor = cloudColor,
                    onClick = { settingsPage = SettingsPage.CLOUD_SYNC }
                )

                val backupUpToDate = lastExport > 0L && lastExportRevision == v.revision
                SettingsNavCard(
                    title = "Backup & recovery",
                    subtitle = "Save a copy, check that it opens, or recover your passwords.",
                    statusText = if (backupUpToDate) "UP TO DATE" else "BACKUP ADVISED",
                    statusColor = if (backupUpToDate) VaultThemeColors.AccentEmerald else VaultThemeColors.AccentAmber,
                    onClick = { settingsPage = SettingsPage.MANUAL_BACKUP }
                )

                SettingsNavCard(
                    title = "How you unlock",
                    subtitle = if (status.mode == "maximum") {
                        "Phone lock and a separate vault passphrase."
                    } else {
                        "Your phone’s fingerprint or PIN."
                    },
                    statusText = if (status.mode == "maximum") "EXTRA LOCK" else "STANDARD",
                    statusColor = if (status.mode == "maximum") VaultThemeColors.AccentCyan else VaultThemeColors.AccentEmerald,
                    onClick = { settingsPage = SettingsPage.LOCK_MODE }
                )

                SettingsNavCard(
                    title = "Password checkup",
                    subtitle = "Find short or reused passwords, keep old passwords, and manage copies on this phone.",
                    statusText = if (pro && sv.health.reusedEntries > 0) "${sv.health.reusedEntries} REUSED" else "${v.entries.size} ITEMS",
                    statusColor = if (pro && sv.health.reusedEntries > 0) VaultThemeColors.AccentAmber else VaultThemeColors.AccentCyan,
                    onClick = { settingsPage = SettingsPage.HEALTH_AND_SNAPSHOTS }
                )

                SettingsNavCard(
                    title = "How this app works",
                    subtitle = "A short introduction to your vault and keeping a backup.",
                    statusText = "2 MIN READ",
                    statusColor = VaultThemeColors.AccentCyan,
                    onClick = { showGuide = true }
                )

                SectionCard(
                    title = "Appearance",
                    subtitle = "Choose light, dark, or match your phone's system theme."
                ) {
                    ThemeModeSelector(themeMode, ::updateThemeMode)
                }

                LockVaultButton(
                    onClick = { lock(clearPendingBackup = true) },
                    label = "Lock Vault Now",
                    modifier = Modifier.fillMaxWidth()
                )
            }

            if (settingsPage == SettingsPage.CLOUD_SYNC) {
                SectionCard(
                title = "Automatic backup",
                subtitle = "Choose where copies are saved. Your phone’s file provider handles any cloud upload; this app can’t confirm when it finishes.",
                badgeText = when {
                    syncInProgress -> "SAVING"
                    syncUriString.isEmpty() -> "NOT CONNECTED"
                    cloudSyncError.isNotEmpty() -> "SAVE FAILED"
                    !status.hasBackupKey -> "KEY NEEDED"
                    lastCloudSync > 0L && lastCloudSyncRevision == v.revision -> "COPY SAVED"
                    else -> "CHANGES TO SAVE"
                },
                badgeColor = when {
                    syncInProgress -> VaultThemeColors.AccentCyan
                    syncUriString.isEmpty() -> VaultThemeColors.TextSecondary
                    cloudSyncError.isNotEmpty() -> VaultThemeColors.AccentDanger
                    !status.hasBackupKey -> VaultThemeColors.AccentAmber
                    lastCloudSync > 0L && lastCloudSyncRevision == v.revision -> VaultThemeColors.AccentEmerald
                    else -> VaultThemeColors.AccentAmber
                }
            ) {
                if (syncUriString.isEmpty()) {
                    Text(
                        "Choose a file location such as Google Drive. Save the recovery phrase when asked. After that, the app saves an updated locked copy whenever your vault changes. This is a backup, not a way to combine changes from multiple devices.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Button(
                        onClick = { setupOrLinkCloudSync(useFolder = false) },
                        enabled = !busy && !syncInProgress,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = VaultThemeColors.AccentEmerald,
                            contentColor = VaultThemeColors.OnAccentDark
                        )
                    ) {
                        Text("Choose backup location")
                    }
                    OutlinedButton(
                        onClick = { setupOrLinkCloudSync(useFolder = true) },
                        enabled = !busy && !syncInProgress,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                    ) {
                        Text("Choose a folder instead", color = VaultThemeColors.AccentCyan)
                    }
                } else {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = VaultThemeColors.BgElevated,
                        border = BorderStroke(
                            1.dp,
                            if (cloudSyncError.isNotEmpty()) VaultThemeColors.AccentDanger.copy(alpha = 0.6f) else VaultThemeColors.BorderSubtle
                        )
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val kindLabel = if (syncMode == "tree") "Linked Folder" else "Linked Drive File"
                            Text("$kindLabel: $syncDisplayName", style = MaterialTheme.typography.bodySmall)
                            Text(
                                if (lastCloudSync == 0L) {
                                    "No copy saved yet"
                                } else {
                                    "Last copy saved: ${DateFormat.getDateTimeInstance().format(Date(lastCloudSync))}"
                                },
                                style = MaterialTheme.typography.bodySmall
                            )
                            if (cloudSyncError.isNotEmpty()) {
                                Text(cloudSyncError, style = MaterialTheme.typography.bodySmall, color = VaultThemeColors.AccentDanger)
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { performCloudSync(announceSuccess = true) },
                            enabled = !busy && !syncInProgress && status.hasBackupKey,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = VaultThemeColors.AccentEmerald,
                                contentColor = VaultThemeColors.OnAccentDark
                            )
                        ) {
                            Text(if (syncInProgress) "Saving…" else "Back up now")
                        }
                        if (syncMode == "file") {
                            OutlinedButton(
                                onClick = {
                                    loadCloudSyncFileToTest()
                                    if (pendingImport != null) {
                                        settingsPage = SettingsPage.MANUAL_BACKUP
                                    }
                                },
                                enabled = !busy && !syncInProgress,
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(12.dp),
                                border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                            ) {
                                Text("Test recovery", color = VaultThemeColors.AccentCyan)
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = { setupOrLinkCloudSync(useFolder = false) },
                            enabled = !busy && !syncInProgress,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Text("Change location", maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = { setupOrLinkCloudSync(useFolder = true) },
                            enabled = !busy && !syncInProgress,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                        ) {
                            Text("Choose folder", maxLines = 1)
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        TextButton(
                            onClick = {
                                rotateBackupKey(
                                    "Confirm it’s you to replace the recovery phrase",
                                    "New recovery phrase created. Keep older phrases for older backup files."
                                )
                            },
                            enabled = !busy && !syncInProgress,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Replace backup recovery phrase", color = VaultThemeColors.AccentCyan)
                        }
                        TextButton(
                            onClick = { unlinkCloudSync() },
                            enabled = !busy && !syncInProgress
                        ) {
                            Text("Disconnect automatic backup", color = VaultThemeColors.AccentDanger)
                        }
                    }
                }
            }
            }

            if (settingsPage == SettingsPage.MANUAL_BACKUP) {
            SectionCard(
                title = if (pendingImport == null) "Keep a way back in" else "Open your backup",
                subtitle = if (pendingImport == null) "A backup is a locked copy of your passwords. Keep its recovery phrase separately — you need both to open it on another phone. Manual backup and recovery are always free." else "Your file is selected. Enter the recovery phrase or code saved with this backup. This is different from the passphrase used to unlock your vault.",
                badgeText = if (pendingImport != null) null else if (lastExport > 0L && lastExportRevision == v.revision) "UP TO DATE" else "ACTION ADVISED",
                badgeColor = if (lastExport > 0L && lastExportRevision == v.revision) VaultThemeColors.AccentEmerald else VaultThemeColors.AccentAmber
            ) {
                if (pendingImport == null) {
                val exportStatusText = when {
                    lastExport == 0L -> "No backup saved yet"
                    lastExportRevision == v.revision -> "Saved · ${DateFormat.getDateTimeInstance().format(Date(lastExport))} (current)"
                    else -> "Saved ${DateFormat.getDateTimeInstance().format(Date(lastExport))} (older version)"
                }
                val verifiedStatusText = when {
                    lastVerified == 0L -> "Not tested yet"
                    lastVerifiedRevision == v.revision -> "Tested & verified · ${DateFormat.getDateTimeInstance().format(Date(lastVerified))}"
                    else -> "Tested ${DateFormat.getDateTimeInstance().format(Date(lastVerified))} (older version)"
                }

                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = VaultThemeColors.BgElevated,
                    border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text("Latest copy: $exportStatusText", style = MaterialTheme.typography.bodySmall)
                        Text("Recovery check: $verifiedStatusText", style = MaterialTheme.typography.bodySmall)
                    }
                }

                Button(
                    onClick = { newBackup() },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = VaultThemeColors.AccentEmerald,
                        contentColor = VaultThemeColors.OnAccentDark
                    )
                ) {
                    Text("Create backup")
                }

                OutlinedButton(
                    onClick = { importer.launch(arrayOf("*/*")) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                ) {
                    Text("Choose a backup to test or restore", color = VaultThemeColors.AccentCyan)
                }

                }
                if (pendingImport != null) {
                    VaultSecretField(
                        value = code,
                        onValueChange = { code = it },
                        label = "Recovery phrase or code",
                        singleLine = false,
                        visible = showImportCode,
                        onToggleVisible = { showImportCode = !showImportCode }
                    )
                    OutlinedButton(
                        onClick = {
                            verifyBackup(code)
                        },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.6f))
                    ) {
                        Text("Test backup — keep my vault unchanged", color = VaultThemeColors.AccentCyan)
                    }
                    if (v.entries.isEmpty()) {
                        Button(
                            onClick = {
                                restore(code)
                                code = ""
                            },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = VaultThemeColors.AccentEmerald,
                                contentColor = VaultThemeColors.OnAccentDark
                            )
                        ) {
                            Text("Restore passwords")
                        }
                    } else {
                        OutlinedButton(
                            onClick = { confirmResetRestore = true },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, VaultThemeColors.AccentAmber.copy(alpha = 0.7f))
                        ) {
                            Text("Replace my vault with this backup", color = VaultThemeColors.AccentAmber)
                        }
                    }
                    TextButton(
                        onClick = {
                            pendingImport = null
                            code = ""
                        },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Cancel restore")
                    }
                    TextButton(onClick = { importer.launch(arrayOf("*/*")) }, enabled = !busy) { Text("Choose a different backup") }
                }
            }
            }

            if (settingsPage == SettingsPage.LOCK_MODE) {
            SectionCard(
                title = "How you unlock your vault",
                subtitle = if (status.mode == "maximum") {
                    "Your phone lock plus a separate vault passphrase. A passphrase is a password made of words or a longer sentence."
                } else {
                    "Uses your phone’s screen lock. Add a separate passphrase if you want a lock that’s different from your phone PIN."
                },
                badgeText = null
            ) {
                TextButton(onClick = { showSecurityDetails = !showSecurityDetails }) {
                    Text(if (showSecurityDetails) "Hide technical details" else "Technical details")
                }
                if (showSecurityDetails) {
                    Text(
                        "Android Keystore keeps the device key. ${if (status.hardwareBacked) "This phone protects it in security hardware." else "This phone uses its system key storage."} Key status: ${status.keyHealth.name}.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                OutlinedButton(
                    onClick = { showModeEditor = !showModeEditor },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                ) {
                    Text(if (showModeEditor) "Hide Lock Settings" else "Change how I unlock")
                }
                if (showModeEditor) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = VaultThemeColors.BgElevated,
                        border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { nextMaximum = !nextMaximum },
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Switch(
                                    checked = nextMaximum,
                                    onCheckedChange = { nextMaximum = it },
                                    colors = SwitchDefaults.colors(checkedTrackColor = VaultThemeColors.AccentEmerald)
                                )
                                Spacer(Modifier.width(10.dp))
                                Text("Also require a separate vault passphrase", style = MaterialTheme.typography.bodyMedium)
                            }
                            if (nextMaximum) {
                                VaultSecretField(
                                    value = nextPass,
                                    onValueChange = { nextPass = it },
                                    label = "New vault passphrase (16+ chars)",
                                    visible = showNextPass,
                                    onToggleVisible = { showNextPass = !showNextPass }
                                )
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    OutlinedButton(
                                        onClick = {
                                            val generated = Generator.passphrase(SecureRandomSource(rng::nextInt))
                                            nextPass = generated
                                            nextConfirm = generated
                                            showNextPass = true
                                        },
                                        modifier = Modifier.weight(1f),
                                        shape = RoundedCornerShape(10.dp),
                                        border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                                    ) {
                                        Text("Suggest 6 words", color = VaultThemeColors.AccentCyan)
                                    }
                                    if (nextPass.isNotEmpty()) {
                                        OutlinedButton(
                                            onClick = { copySecret(nextPass, "Vault passphrase") },
                                            modifier = Modifier.weight(1f),
                                            shape = RoundedCornerShape(10.dp),
                                            border = BorderStroke(1.dp, VaultThemeColors.AccentEmerald.copy(alpha = 0.5f))
                                        ) {
                                            Text("Copy phrase", color = VaultThemeColors.AccentEmerald)
                                        }
                                    }
                                }
                                VaultSecretField(
                                    value = nextConfirm,
                                    onValueChange = { nextConfirm = it },
                                    label = "Confirm new vault passphrase",
                                    visible = showNextPass
                                )
                            }
                            Button(
                                onClick = {
                                    if (nextMaximum && nextPass != nextConfirm) {
                                        showStatus("Vault passphrases do not match.", isError = true)
                                    } else if (nextMaximum && nextPass.length < 16) {
                                        showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
                                    } else {
                                        changeProtectionMode(if (nextMaximum) nextPass else null)
                                        nextPass = ""
                                        nextConfirm = ""
                                        showNextPass = false
                                        showModeEditor = false
                                    }
                                },
                                enabled = !busy,
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = VaultThemeColors.AccentEmerald,
                                    contentColor = VaultThemeColors.OnAccentDark
                                )
                            ) {
                                Text("Save unlock settings")
                            }
                        }
                    }
                }
            }
            }

            if (settingsPage == SettingsPage.HEALTH_AND_SNAPSHOTS) {
            SectionCard(
                title = "Password checkup & saved copies",
                subtitle = "Spot short or reused passwords and keep previous passwords when you change them. Saved copies on this phone can help undo a change, but won’t protect you if the phone is lost.",
                badgeText = "SAFETY NET",
                badgeColor = VaultThemeColors.AccentCyan
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { commit { it.historyEnabled(!v.keepHistory) } },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Switch(
                        checked = v.keepHistory,
                        onCheckedChange = { checked -> commit { it.historyEnabled(checked) } },
                        colors = SwitchDefaults.colors(checkedTrackColor = VaultThemeColors.AccentEmerald)
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("Save last 5 previous passwords when updating an entry", style = MaterialTheme.typography.bodyMedium)
                }

                if (BuildConfig.DEBUG) {
                    OutlinedButton(
                        onClick = {
                            pro = !pro
                            prefs.edit { putBoolean("testPro", pro) }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, VaultThemeColors.AccentCyan.copy(alpha = 0.5f))
                    ) {
                        Text(
                            if (pro) "Preview Mode: Pro Features On (Tap to Switch Back)" else "Preview Pro Features (Free Test Switch)",
                            color = VaultThemeColors.AccentCyan
                        )
                    }
                }

                if (pro) {
                    val h = sv.health
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = VaultThemeColors.BgElevated,
                        border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text("${h.passwords}", style = MaterialTheme.typography.headlineSmall, color = VaultThemeColors.AccentEmerald)
                                Text("Passwords", style = MaterialTheme.typography.bodySmall)
                            }
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    "${h.reusedEntries}",
                                    style = MaterialTheme.typography.headlineSmall,
                                    color = if (h.reusedEntries > 0) VaultThemeColors.AccentAmber else VaultThemeColors.AccentEmerald
                                )
                                Text("Reused", style = MaterialTheme.typography.bodySmall)
                            }
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    "${h.shortEntries}",
                                    style = MaterialTheme.typography.headlineSmall,
                                    color = if (h.shortEntries > 0) VaultThemeColors.AccentAmber else VaultThemeColors.AccentEmerald
                                )
                                Text("Short (<12)", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }

                    HorizontalDivider(color = VaultThemeColors.BorderSubtle)
                    Text("Saved copies on this phone", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "Keeps the five newest locked copies on this phone as you make changes. Save their recovery phrase separately to open them later.",
                        style = MaterialTheme.typography.bodySmall
                    )

                    if (!status.hasBackupKey) {
                        Button(
                            onClick = { enableSnapshots() },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = VaultThemeColors.AccentCyan,
                                contentColor = VaultThemeColors.BgDeep
                            )
                        ) {
                            Text("Keep automatic copies on this phone")
                        }
                    } else {
                        Text(
                            "${snapshots.size} copies saved on this phone (up to 5). These won’t help if the phone is lost.",
                            style = MaterialTheme.typography.bodySmall,
                            color = VaultThemeColors.AccentEmerald
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { createSnapshotNow() },
                                enabled = !busy,
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(10.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = VaultThemeColors.AccentEmerald,
                                    contentColor = VaultThemeColors.OnAccentDark
                                )
                            ) {
                                Text("Save Now")
                            }
                            OutlinedButton(
                                onClick = { enableSnapshots() },
                                enabled = !busy,
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(10.dp),
                                border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                            ) {
                                Text("New Phrase")
                            }
                        }
                        TextButton(
                            onClick = {
                                storage.disableSnapshots()
                                if (syncUriString.isNotEmpty()) unlinkCloudSync()
                                refreshStatus()
                                showStatus("Automatic restore points turned off and local snapshots deleted.")
                            },
                            enabled = !busy
                        ) {
                            Text("Stop saving and delete local copies", color = VaultThemeColors.AccentDanger)
                        }
                        snapshots.forEach { snap ->
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(10.dp),
                                color = VaultThemeColors.BgElevated,
                                border = BorderStroke(1.dp, VaultThemeColors.BorderSubtle)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        "rev ${snap.revision} · ${DateFormat.getDateTimeInstance().format(Date(snap.createdAt))}",
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.weight(1f)
                                    )
                                    TextButton(onClick = {
                                        runCatching {
                                            pendingImport = storage.readSnapshot(snap.name)
                                            settingsPage = SettingsPage.MANUAL_BACKUP
                                            showStatus("Loaded ${snap.name}. Enter your snapshot recovery phrase below to test or restore.")
                                        }.onFailure {
                                            showStatus("Could not load restore point.", isError = true)
                                        }
                                    }) {
                                        Text("Test", color = VaultThemeColors.AccentCyan)
                                    }
                                    TextButton(onClick = {
                                        runCatching {
                                            pendingExport = storage.readSnapshot(snap.name)
                                            pendingExportRevision = snap.revision
                                            exportPickerActive = true
                                            exporter.launch(snap.name)
                                        }.onFailure {
                                            exportPickerActive = false
                                            showStatus("Could not export restore point.", isError = true)
                                        }
                                    }) {
                                        Text("Export", color = VaultThemeColors.AccentEmerald)
                                    }
                                }
                            }
                        }
                    }
                    Text(
                        "Local copies stay on this phone. For a lost-phone backup, save a copy somewhere else and keep its recovery phrase separately.",
                        style = MaterialTheme.typography.bodySmall
                    )
                } else {
                    Text(
                        "Try the free Pro preview above to check short or reused passwords and keep automatic copies on this phone.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
            }
        }

        if (confirmResetRestore) {
            var replaceMaximum by remember(status.mode) { mutableStateOf(status.mode == "maximum") }
            var replacePass by remember { mutableStateOf("") }
            var replaceConfirm by remember { mutableStateOf("") }
            var showReplacePass by remember { mutableStateOf(false) }

            AlertDialog(
                onDismissRequest = { confirmResetRestore = false },
                containerColor = VaultThemeColors.BgSurface,
                title = { Text("Replace current vault with backup?") },
                text = {
                    Column(
                        modifier = Modifier.verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            "Your backup file and recovery phrase will be checked first. Your existing items are replaced only if the backup decrypts cleanly and you verify your identity.",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { replaceMaximum = !replaceMaximum },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Switch(
                                checked = replaceMaximum,
                                onCheckedChange = { replaceMaximum = it },
                                colors = SwitchDefaults.colors(checkedTrackColor = VaultThemeColors.AccentEmerald)
                            )
                            Spacer(Modifier.width(10.dp))
                            Text("Add a separate vault passphrase", style = MaterialTheme.typography.bodyMedium)
                        }
                        if (replaceMaximum) {
                            VaultSecretField(
                                value = replacePass,
                                onValueChange = { replacePass = it },
                                label = "New vault passphrase (16+ chars)",
                                visible = showReplacePass,
                                onToggleVisible = { showReplacePass = !showReplacePass }
                            )
                            VaultSecretField(
                                value = replaceConfirm,
                                onValueChange = { replaceConfirm = it },
                                label = "Confirm vault passphrase",
                                visible = showReplacePass
                            )
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        if (replaceMaximum && replacePass != replaceConfirm) {
                            showStatus("Vault passphrases do not match.", isError = true)
                        } else if (replaceMaximum && replacePass.length < 16) {
                            showStatus("Vault passphrase must be at least 16 characters long.", isError = true)
                        } else {
                            val recoveryCode = code
                            val passToUse = if (replaceMaximum) replacePass else null
                            resetAndRecover(recoveryCode, passToUse) {
                                code = ""
                                replacePass = ""
                                replaceConfirm = ""
                                confirmResetRestore = false
                            }
                        }
                    }) {
                        Text("Verify & Replace", color = VaultThemeColors.AccentAmber)
                    }
                },
                dismissButton = {
                    TextButton(onClick = {
                        replacePass = ""
                        replaceConfirm = ""
                        confirmResetRestore = false
                    }) { Text("Cancel") }
                }
            )
        }
    }

    @Composable
    private fun RecoveryKeyDialog() {
        val rk = recoveryKey ?: return
        val kit = recoveryKit.orEmpty()
        var step by remember(rk) { mutableIntStateOf(if (recoveryIsSnapshotSetup) 1 else 0) }
        var acknowledged by remember(rk) { mutableStateOf(false) }
        var showCode by remember(rk) { mutableStateOf(false) }
        var copied by remember(rk) { mutableStateOf(false) }
        var confirmDiscard by remember(rk) { mutableStateOf(false) }
        LaunchedEffect(backupFileSaved) { if (backupFileSaved && step == 0) step = 1 }
        val requestClose = { confirmDiscard = true }
        Dialog(
            onDismissRequest = requestClose,
            properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnClickOutside = false)
        ) {
            Surface(modifier = Modifier.fillMaxSize(), color = VaultThemeColors.BgDeep) {
                Column(
                    Modifier.fillMaxSize().systemBarsPadding().padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text("Keep a way back in", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        TextButton(onClick = requestClose) { Text("Cancel") }
                    }
                    Text(
                        if (recoveryIsSnapshotSetup) "Recovery phrase · ${step} of 2" else "Backup · ${step + 1} of 3",
                        style = MaterialTheme.typography.bodySmall
                    )
                    LinearProgressIndicator(
                        progress = { if (recoveryIsSnapshotSetup) step / 2f else (step + 1) / 3f },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Column(
                        Modifier.weight(1f).verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        if (messageIsError && message.isNotEmpty()) {
                            Text(message, color = VaultThemeColors.AccentDanger, style = MaterialTheme.typography.bodyMedium)
                        }
                        when (step) {
                            0 -> {
                                Text("Save your backup file", style = MaterialTheme.typography.headlineMedium)
                                Text("This is a locked copy of your vault. Save it somewhere you can reach if you lose this phone, such as Drive or another device.")
                                Text("The next step gives you the recovery phrase that opens this copy. Each manual backup has its own phrase.", style = MaterialTheme.typography.bodyMedium)
                                Button(
                                    onClick = {
                                        exportPickerActive = true
                                        exporter.launch("password-protection-${System.currentTimeMillis()}.ppvault")
                                    }, modifier = Modifier.fillMaxWidth()
                                ) { Text(if (backupFileSaved) "Save another copy" else "Choose where to save") }
                                Text("The file ends in .ppvault. Its contents stay scrambled until opened with the matching recovery phrase.", style = MaterialTheme.typography.bodySmall)
                            }
                            1 -> {
                                Text("Keep the key to this copy", style = MaterialTheme.typography.headlineMedium)
                                Text("These 33 words are your recovery phrase. Write them down in order and store them separately from the backup file.")
                                Text("Anyone with the file and these words can open it. We can’t replace lost words.", color = VaultThemeColors.AccentAmber)
                                Surface(shape = RoundedCornerShape(12.dp), color = VaultThemeColors.BgSurface) {
                                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                        kit.split(" ").filter { it.isNotBlank() }.chunked(3).forEachIndexed { row, words ->
                                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                                words.forEachIndexed { col, word ->
                                                    Text("${row * 3 + col + 1}. $word", modifier = Modifier.weight(1f), style = VaultMonoStyle.copy(letterSpacing = androidx.compose.ui.unit.TextUnit.Unspecified))
                                                }
                                            }
                                        }
                                    }
                                }
                                OutlinedButton(onClick = { copySecret(kit, "Recovery phrase"); copied = true }, modifier = Modifier.fillMaxWidth()) {
                                    Text(if (copied) "Copied · copy again" else "Copy recovery phrase")
                                }
                                Text("You can switch apps to store it. This page stays available when you return; the vault itself locks in the background.", style = MaterialTheme.typography.bodySmall)
                                TextButton(onClick = { showCode = !showCode }) { Text(if (showCode) "Hide alternative code" else "Use a compact code instead") }
                                if (showCode) {
                                    Text("This code opens the same backup. Save either the words or the code — you don’t need both.", style = MaterialTheme.typography.bodySmall)
                                    SelectionContainer { Text(rk, style = VaultMonoStyle) }
                                    OutlinedButton(onClick = { copySecret(rk, "Recovery code") }) { Text("Copy code") }
                                }
                            }
                            else -> {
                                Text("Your recovery checklist", style = MaterialTheme.typography.headlineMedium)
                                Text(if (recoveryIsSnapshotSetup) "Your new phrase opens copies saved with it. Keep any older recovery phrases for older backups." else "Keep this file and its phrase as a matching pair. A phrase from a different manual backup won’t open this file.")
                                Text("Next: use Test backup in Settings to check that the file and phrase work together. Saving a file alone doesn’t test recovery.")
                                Row(
                                    Modifier.fillMaxWidth().clickable(role = Role.Checkbox) { acknowledged = !acknowledged },
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Checkbox(checked = acknowledged, onCheckedChange = null)
                                    Text("I saved my recovery phrase or code separately from the backup.", modifier = Modifier.padding(start = 10.dp))
                                }
                            }
                        }
                    }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (step > (if (recoveryIsSnapshotSetup) 1 else 0)) {
                            OutlinedButton(onClick = { step-- }) { Text("Back") }
                        }
                        Button(
                            onClick = { if (step < 2) step++ else clearBackupExportState() },
                            enabled = when (step) { 0 -> backupFileSaved; 2 -> acknowledged; else -> true },
                            modifier = Modifier.weight(1f)
                        ) { Text(if (step == 2) "Finish" else "Continue") }
                    }
                }
            }
            if (confirmDiscard) {
                AlertDialog(
                    onDismissRequest = { confirmDiscard = false },
                    title = { Text("Leave backup setup?") },
                    text = { Text("Make sure you have the recovery phrase before leaving. You won’t be able to view this phrase here again. A saved file without its phrase can’t be recovered.") },
                    confirmButton = { TextButton(onClick = { clearBackupExportState() }) { Text("Leave setup") } },
                    dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep setting up") } }
                )
            }
        }
    }
}
