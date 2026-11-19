package com.passwordprotection.vault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import com.passwordprotection.core.Vault
import java.io.File
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject

class KeyInvalidatedException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

enum class KeyHealth { READY, NOT_CREATED, INVALIDATED }

data class SecurityStatus(
    val mode: String,
    val keyHealth: KeyHealth,
    val hardwareBacked: Boolean,
    val hasBackupKey: Boolean,
    val snapshotCount: Int
)

data class SnapshotInfo(
    val name: String,
    val revision: Long,
    val createdAt: Long,
    val sizeBytes: Long
)

class Storage(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "vault.v1"))
    private val snapshotsDir = File(context.noBackupFilesDir, "snapshots")
    private val alias = "password-protection-device-wrapper-v1"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val contextTag = "PasswordProtection/local-vault/v1"
    private val snapshotNamePattern = Regex("^snapshot-rev(\\d+)-(\\d+)\\.ppvault$")

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    private fun unb64(s: String) = Base64.getDecoder().decode(s)

    fun exists() = file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()

    fun createDeviceKeyIfNeeded() {
        check(!exists())
        if (ks.containsAlias(alias)) return
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(10, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    .build()
            )
            generateKey()
        }
    }

    private fun deviceKey(): SecretKey {
        return try {
            ks.getKey(alias, null) as? SecretKey
                ?: throw KeyInvalidatedException("Device key unavailable. Recover using a verified backup.")
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException("Device key invalidated by a screen lock or biometric change. Recover using a verified backup.", e)
        } catch (e: UnrecoverableKeyException) {
            throw KeyInvalidatedException("Device key invalidated or unrecoverable. Recover using a verified backup.", e)
        }
    }

    private fun wrap(payload: ByteArray, mode: String): Pair<ByteArray, ByteArray> {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, deviceKey())
            cipher.updateAAD("$contextTag/wrapper/$mode".toByteArray())
            cipher.iv to cipher.doFinal(payload)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException("Device key invalidated by a screen lock or biometric change. Recover using a verified backup.", e)
        } catch (e: UnrecoverableKeyException) {
            throw KeyInvalidatedException("Device key invalidated or unrecoverable. Recover using a verified backup.", e)
        }
    }

    private fun unwrap(nonce: ByteArray, wrapped: ByteArray, mode: String): ByteArray {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, deviceKey(), GCMParameterSpec(128, nonce))
            cipher.updateAAD("$contextTag/wrapper/$mode".toByteArray())
            cipher.doFinal(wrapped)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException("Device key invalidated by a screen lock or biometric change. Recover using a verified backup.", e)
        } catch (e: UnrecoverableKeyException) {
            throw KeyInvalidatedException("Device key invalidated or unrecoverable. Recover using a verified backup.", e)
        }
    }

    fun securityStatus(): SecurityStatus {
        val vaultExists = exists()
        val obj = if (vaultExists) runCatching { read() }.getOrNull() else null
        val mode = obj?.optString("mode", "none") ?: "none"
        val hasBackupKey = obj?.optString("backupKey", "")?.isNotEmpty() == true
        val snapshots = listSnapshots().size
        if (!ks.containsAlias(alias)) {
            return SecurityStatus(
                mode = mode,
                keyHealth = if (vaultExists) KeyHealth.INVALIDATED else KeyHealth.NOT_CREATED,
                hardwareBacked = false,
                hasBackupKey = hasBackupKey,
                snapshotCount = snapshots
            )
        }
        return try {
            val secretKey = ks.getKey(alias, null) as? SecretKey
                ?: return SecurityStatus(mode, KeyHealth.INVALIDATED, false, hasBackupKey, snapshots)
            val factory = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo
            val hardwareBacked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }
            SecurityStatus(mode, KeyHealth.READY, hardwareBacked, hasBackupKey, snapshots)
        } catch (_: KeyPermanentlyInvalidatedException) {
            SecurityStatus(mode, KeyHealth.INVALIDATED, false, hasBackupKey, snapshots)
        } catch (_: UnrecoverableKeyException) {
            SecurityStatus(mode, KeyHealth.INVALIDATED, false, hasBackupKey, snapshots)
        } catch (_: Exception) {
            SecurityStatus(mode, KeyHealth.INVALIDATED, false, hasBackupKey, snapshots)
        }
    }

    private fun derived(passphrase: CharArray, salt: ByteArray): ByteArray {
        require(salt.size == 16)
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(65536)
            .withIterations(3)
            .withParallelism(1)
            .build()
        return ByteArray(32).also { Argon2BytesGenerator().apply { init(params) }.generateBytes(passphrase, it) }
    }

    private fun read(): JSONObject = file.openRead().use { stream ->
        val bytes = stream.readBounded(24_000_000)
        JSONObject(bytes.toString(Charsets.UTF_8)).also { require(it.getInt("v") == 1) }
    }

    private fun write(obj: JSONObject) {
        val bytes = obj.toString().toByteArray(Charsets.UTF_8)
        require(bytes.size <= 24_000_000)
        val stream = file.startWrite()
        try {
            stream.write(bytes)
            file.finishWrite(stream)
        } catch (e: Exception) {
            file.failWrite(stream)
            throw e
        }
    }

    data class Opened(val mode: String, val payload: ByteArray, val salt: ByteArray, val encrypted: ByteArray)

    fun deviceUnlock(): Opened {
        val obj = read()
        val mode = obj.getString("mode")
        require(mode == "standard" || mode == "maximum")
        return Opened(
            mode,
            unwrap(unb64(obj.getString("iv")), unb64(obj.getString("wrapped")), mode),
            unb64(obj.getString("salt")),
            unb64(obj.getString("data"))
        )
    }

    fun openKey(opened: Opened, passphrase: CharArray?): ByteArray {
        if (opened.mode == "standard") return opened.payload.copyOf().also { require(it.size == 32) }
        require(passphrase != null)
        val key = derived(passphrase, opened.salt)
        return try {
            Aead.open(key, opened.payload, "$contextTag/passphrase").also { require(it.size == 32) }
        } finally {
            key.fill(0)
        }
    }

    fun decrypt(key: ByteArray, opened: Opened): Vault =
        Aead.open(key, opened.encrypted, "$contextTag/data").let { bytes ->
            try {
                Codec.decode(bytes)
            } finally {
                bytes.fill(0)
            }
        }

    // Called only following device authentication. The expensive KDF is computed before prompt during setup.
    data class Prepared(val key: ByteArray, val mode: String, val salt: ByteArray, val payload: ByteArray)

    fun prepare(passphrase: CharArray?): Prepared {
        val key = Aead.randomBytes(32)
        val salt = if (passphrase == null) byteArrayOf() else Aead.randomBytes(16)
        try {
            val payload = if (passphrase == null) {
                key.copyOf()
            } else {
                derived(passphrase, salt).let { k ->
                    try {
                        Aead.seal(k, key, "$contextTag/passphrase")
                    } finally {
                        k.fill(0)
                    }
                }
            }
            return Prepared(key, if (passphrase == null) "standard" else "maximum", salt, payload)
        } catch (e: Exception) {
            key.fill(0)
            throw e
        }
    }

    fun create(prepared: Prepared): Vault {
        check(!exists())
        val (iv, wrapped) = wrap(prepared.payload, prepared.mode)
        val vault = Vault()
        val bytes = Codec.encode(vault)
        try {
            write(
                JSONObject()
                    .put("v", 1)
                    .put("mode", prepared.mode)
                    .put("salt", b64(prepared.salt))
                    .put("iv", b64(iv))
                    .put("wrapped", b64(wrapped))
                    .put("data", b64(Aead.seal(prepared.key, bytes, "$contextTag/data")))
            )
        } finally {
            bytes.fill(0)
        }
        return vault
    }

    fun save(key: ByteArray, vault: Vault) {
        val obj = read()
        val bytes = Codec.encode(vault)
        try {
            obj.put("data", b64(Aead.seal(key, bytes, "$contextTag/data")))
            write(obj)
        } finally {
            bytes.fill(0)
        }
        if (obj.optString("backupKey", "").isNotEmpty()) {
            runCatching { writeVerifiedSnapshot(key, vault) }
        }
    }

    fun rekey(oldKey: ByteArray, prepared: Prepared, vault: Vault) {
        val obj = read()
        val (iv, wrapped) = wrap(prepared.payload, prepared.mode)
        val existingBackupKey = obj.optString("backupKey", "")
        if (existingBackupKey.isNotEmpty()) {
            val bk = Aead.open(oldKey, unb64(existingBackupKey), "$contextTag/backup-key")
            val rewrappedBk = try {
                Aead.seal(prepared.key, bk, "$contextTag/backup-key")
            } finally {
                bk.fill(0)
            }
            obj.put("backupKey", b64(rewrappedBk))
        }
        val bytes = Codec.encode(vault)
        try {
            obj.put("v", 1)
                .put("mode", prepared.mode)
                .put("salt", b64(prepared.salt))
                .put("iv", b64(iv))
                .put("wrapped", b64(wrapped))
                .put("data", b64(Aead.seal(prepared.key, bytes, "$contextTag/data")))
            write(obj)
        } finally {
            bytes.fill(0)
        }
    }

    fun resetToEmptyVault(prepared: Prepared): Vault {
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
        }
        file.delete()
        createDeviceKeyIfNeeded()
        return create(prepared)
    }

    fun configureBackupKey(vaultKey: ByteArray): ByteArray {
        val backupKey = PortableBackup.recoveryKey()
        try {
            val wrappedBk = Aead.seal(vaultKey, backupKey, "$contextTag/backup-key")
            val obj = read()
            obj.put("backupKey", b64(wrappedBk))
            write(obj)
            return backupKey
        } catch (e: Exception) {
            backupKey.fill(0)
            throw e
        }
    }

    fun disableSnapshots() {
        if (exists()) {
            val obj = read()
            if (obj.has("backupKey")) {
                obj.remove("backupKey")
                write(obj)
            }
        }
        snapshotsDir.listFiles()?.forEach { it.delete() }
    }

    fun exportWithBackupKey(vaultKey: ByteArray, vault: Vault): ByteArray {
        val obj = read()
        val encodedBk = obj.optString("backupKey", "")
        require(encodedBk.isNotEmpty()) { "Backup key not configured" }
        val backupKey = Aead.open(vaultKey, unb64(encodedBk), "$contextTag/backup-key")
        try {
            val plaintext = Codec.encode(vault)
            return try {
                PortableBackup.export(backupKey, plaintext)
            } finally {
                plaintext.fill(0)
            }
        } finally {
            backupKey.fill(0)
        }
    }

    fun verifyWithBackupKey(vaultKey: ByteArray, blob: ByteArray, expectedVault: Vault) {
        val obj = read()
        val encodedBk = obj.optString("backupKey", "")
        require(encodedBk.isNotEmpty()) { "Backup key not configured" }
        val backupKey = Aead.open(vaultKey, unb64(encodedBk), "$contextTag/backup-key")
        try {
            val verifiedPlaintext = PortableBackup.restore(backupKey, blob)
            val decoded = try {
                Codec.decode(verifiedPlaintext)
            } finally {
                verifiedPlaintext.fill(0)
            }
            require(decoded == expectedVault) { "Backup readback verification mismatch" }
        } finally {
            backupKey.fill(0)
        }
    }

    fun writeVerifiedSnapshot(vaultKey: ByteArray, vault: Vault): SnapshotInfo? {
        val obj = read()
        val encodedBk = obj.optString("backupKey", "")
        if (encodedBk.isEmpty()) return null
        val blob = exportWithBackupKey(vaultKey, vault)
        snapshotsDir.mkdirs()
        val timestamp = System.currentTimeMillis()
        val fileName = "snapshot-rev${vault.revision}-$timestamp.ppvault"
        val targetFile = File(snapshotsDir, fileName)
        val atomic = AtomicFile(targetFile)
        val stream = atomic.startWrite()
        try {
            stream.write(blob)
            atomic.finishWrite(stream)
        } catch (e: Exception) {
            atomic.failWrite(stream)
            throw e
        }
        val readBack = atomic.openRead().use { it.readBounded(16_777_216) }
        verifyWithBackupKey(vaultKey, readBack, vault)
        val retained = listSnapshots()
        retained.drop(5).forEach { old ->
            AtomicFile(File(snapshotsDir, old.name)).delete()
        }
        return SnapshotInfo(fileName, vault.revision, timestamp, targetFile.length())
    }

    fun listSnapshots(): List<SnapshotInfo> {
        val files = snapshotsDir.listFiles() ?: return emptyList()
        return files.mapNotNull { file ->
            val match = snapshotNamePattern.matchEntire(file.name) ?: return@mapNotNull null
            val revision = match.groupValues[1].toLongOrNull() ?: return@mapNotNull null
            val createdAt = match.groupValues[2].toLongOrNull() ?: return@mapNotNull null
            SnapshotInfo(file.name, revision, createdAt, file.length())
        }.sortedWith(compareByDescending<SnapshotInfo> { it.createdAt }.thenByDescending { it.revision }.thenByDescending { it.name })
    }

    fun readSnapshot(name: String): ByteArray {
        require('/' !in name && '\\' !in name && snapshotNamePattern.matches(name)) { "Invalid snapshot name" }
        val target = File(snapshotsDir, name)
        require(target.canonicalFile.parentFile == snapshotsDir.canonicalFile) { "Invalid snapshot path" }
        return AtomicFile(target).openRead().use { it.readBounded(16_777_216) }
    }
}
