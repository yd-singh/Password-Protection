package com.passwordprotection.vault

import com.passwordprotection.core.*
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Aead {
    private val random = SecureRandom()

    fun randomBytes(size: Int) = ByteArray(size).also(random::nextBytes)

    fun seal(key: ByteArray, data: ByteArray, context: String): ByteArray {
        require(key.size == 32)
        val nonce = randomBytes(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(context.toByteArray(Charsets.UTF_8))
        return nonce + cipher.doFinal(data)
    }

    fun open(key: ByteArray, blob: ByteArray, context: String): ByteArray {
        require(key.size == 32 && blob.size >= 28)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        cipher.updateAAD(context.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(blob, 12, blob.size - 12)
    }
}

object PortableBackup {
    private val magic = "PPBACKUP1".toByteArray(Charsets.US_ASCII)
    private const val context = "PasswordProtection/portable-backup/v1"

    fun recoveryKey() = Aead.randomBytes(32)

    fun encodeKey(key: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(key)

    fun decodeKey(text: String): ByteArray {
        val trimmed = text.trim()
        val key = Base64.getUrlDecoder().decode(trimmed)
        require(key.size == 32 && encodeKey(key) == trimmed) { "Invalid recovery key" }
        return key
    }

    fun encodeKit(key: ByteArray): String = RecoveryKit.encodeWords(key)

    fun decodeFlexibleKey(text: String): ByteArray {
        val trimmed = text.trim()
        return if (trimmed.any { it.isWhitespace() } || (trimmed.length > 64 && '-' in trimmed)) {
            RecoveryKit.decodeWords(trimmed)
        } else {
            decodeKey(trimmed)
        }
    }

    fun export(key: ByteArray, plaintext: ByteArray) = magic + Aead.seal(key, plaintext, context)

    fun restore(key: ByteArray, file: ByteArray): ByteArray {
        require(file.size in (magic.size + 28)..16_777_216)
        require(file.copyOfRange(0, magic.size).contentEquals(magic)) { "Unsupported backup format" }
        return Aead.open(key, file.copyOfRange(magic.size, file.size), context)
    }
}

/**
 * Holds an unlocked vault in memory with each entry's sensitive payload sealed under an
 * ephemeral session key, exposing only redacted metadata until a single entry is opened.
 */
class SessionVault(initial: Vault) {
    private val sessionKey = Aead.randomBytes(32)
    private var closed = false

    val health: Health = initial.health()
    private val historySizes: Map<String, Int> = initial.entries.associate { it.id to it.history.size }
    private val sealedRecords: Map<String, ByteArray> = buildMap {
        try {
            for (entry in initial.entries) {
                val bytes = VaultCodec.encode(Vault(listOf(entry)))
                try {
                    put(entry.id, Aead.seal(sessionKey, bytes, "PasswordProtection/session-record/v1/${entry.id}"))
                } finally {
                    bytes.fill(0)
                }
            }
        } catch (e: Exception) {
            values.forEach { it.fill(0) }
            sessionKey.fill(0)
            closed = true
            throw e
        }
    }

    val redactedVault: Vault = initial.copy(
        entries = initial.entries.map { entry ->
            entry.copy(
                password = if (entry.kind == Kind.PASSWORD) "•" else "",
                notes = "",
                history = emptyList()
            )
        }
    )

    fun historyCount(id: String): Int = historySizes[id] ?: 0

    fun openEntry(id: String): Entry? {
        check(!closed) { "SessionVault is closed" }
        val blob = sealedRecords[id] ?: return null
        val bytes = Aead.open(sessionKey, blob, "PasswordProtection/session-record/v1/$id")
        return try {
            VaultCodec.decode(bytes).entries.single()
        } finally {
            bytes.fill(0)
        }
    }

    fun materialize(): Vault {
        check(!closed) { "SessionVault is closed" }
        val fullEntries = redactedVault.entries.map { redacted ->
            openEntry(redacted.id) ?: error("Missing sealed record for ${redacted.id}")
        }
        return Vault(fullEntries, redactedVault.keepHistory, redactedVault.revision)
    }

    fun close() {
        if (closed) return
        closed = true
        sessionKey.fill(0)
        sealedRecords.values.forEach { it.fill(0) }
    }
}
