package com.passwordprotection.vault

import com.passwordprotection.core.Vault
import com.passwordprotection.core.VaultCodec

object Codec {
    fun encode(vault: Vault): ByteArray = VaultCodec.encode(vault)

    fun decode(bytes: ByteArray): Vault = VaultCodec.decode(bytes)
}
