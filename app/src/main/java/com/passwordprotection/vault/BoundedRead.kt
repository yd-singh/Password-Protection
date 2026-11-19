package com.passwordprotection.vault

import java.io.InputStream
import java.io.ByteArrayOutputStream
internal fun InputStream.readBounded(max: Int): ByteArray {
    val out = ByteArrayOutputStream(); val buffer = ByteArray(8192)
    while (true) {
        val n = read(buffer); if (n < 0) break
        require(n <= max - out.size()) { "File exceeds size limit" }
        out.write(buffer,0,n)
    }
    return out.toByteArray()
}
