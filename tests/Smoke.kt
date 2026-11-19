import com.passwordprotection.core.*
import com.passwordprotection.vault.*
import java.security.SecureRandom

fun main() {
    val random = SecureRandom()
    val source = SecureRandomSource(random::nextInt)

    // Password & word passphrase generation
    val p = Generator.password(source, 24)
    check(p.length == 24 && p.any { it.isUpperCase() } && p.any { it.isLowerCase() } && p.any { it.isDigit() })
    val phrase = Generator.passphrase(source, words = 6, separator = "-")
    val phraseWords = phrase.split("-")
    check(phraseWords.size == 6 && phraseWords.all { it in RecoveryKit.wordList })
    check(runCatching { Generator.passphrase(source, words = 3) }.isFailure)
    check(runCatching { Generator.passphrase(source, words = 6, separator = "") }.isFailure)
    check(RecoveryKit.wordList.distinct().size == 256)

    // Vault domain model
    val a = Entry("1", "Example", password = "original")
    val v = Vault().save(a, 1).save(a.copy(password = "replacement"), 2)
    check(v.entries.single().history.single().value == "original")
    check(v.search("EXAMPLE").size == 1 && v.historyEnabled(false).entries.single().history.isEmpty())
    val populated = v
        .save(Entry("2", "Another", username = "user@example.com", password = "replacement", notes = "secret\n\"line\"\t\\end", category = "Work", favorite = true), 3)
        .save(Entry("3", "Secure Note", notes = "Unicode café 🔐\nLine 2", kind = Kind.NOTE), 4)
    check(populated.health().reusedEntries == 2)

    // Recovery key & 33-word mnemonic recovery kit
    val key = PortableBackup.recoveryKey()
    val encodedKey = PortableBackup.encodeKey(key)
    check(PortableBackup.decodeKey(encodedKey).contentEquals(key))
    val kit = PortableBackup.encodeKit(key)
    val kitWords = kit.split(" ")
    check(kitWords.size == 33)
    check(RecoveryKit.decodeWords(kit).contentEquals(key))
    check(PortableBackup.decodeFlexibleKey(encodedKey).contentEquals(key))
    check(PortableBackup.decodeFlexibleKey(kit).contentEquals(key))
    check(PortableBackup.decodeFlexibleKey(kitWords.joinToString("-").uppercase()).contentEquals(key))
    val tamperedKit = kitWords.toMutableList().apply {
        val replacement = RecoveryKit.wordList.first { it != this[0] }
        this[0] = replacement
    }.joinToString(" ")
    check(runCatching { RecoveryKit.decodeWords(tamperedKit) }.isFailure)
    check(runCatching { RecoveryKit.decodeWords(kitWords.dropLast(1).joinToString(" ")) }.isFailure)
    check(runCatching { RecoveryKit.decodeWords((kitWords.dropLast(1) + "notaword").joinToString(" ")) }.isFailure)

    // Multiplatform VaultCodec JSON roundtrip and strict validation
    val encodedVault = VaultCodec.encode(populated)
    val decodedVault = VaultCodec.decode(encodedVault)
    check(decodedVault == populated)
    check(runCatching { VaultCodec.decode("{\"version\":2,\"revision\":0,\"history\":true,\"entries\":[]}".encodeToByteArray()) }.isFailure)
    check(runCatching { VaultCodec.decode("{\"version\":1,\"revision\":0,\"history\":true,\"entries\":[]}trailing".encodeToByteArray()) }.isFailure)
    check(runCatching { VaultCodec.decode("{\"version\":1,\"revision\":0,\"history\":true,\"entries\":[{\"id\":\"1\",\"title\":\"A\nB\",\"username\":\"\",\"password\":\"p\",\"website\":\"\",\"notes\":\"\",\"category\":\"\",\"favorite\":false,\"modified\":1,\"kind\":\"PASSWORD\",\"previous\":[]}]}".encodeToByteArray()) }.isFailure)
    val dupId = "{\"version\":1,\"revision\":1,\"history\":true,\"entries\":[" +
        "{\"id\":\"1\",\"title\":\"One\",\"username\":\"\",\"password\":\"p1\",\"website\":\"\",\"notes\":\"\",\"category\":\"\",\"favorite\":false,\"modified\":1,\"kind\":\"PASSWORD\",\"previous\":[]}," +
        "{\"id\":\"1\",\"title\":\"Two\",\"username\":\"\",\"password\":\"p2\",\"website\":\"\",\"notes\":\"\",\"category\":\"\",\"favorite\":false,\"modified\":2,\"kind\":\"PASSWORD\",\"previous\":[]}]}"
    check(runCatching { VaultCodec.decode(dupId.encodeToByteArray()) }.isFailure)
    val blankTitle = "{\"version\":1,\"revision\":1,\"history\":true,\"entries\":[{\"id\":\"1\",\"title\":\"  \",\"username\":\"\",\"password\":\"p\",\"website\":\"\",\"notes\":\"\",\"category\":\"\",\"favorite\":false,\"modified\":1,\"kind\":\"PASSWORD\",\"previous\":[]}]}"
    check(runCatching { VaultCodec.decode(blankTitle.encodeToByteArray()) }.isFailure)
    val emptyPassword = "{\"version\":1,\"revision\":1,\"history\":true,\"entries\":[{\"id\":\"1\",\"title\":\"Valid\",\"username\":\"\",\"password\":\"\",\"website\":\"\",\"notes\":\"\",\"category\":\"\",\"favorite\":false,\"modified\":1,\"kind\":\"PASSWORD\",\"previous\":[]}]}"
    check(runCatching { VaultCodec.decode(emptyPassword.encodeToByteArray()) }.isFailure)
    val sixHistory = "{\"version\":1,\"revision\":1,\"history\":true,\"entries\":[{\"id\":\"1\",\"title\":\"Valid\",\"username\":\"\",\"password\":\"p\",\"website\":\"\",\"notes\":\"\",\"category\":\"\",\"favorite\":false,\"modified\":1,\"kind\":\"PASSWORD\",\"previous\":[{\"value\":\"1\",\"changed\":1},{\"value\":\"2\",\"changed\":2},{\"value\":\"3\",\"changed\":3},{\"value\":\"4\",\"changed\":4},{\"value\":\"5\",\"changed\":5},{\"value\":\"6\",\"changed\":6}]}]}"
    check(runCatching { VaultCodec.decode(sixHistory.encodeToByteArray()) }.isFailure)

    // SessionVault per-record sealing
    val session = SessionVault(populated)
    check(session.health == populated.health())
    check(session.historyCount("1") == 1)
    check(session.redactedVault.entries.first { it.id == "1" }.password == "•")
    check(session.redactedVault.entries.first { it.id == "2" }.notes.isEmpty())
    check(session.redactedVault.entries.first { it.id == "1" }.history.isEmpty())
    check(session.openEntry("1") == populated.entries.first { it.id == "1" })
    check(session.openEntry("2") == populated.entries.first { it.id == "2" })
    check(session.openEntry("3") == populated.entries.first { it.id == "3" })
    check(session.openEntry("missing") == null)
    check(session.materialize() == populated)
    session.close()
    check(runCatching { session.openEntry("1") }.isFailure)
    check(runCatching { session.materialize() }.isFailure)

    // Portable backup AEAD checks
    val data = encodedVault
    val backup = PortableBackup.export(key, data)
    check(PortableBackup.restore(key, backup).contentEquals(data))
    check(!backup.contentEquals(PortableBackup.export(key, data)))
    check(runCatching { PortableBackup.restore(PortableBackup.recoveryKey(), backup) }.isFailure)
    val altered = backup.copyOf()
    altered[altered.lastIndex] = (altered.last().toInt() xor 1).toByte()
    check(runCatching { PortableBackup.restore(key, altered) }.isFailure)
    check(runCatching { PortableBackup.restore(key, backup.copyOf(10)) }.isFailure)
    val blob = Aead.seal(key, data, "one")
    check(runCatching { Aead.open(key, blob, "two") }.isFailure)

    println("PASS: generator, passphrase, recovery kit, codec, session vault, portable backup and AEAD checks")
}
