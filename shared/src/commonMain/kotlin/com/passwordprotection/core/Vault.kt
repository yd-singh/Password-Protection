package com.passwordprotection.core

enum class Kind { PASSWORD, NOTE }
data class PreviousPassword(val value: String, val changedAt: Long)
data class Entry(val id: String, val title: String, val username: String = "", val password: String = "", val website: String = "", val notes: String = "", val category: String = "", val favorite: Boolean = false, val modifiedAt: Long = 0, val kind: Kind = Kind.PASSWORD, val history: List<PreviousPassword> = emptyList())
data class Vault(val entries: List<Entry> = emptyList(), val keepHistory: Boolean = true, val revision: Long = 0) {
    fun save(entry: Entry, now: Long): Vault {
        require(entry.title.isNotBlank())
        require(entry.kind == Kind.NOTE || entry.password.isNotEmpty())
        val old = entries.find { it.id == entry.id }
        val history = when {
            !keepHistory || entry.kind == Kind.NOTE -> emptyList()
            old != null && old.password.isNotEmpty() && old.password != entry.password -> (listOf(PreviousPassword(old.password, now)) + entry.history).take(5)
            else -> entry.history.take(5)
        }
        return copy(entries = entries.filterNot { it.id == entry.id } + entry.copy(history = history, modifiedAt = now), revision = revision + 1)
    }
    fun delete(id: String) = copy(entries = entries.filterNot { it.id == id }, revision = revision + 1)
    fun historyEnabled(enabled: Boolean) = copy(keepHistory = enabled, entries = if (enabled) entries else entries.map { it.copy(history = emptyList()) }, revision = revision + 1)
    fun search(query: String, favoritesOnly: Boolean = false) = entries.filter { (!favoritesOnly || it.favorite) && listOf(it.title, it.username, it.website, it.category).any { field -> field.contains(query, true) } }.sortedWith(compareByDescending<Entry> { it.favorite }.thenBy { it.title.lowercase() })
    fun health(): Health {
        val passwords = entries.filter { it.kind == Kind.PASSWORD && it.password.isNotEmpty() }
        val reused = passwords.groupingBy { it.password }.eachCount().filterValues { it > 1 }.keys
        return Health(passwords.size, passwords.count { it.password in reused }, passwords.count { it.password.length < 12 })
    }
}
data class Health(val passwords: Int, val reusedEntries: Int, val shortEntries: Int)
fun interface SecureRandomSource { fun nextInt(bound: Int): Int }
object Generator {
    private val groups = listOf(
        "abcdefghijkmnopqrstuvwxyz",
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "23456789",
        "!@#%&*+-=?_"
    )

    fun password(random: SecureRandomSource, length: Int = 24): String {
        require(length in 12..128)
        val pool = groups.joinToString("")
        // Rejection sampling of complete candidates preserves a uniform conditional distribution.
        while (true) {
            val candidate = buildString { repeat(length) { append(pool[random.nextInt(pool.length)]) } }
            if (groups.all { g -> candidate.any { it in g } }) return candidate
        }
    }

    /** Generates a uniform random word-based passphrase from the 256-word dictionary. */
    fun passphrase(random: SecureRandomSource, words: Int = 6, separator: String = "-"): String {
        require(words in 4..24)
        require(separator.isNotEmpty())
        val dict = RecoveryKit.wordList
        return (0 until words).joinToString(separator) { dict[random.nextInt(dict.size)] }
    }
}

/** Encodes and decodes 32-byte recovery keys as a 33-word mnemonic phrase with an 8-bit checksum. */
object RecoveryKit {
    val wordList: List<String> = listOf(
        "able", "acid", "aged", "also", "amid", "arch", "area", "army", "atom", "aunt", "auto", "avid", "away", "axis", "baby", "back",
        "bake", "bald", "ball", "band", "bank", "bark", "barn", "base", "bath", "bead", "beam", "bean", "bear", "beat", "beck", "beef",
        "bell", "belt", "bend", "best", "bike", "bird", "bite", "blue", "blur", "boat", "body", "boil", "bold", "bolt", "bond", "bone",
        "book", "boom", "boot", "born", "boss", "both", "bowl", "brim", "bulk", "bull", "bump", "burn", "bush", "busy", "byte", "cafe",
        "cage", "cake", "calf", "call", "calm", "came", "camp", "cane", "cape", "card", "care", "carp", "cart", "case", "cash", "cast",
        "cave", "cell", "cent", "chat", "chef", "chin", "chip", "chop", "city", "clad", "clam", "clap", "clay", "clip", "club", "clue",
        "coal", "coat", "code", "coil", "coin", "cold", "comb", "come", "cone", "cook", "cool", "cope", "copy", "cord", "core", "cork",
        "corn", "cost", "cozy", "crab", "crew", "crop", "crow", "cube", "curb", "cure", "curl", "cute", "cyan", "dale", "dame", "damp",
        "dare", "dark", "dart", "dash", "data", "date", "dawn", "days", "deal", "dear", "debt", "deck", "deed", "deep", "deer", "demo",
        "desk", "dial", "dice", "dime", "dine", "dirt", "disc", "dish", "dock", "dome", "done", "door", "dose", "dove", "down", "drag",
        "draw", "drew", "drip", "drop", "drum", "duck", "duct", "duet", "duke", "dull", "dune", "dusk", "dust", "duty", "each", "earn",
        "ease", "east", "easy", "echo", "edge", "edit", "else", "emit", "envy", "epic", "even", "ever", "evil", "exam", "exit", "face",
        "fact", "fade", "fail", "fair", "fake", "fall", "fame", "farm", "fast", "fate", "fawn", "fear", "feat", "feed", "feel", "feet",
        "fell", "felt", "fern", "fest", "file", "fill", "film", "find", "fine", "fire", "firm", "fish", "fist", "five", "flag", "flak",
        "flame", "flap", "flat", "flea", "fled", "flew", "flex", "flip", "flit", "flow", "foam", "foil", "fold", "folk", "fond", "font",
        "food", "fool", "foot", "ford", "fore", "fork", "form", "fort", "foul", "four", "fowl", "foxy", "free", "frog", "from", "fuel"
    )

    private val wordIndex: Map<String, Int> by lazy {
        check(wordList.size == 256)
        wordList.withIndex().associate { (index, word) -> word to index }.also { check(it.size == 256) }
    }

    private fun checksumByte(key: ByteArray): Int =
        key.fold(0x5A) { acc, b -> ((acc * 33) xor (b.toInt() and 0xFF)) and 0xFF }

    fun encodeWords(key: ByteArray): String {
        require(key.size == 32)
        val dict = wordList
        check(dict.size == 256)
        val indices = IntArray(33)
        for (i in 0 until 32) {
            indices[i] = key[i].toInt() and 0xFF
        }
        indices[32] = checksumByte(key)
        return indices.joinToString(" ") { dict[it] }
    }

    fun decodeWords(phrase: String): ByteArray {
        val tokens = phrase.trim().lowercase().split(Regex("[\\s-]+")).filter { it.isNotEmpty() }
        require(tokens.size == 33) { "Recovery kit must contain 33 words" }
        val indexMap = wordIndex
        val key = ByteArray(32)
        for (i in 0 until 32) {
            val idx = indexMap[tokens[i]] ?: throw IllegalArgumentException("Unknown recovery word")
            key[i] = idx.toByte()
        }
        val expected = indexMap[tokens[32]] ?: throw IllegalArgumentException("Unknown recovery word")
        require(checksumByte(key) == expected) { "Invalid recovery kit checksum" }
        return key
    }
}

/** Platform-independent version 1 JSON vault serializer and strict validator. */
object VaultCodec {
    private const val MAX_JSON_BYTES = 16_000_000
    private const val MAX_ENTRIES = 100_000
    private const val MAX_HISTORY = 5

    fun encode(vault: Vault): ByteArray {
        val sb = StringBuilder(256)
        sb.append('{')
        sb.append("\"version\":1,")
        sb.append("\"revision\":").append(vault.revision).append(',')
        sb.append("\"history\":").append(vault.keepHistory).append(',')
        sb.append("\"entries\":[")
        vault.entries.forEachIndexed { index, e ->
            if (index > 0) sb.append(',')
            sb.append('{')
            appendField(sb, "id", e.id, true)
            appendField(sb, "title", e.title, true)
            appendField(sb, "username", e.username, true)
            appendField(sb, "password", e.password, true)
            appendField(sb, "website", e.website, true)
            appendField(sb, "notes", e.notes, true)
            appendField(sb, "category", e.category, true)
            sb.append("\"favorite\":").append(e.favorite).append(',')
            sb.append("\"modified\":").append(e.modifiedAt).append(',')
            appendField(sb, "kind", e.kind.name, true)
            sb.append("\"previous\":[")
            e.history.forEachIndexed { hIndex, p ->
                if (hIndex > 0) sb.append(',')
                sb.append('{')
                appendField(sb, "value", p.value, true)
                sb.append("\"changed\":").append(p.changedAt)
                sb.append('}')
            }
            sb.append("]}")
        }
        sb.append("]}")
        return sb.toString().encodeToByteArray()
    }

    fun decode(bytes: ByteArray): Vault {
        require(bytes.size <= MAX_JSON_BYTES)
        val text = bytes.decodeToString(throwOnInvalidSequence = true)
        val root = JsonReader(text).parseRootObject()
        require(requireLong(root, "version") == 1L)
        val revision = requireLong(root, "revision")
        val keepHistory = requireBoolean(root, "history")
        val rawEntries = requireArray(root, "entries")
        require(rawEntries.size <= MAX_ENTRIES)
        val entries = rawEntries.map { item ->
            val obj = item as? Map<*, *> ?: throw IllegalArgumentException("Invalid entry object")
            val rawHistory = requireArray(obj, "previous")
            require(rawHistory.size <= MAX_HISTORY)
            val history = rawHistory.map { hItem ->
                val hObj = hItem as? Map<*, *> ?: throw IllegalArgumentException("Invalid history object")
                PreviousPassword(requireString(hObj, "value"), requireLong(hObj, "changed"))
            }
            Entry(
                id = requireString(obj, "id"),
                title = requireString(obj, "title"),
                username = requireString(obj, "username"),
                password = requireString(obj, "password"),
                website = requireString(obj, "website"),
                notes = requireString(obj, "notes"),
                category = requireString(obj, "category"),
                favorite = requireBoolean(obj, "favorite"),
                modifiedAt = requireLong(obj, "modified"),
                kind = Kind.valueOf(requireString(obj, "kind")),
                history = history
            )
        }
        require(entries.map { it.id }.toSet().size == entries.size)
        require(entries.all { it.title.isNotBlank() && (it.kind == Kind.NOTE || it.password.isNotEmpty()) })
        return Vault(entries, keepHistory, revision)
    }

    private fun appendField(sb: StringBuilder, name: String, value: String, comma: Boolean) {
        appendJsonString(sb, name)
        sb.append(':')
        appendJsonString(sb, value)
        if (comma) sb.append(',')
    }

    private fun appendJsonString(sb: StringBuilder, value: String) {
        sb.append('"')
        for (ch in value) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (ch.code < 0x20) {
                    sb.append("\\u00")
                    val hex = ch.code.toString(16).padStart(2, '0')
                    sb.append(hex)
                } else {
                    sb.append(ch)
                }
            }
        }
        sb.append('"')
    }

    private fun requireString(obj: Map<*, *>, key: String): String {
        require(obj.containsKey(key)) { "Missing field: $key" }
        return obj[key] as? String ?: throw IllegalArgumentException("Expected string for $key")
    }

    private fun requireBoolean(obj: Map<*, *>, key: String): Boolean {
        require(obj.containsKey(key)) { "Missing field: $key" }
        return obj[key] as? Boolean ?: throw IllegalArgumentException("Expected boolean for $key")
    }

    private fun requireLong(obj: Map<*, *>, key: String): Long {
        require(obj.containsKey(key)) { "Missing field: $key" }
        return obj[key] as? Long ?: throw IllegalArgumentException("Expected integer for $key")
    }

    private fun requireArray(obj: Map<*, *>, key: String): List<*> {
        require(obj.containsKey(key)) { "Missing field: $key" }
        return obj[key] as? List<*> ?: throw IllegalArgumentException("Expected array for $key")
    }

    private class JsonReader(private val input: String) {
        private var pos = 0

        fun parseRootObject(): Map<String, Any?> {
            skipWhitespace()
            val obj = parseObject(0)
            skipWhitespace()
            require(pos == input.length) { "Trailing JSON content" }
            return obj
        }

        private fun parseValue(depth: Int): Any? {
            require(depth <= 32) { "JSON nesting limit exceeded" }
            skipWhitespace()
            require(pos < input.length) { "Unexpected end of JSON" }
            return when (val ch = input[pos]) {
                '{' -> parseObject(depth + 1)
                '[' -> parseArray(depth + 1)
                '"' -> parseString()
                't' -> parseLiteral("true", true)
                'f' -> parseLiteral("false", false)
                'n' -> parseLiteral("null", null)
                '-', in '0'..'9' -> parseNumber()
                else -> throw IllegalArgumentException("Unexpected token: $ch")
            }
        }

        private fun parseObject(depth: Int): Map<String, Any?> {
            expect('{')
            skipWhitespace()
            val map = LinkedHashMap<String, Any?>()
            if (peek('}')) {
                pos++
                return map
            }
            while (true) {
                skipWhitespace()
                require(pos < input.length && input[pos] == '"') { "Expected object key" }
                val key = parseString()
                skipWhitespace()
                expect(':')
                val value = parseValue(depth)
                map[key] = value
                skipWhitespace()
                if (peek(',')) {
                    pos++
                } else if (peek('}')) {
                    pos++
                    return map
                } else {
                    throw IllegalArgumentException("Expected ',' or '}'")
                }
            }
        }

        private fun parseArray(depth: Int): List<Any?> {
            expect('[')
            skipWhitespace()
            val list = ArrayList<Any?>()
            if (peek(']')) {
                pos++
                return list
            }
            while (true) {
                list.add(parseValue(depth))
                skipWhitespace()
                if (peek(',')) {
                    pos++
                } else if (peek(']')) {
                    pos++
                    return list
                } else {
                    throw IllegalArgumentException("Expected ',' or ']'")
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (pos < input.length) {
                val ch = input[pos++]
                when {
                    ch == '"' -> return sb.toString()
                    ch.code < 0x20 -> throw IllegalArgumentException("Unescaped control character in JSON string")
                    ch == '\\' -> {
                        require(pos < input.length) { "Unterminated escape sequence" }
                        when (val esc = input[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                require(pos + 4 <= input.length) { "Invalid unicode escape" }
                                val code = input.substring(pos, pos + 4).toIntOrNull(16)
                                    ?: throw IllegalArgumentException("Invalid hex escape")
                                sb.append(code.toChar())
                                pos += 4
                            }
                            else -> throw IllegalArgumentException("Invalid escape character: $esc")
                        }
                    }
                    else -> sb.append(ch)
                }
            }
            throw IllegalArgumentException("Unterminated JSON string")
        }

        private fun parseLiteral(expected: String, value: Any?): Any? {
            require(input.startsWith(expected, pos)) { "Invalid JSON literal" }
            pos += expected.length
            return value
        }

        private fun parseNumber(): Number {
            val start = pos
            if (peek('-')) pos++
            require(pos < input.length) { "Invalid JSON number" }
            if (input[pos] == '0') {
                pos++
            } else {
                require(input[pos] in '1'..'9') { "Invalid JSON number" }
                while (pos < input.length && input[pos] in '0'..'9') pos++
            }
            var isFloat = false
            if (pos < input.length && input[pos] == '.') {
                isFloat = true
                pos++
                require(pos < input.length && input[pos] in '0'..'9') { "Invalid JSON fraction" }
                while (pos < input.length && input[pos] in '0'..'9') pos++
            }
            if (pos < input.length && (input[pos] == 'e' || input[pos] == 'E')) {
                isFloat = true
                pos++
                if (pos < input.length && (input[pos] == '+' || input[pos] == '-')) pos++
                require(pos < input.length && input[pos] in '0'..'9') { "Invalid JSON exponent" }
                while (pos < input.length && input[pos] in '0'..'9') pos++
            }
            val token = input.substring(start, pos)
            return if (isFloat) {
                token.toDouble()
            } else {
                token.toLongOrNull() ?: throw IllegalArgumentException("Integer out of range: $token")
            }
        }

        private fun skipWhitespace() {
            while (pos < input.length) {
                when (input[pos]) {
                    ' ', '\t', '\n', '\r' -> pos++
                    else -> return
                }
            }
        }

        private fun peek(expected: Char): Boolean = pos < input.length && input[pos] == expected

        private fun expect(expected: Char) {
            require(pos < input.length && input[pos] == expected) { "Expected '$expected'" }
            pos++
        }
    }
}
