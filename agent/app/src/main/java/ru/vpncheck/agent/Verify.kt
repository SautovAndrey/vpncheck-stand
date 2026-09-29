package ru.vpncheck.agent

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

object Verify {
    private fun hexToBytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    internal fun canonical(obj: JSONObject): String {
        val keys = obj.keys().asSequence().filter { it != "signature" }.sorted().toList()
        val sb = StringBuilder("{")
        keys.forEachIndexed { index, key ->
            if (index > 0) sb.append(',')
            sb.append(quote(key)).append(':').append(encode(obj.get(key)))
        }
        return sb.append('}').toString()
    }

    private fun quote(text: String): String {
        val sb = StringBuilder("\"")
        for (ch in text) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (ch < ' ') sb.append("\\u%04x".format(ch.code)) else sb.append(ch)
            }
        }
        return sb.append('"').toString()
    }

    private fun encode(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> canonical(value)
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { encode(value.get(it)) }
        is String -> quote(value)
        is Boolean -> value.toString()
        is Number -> if (value.toDouble() == value.toLong().toDouble()) value.toLong().toString() else value.toString()
        else -> quote(value.toString())
    }

    @Volatile var manifestKey: String = BuildConfig.MANIFEST_PUBKEY

    fun manifestSigned(manifest: JSONObject): Boolean {
        val pub = manifestKey
        val signature = manifest.optString("signature", "")
        if (pub.isEmpty() || signature.isEmpty()) return false
        return try {
            val signer = Ed25519Signer()
            signer.init(false, Ed25519PublicKeyParameters(hexToBytes(pub), 0))
            val message = canonical(manifest).toByteArray(Charsets.UTF_8)
            signer.update(message, 0, message.size)
            signer.verifySignature(hexToBytes(signature))
        } catch (_: Exception) {
            false
        }
    }

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
