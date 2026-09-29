package ru.vpncheck.agent

import android.annotation.SuppressLint
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import org.json.JSONObject
import java.net.ConnectException
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

class PinnedTls(val host: String, val port: Int, val pin: String) {
    class PinMismatch(message: String) : CertificateException(message)

    class Change(val tls: PinnedTls?, val issued: Long)

    @SuppressLint("CustomX509TrustManager")
    val trust: X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw CertificateException("client certificates are not accepted")
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw PinMismatch("server sent no certificate")
            if (pinOf(leaf) != pin) throw PinMismatch("server certificate does not match the pin")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private val factory: SSLSocketFactory = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }.socketFactory

    val base: String = HttpUrl.Builder().scheme("https").host(host).port(port).build().toString().trimEnd('/')

    fun secure(builder: OkHttpClient.Builder): OkHttpClient =
        builder.sslSocketFactory(factory, trust).hostnameVerifier { name, _ -> name.equals(host, ignoreCase = true) }.build()

    companion object {
        private val PIN = Regex("^sha256/[A-Za-z0-9+/]{43}=$")

        fun pinOf(cert: X509Certificate): String =
            "sha256/" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

        fun parse(server: String, tls: JSONObject?): PinnedTls? {
            if (tls == null) return null
            val host = server.toHttpUrlOrNull()?.host ?: return null
            val port = tls.opt("port") as? Number ?: return null
            val pin = tls.opt("pin") as? String ?: return null
            if (port.toDouble() != port.toInt().toDouble() || port.toInt() !in 1..65535 || !PIN.matches(pin)) return null
            return PinnedTls(host, port.toInt(), pin)
        }

        fun fromManifest(server: String, tlsIssued: Long, floor: Long, manifest: JSONObject?): Change? {
            if (manifest == null || !manifest.has("tls") || !Verify.manifestSigned(manifest)) return null
            val issued = manifest.optLong("issued", 0)
            if (issued <= tlsIssued || issued < floor) return null
            val value = manifest.opt("tls")
            if (value == JSONObject.NULL || (value is JSONObject && value.opt("off") == true)) return Change(null, issued)
            val tls = parse(server, value as? JSONObject) ?: return null
            return Change(tls, issued)
        }

        fun isPinFailure(error: Throwable?): Boolean = causes(error).any { it is PinMismatch }

        fun needsRecovery(error: Throwable?): Boolean = causes(error).any { it is PinMismatch || it is ConnectException }

        private fun causes(error: Throwable?): Sequence<Throwable> = generateSequence(error) { it.cause }.take(8)
    }
}
