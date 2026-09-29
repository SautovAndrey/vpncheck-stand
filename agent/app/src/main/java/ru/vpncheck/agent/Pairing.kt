package ru.vpncheck.agent

import android.content.Context
import android.net.Uri
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject

object Pairing {
    data class Target(val server: String, val key: String, val tls: PinnedTls? = null, val issued: Long = 0)

    enum class TlsChange { NEW, KEPT, DROPPED, NONE }

    private val HEX_KEY = Regex("^[0-9a-f]{64}$")
    private val ISSUED = Regex("^[0-9]{1,15}$")

    fun load(context: Context) {
        val prefs = Prefs(context)
        Api.base = prefs.serverUrl
        Api.useTls(prefs.tls)
        Verify.manifestKey = prefs.manifestKey
    }

    fun parse(uri: Uri?): Target? {
        if (uri == null || uri.scheme != "vpncheck" || uri.host != "pair") return null
        return parse(uri::getQueryParameter)
    }

    fun parse(param: (String) -> String?): Target? {
        val server = cleanServer(param("server")) ?: return null
        val key = param("key")?.trim()?.lowercase().orEmpty()
        if (key.isNotEmpty() && !HEX_KEY.matches(key)) return null
        val rawIssued = param("ti")?.trim()
        if (rawIssued != null && !ISSUED.matches(rawIssued)) return null
        val issued = rawIssued?.toLong() ?: 0L
        val port = param("tp")?.trim()
        val pin = param("pin")?.replace(' ', '+')?.trim()
        if (port == null && pin == null) return Target(server, key, issued = issued)
        val tls = PinnedTls.parse(server, JSONObject().put("port", port?.toIntOrNull() ?: 0).put("pin", pin.orEmpty()))
            ?: return null
        return Target(server, key, tls, issued)
    }

    private fun cleanServer(raw: String?): String? {
        val text = raw?.trim() ?: return null
        if (text.any { it.isISOControl() || it.isWhitespace() }) return null
        if (!text.startsWith("http://", true) && !text.startsWith("https://", true)) return null
        val url = text.toHttpUrlOrNull() ?: return null
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) return null
        if (url.encodedPath != "/" || url.query != null || url.fragment != null) return null
        if (text.substringAfter("://").contains('@')) return null
        return HttpUrl.Builder().scheme(url.scheme).host(url.host).port(url.port).build().toString().trimEnd('/')
    }

    fun changesKey(context: Context, target: Target): Boolean {
        val current = Prefs(context).manifestKey.trim().lowercase()
        return current.isNotEmpty() && target.key.isNotEmpty() && current != target.key
    }

    private fun samePin(a: PinnedTls?, b: PinnedTls?): Boolean = a != null && b != null && a.port == b.port && a.pin == b.pin

    fun tlsChange(context: Context, target: Target): TlsChange {
        val prefs = Prefs(context)
        val current = prefs.tls.takeIf { prefs.serverUrl == target.server }
        return when {
            target.tls != null -> if (samePin(current, target.tls)) TlsChange.KEPT else TlsChange.NEW
            current != null -> TlsChange.KEPT
            prefs.tls != null -> TlsChange.DROPPED
            else -> TlsChange.NONE
        }
    }

    data class Stored(val tls: PinnedTls?, val tlsIssued: Long, val manifestIssued: Long)

    fun next(stored: Stored, target: Target, sameServer: Boolean, keyChanged: Boolean): Stored {
        var tls = stored.tls.takeIf { sameServer }
        var tlsIssued = if (sameServer) stored.tlsIssued else 0L
        if (target.tls != null) {
            tlsIssued = if (samePin(tls, target.tls)) maxOf(tlsIssued, target.issued) else target.issued
            tls = target.tls
        }
        var manifestIssued = if (!sameServer || keyChanged) 0L else stored.manifestIssued
        if (target.issued > 0) {
            if (target.tls == null) tlsIssued = maxOf(tlsIssued, target.issued - 1)
            manifestIssued = maxOf(manifestIssued, target.issued)
        }
        return Stored(tls, tlsIssued, manifestIssued)
    }

    fun apply(context: Context, target: Target) {
        val prefs = Prefs(context)
        val sameServer = prefs.serverUrl == target.server
        val current = Stored(prefs.tls, prefs.tlsIssued, prefs.lastManifestIssued)
        val stored = next(current, target, sameServer, changesKey(context, target))
        prefs.serverUrl = target.server
        prefs.tls = stored.tls
        prefs.tlsIssued = stored.tlsIssued
        prefs.lastManifestIssued = stored.manifestIssued
        if (target.key.isNotEmpty()) prefs.manifestKey = target.key
        if (!sameServer) {
            prefs.linkAfter = 0
            prefs.pushTokenSent = false
        }
        load(context)
    }
}
