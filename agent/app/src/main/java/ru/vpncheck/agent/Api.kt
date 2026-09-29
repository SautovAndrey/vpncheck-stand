package ru.vpncheck.agent

import android.content.Context
import android.net.Network
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSource
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

object Api {
    class HttpError(val code: Int, message: String) : IOException(message)

    class TooLarge(message: String) : IOException(message)

    private const val MAX_DOWNLOAD_BYTES = 150L * 1024 * 1024
    private const val MAX_ANSWER_BYTES = 2L * 1024 * 1024
    private const val POLL_READ_MARGIN_SEC = 60L
    private const val DOWNLOAD_CALL_MIN = 9L
    private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "0.0.0.0")

    @Volatile var base: String = BuildConfig.SERVER

    private class Secure(val tls: PinnedTls, val client: OkHttpClient)

    @Volatile private var secure: Secure? = null

    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val downloadHttp = http.newBuilder()
        .readTimeout(5, TimeUnit.MINUTES)
        .callTimeout(DOWNLOAD_CALL_MIN, TimeUnit.MINUTES)
        .build()

    fun useTls(tls: PinnedTls?) {
        secure = tls?.let { Secure(it, it.secure(http.newBuilder())) }
    }

    fun root(): String = secure?.tls?.base ?: base

    private fun route(client: OkHttpClient): Pair<String, OkHttpClient> {
        val current = secure ?: return base to client
        return current.tls.base to if (client === http) current.client else current.tls.secure(client.newBuilder())
    }

    private val JSON = "application/json".toMediaType()

    fun config(context: Context): JSONObject = get(
        "/v1/config",
        "agent_id" to Prefs(context).agentId,
        "app_version" to BuildConfig.VERSION_NAME,
        "core_version" to XrayRunner(context).coreVersion(),
    )

    fun manifestOverHttp(): JSONObject? {
        val client = http.newBuilder().followRedirects(false).followSslRedirects(false).build()
        val request = Request.Builder().url("$base/v1/manifest".toHttpUrl()).build()
        return execute(client.newCall(request), "/v1/manifest").optJSONObject("manifest")
    }

    fun ping(agentId: String): JSONObject = get("/v1/ping", "agent_id" to agentId)

    fun paired(): Boolean {
        val host = base.toHttpUrlOrNull()?.host?.trim('[', ']')?.lowercase() ?: return false
        return host !in LOOPBACK_HOSTS && !host.startsWith("127.")
    }

    fun poll(agentId: String, after: Long, waitSec: Int, current: AtomicReference<Call?>): JSONObject {
        val (root, server) = route(http)
        val url = "$root/v1/poll".toHttpUrl().newBuilder()
            .addQueryParameter("agent_id", agentId).addQueryParameter("after", after.toString())
            .addQueryParameter("wait", waitSec.toString()).build()
        val client = server.newBuilder().readTimeout(waitSec + POLL_READ_MARGIN_SEC, TimeUnit.SECONDS).build()
        val call = client.newCall(Request.Builder().url(url).build())
        current.set(call)
        try {
            return execute(call, "/v1/poll")
        } finally {
            current.compareAndSet(call, null)
        }
    }

    fun report(payload: JSONObject, client: OkHttpClient = http): JSONObject = post("/v1/report", payload, client)

    fun clientFor(net: Network): OkHttpClient = http.newBuilder()
        .proxy(Proxy.NO_PROXY)
        .socketFactory(net.socketFactory)
        .dns(object : Dns { override fun lookup(hostname: String) = net.getAllByName(hostname).toList() })
        .connectionPool(ConnectionPool())
        .build()

    fun fetchText(client: OkHttpClient, url: String): String = try {
        client.newCall(Request.Builder().url(url).build()).execute().use {
            if (it.isSuccessful) it.peekBody(64).string().trim() else ""
        }
    } catch (_: Exception) { "" }

    fun evict() {
        http.connectionPool.evictAll()
    }

    fun postToken(payload: JSONObject): JSONObject = post("/v1/token", payload)

    fun postLocation(payload: JSONObject): JSONObject = post("/v1/location", payload)

    fun postResult(agentId: String, action: String, seq: Long, result: JSONObject): JSONObject = post(
        "/v1/result",
        JSONObject().put("agent_id", agentId).put("action", action).put("seq", seq).put("result", result),
    )

    fun postErrors(payload: JSONObject): JSONObject = post("/v1/errors", payload)

    fun download(url: String, target: File) {
        val (root, client) = route(downloadHttp)
        val full = serverUrl(url, root) ?: url
        (if (full.startsWith("$root/")) client else downloadHttp).newCall(Request.Builder().url(full).build()).execute().use { response ->
            if (!response.isSuccessful) throw HttpError(response.code, "download: HTTP ${response.code}")
            val body = response.body ?: throw IOException("download: empty body")
            if (body.contentLength() > MAX_DOWNLOAD_BYTES) throw TooLarge("download: too large")
            target.parentFile?.mkdirs()
            body.byteStream().use { input -> target.outputStream().use { output -> copyLimited(input, output) } }
        }
    }

    private fun copyLimited(input: InputStream, output: OutputStream) {
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_DOWNLOAD_BYTES) throw TooLarge("download: too large")
            output.write(buf, 0, n)
        }
    }

    private fun serverUrl(url: String, root: String): String? {
        if (url.startsWith("/")) return root + url
        val parsed = url.toHttpUrlOrNull() ?: return null
        val rootUrl = root.toHttpUrlOrNull() ?: return null
        val sameHost = parsed.host.equals(rootUrl.host, ignoreCase = true)
        if (!sameHost || secure == null) return parsed.toString()
        return parsed.newBuilder().scheme(rootUrl.scheme).port(rootUrl.port).build().toString()
    }

    private fun get(path: String, vararg query: Pair<String, String>): JSONObject {
        val (root, client) = route(http)
        val url = "$root$path".toHttpUrl().newBuilder()
        for ((name, value) in query) url.addQueryParameter(name, value)
        return execute(client.newCall(Request.Builder().url(url.build()).build()), path)
    }

    private fun post(path: String, payload: JSONObject, client: OkHttpClient = http): JSONObject {
        val (root, server) = route(client)
        val request = Request.Builder().url("$root$path").post(payload.toString().toRequestBody(JSON)).build()
        return execute(server.newCall(request), path)
    }

    private fun readLimited(source: BufferedSource?, path: String): String {
        if (source == null) throw IOException("$path: empty body")
        if (source.request(MAX_ANSWER_BYTES + 1)) throw TooLarge("$path: answer too large")
        return source.readUtf8()
    }

    private fun execute(call: Call, path: String): JSONObject {
        call.execute().use { response ->
            if (!response.isSuccessful) throw HttpError(response.code, "$path: HTTP ${response.code}")
            val body = readLimited(response.body?.source(), path)
            return try {
                JSONObject(body)
            } catch (_: JSONException) {
                throw IOException("$path: not JSON")
            }
        }
    }
}

fun JSONObject.text(name: String, fallback: String = ""): String =
    optString(name, fallback).takeUnless { isNull(name) || it.isEmpty() } ?: fallback
