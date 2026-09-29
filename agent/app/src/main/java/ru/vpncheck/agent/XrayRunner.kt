package ru.vpncheck.agent

import android.content.Context
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.Authenticator
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

class XrayRunner(private val context: Context) {

    data class Outcome(val ok: Boolean, val latencyMs: Long?, val exitIp: String, val coreExit: Int? = null, val logTail: String = "")

    data class Via(val ip: String, val device: String?)

    data class Speed(val ok: Boolean, val bytes: Long, val ms: Long, val mbps: Double, val error: String)

    class CoreStartError(cause: Throwable) : Exception("core start failed: ${cause.message ?: cause.javaClass.simpleName}", cause)

    fun coreVersion(): String = BuildConfig.CORE_VERSION

    private fun corePath(): File = File(context.applicationInfo.nativeLibraryDir, "libxray.so")

    fun check(node: JSONObject?, testUrl: String, latencyUrl: String, waitMs: Long, via: Via?,
              timeoutSec: Long = 12, hosts: Map<String, List<String>> = emptyMap()): Outcome {
        if (node != null && refusal(node) != null) return Outcome(false, null, "")
        val log = File(coreDir(), "log_${UUID.randomUUID()}.txt")
        try {
            val outcome = withCore(node, via, if (node == null) "info" else "warning", log, hosts) { port, process ->
                if (!waitPort(port, waitMs + 6000, process)) {
                    check(node != null || process.isAlive) { "xray exited with code ${process.exitValue()}" }
                    return@withCore if (process.isAlive) Outcome(false, null, "") else crashed(node, process, log)
                }
                val client = socksClient(port, timeoutSec)
                val ip = try {
                    client.newCall(Request.Builder().url(testUrl).build()).execute().use {
                        if (it.isSuccessful) it.peekBody(64).string().trim() else ""
                    }
                } catch (_: Exception) { "" }
                if (ip.isEmpty()) {
                    return@withCore if (node == null || process.isAlive) Outcome(false, null, "") else crashed(node, process, log)
                }
                val started = System.nanoTime()
                val latency = try {
                    client.newCall(Request.Builder().url(latencyUrl).build()).execute().use {
                        if (it.code in 200..399) (System.nanoTime() - started) / 1_000_000 else null
                    }
                } catch (_: Exception) { null }
                Outcome(true, latency, ip)
            }
            return if (node == null && !outcome.ok) outcome.copy(logTail = tail(log, DIRECT_LOG_LINES)) else outcome
        } finally {
            log.delete()
        }
    }

    private fun tail(log: File?, lines: Int): String {
        val text = try { log?.readText().orEmpty() } catch (_: IOException) { "" }
        return text.lines().filter { it.isNotBlank() }.takeLast(lines).joinToString("\n")
    }

    private fun crashed(node: JSONObject?, process: Process, log: File?): Outcome {
        val code = try { process.exitValue() } catch (_: IllegalThreadStateException) { -1 }
        val tail = tail(log, 15)
        val key = node?.optString("key").orEmpty().take(64)
        ErrorLog.recordLimited(
            context, "core-exit", null, text = "node $key: xray exited with code $code\n$tail", dueKey = "core-exit:$key"
        )
        return Outcome(false, null, "", coreExit = code)
    }

    fun captureLog(node: JSONObject, testUrl: String): String {
        val prepared = prepare(node)
        prepared.error?.let { return it }
        val log = File(coreDir(), "log_${UUID.randomUUID()}.txt")
        try {
            return withCore(node, null, "debug", log, prepared.hosts) { port, process ->
                val portUp = waitPort(port, 10000, process)
                var attempt = ""
                if (portUp) {
                    attempt = try {
                        socksClient(port).newCall(Request.Builder().url(testUrl).build()).execute().use {
                            "request via node: HTTP ${it.code}, exit ${it.peekBody(64).string().trim()}"
                        }
                    } catch (e: Exception) { "request via node failed: ${(e.message ?: e.javaClass.simpleName).take(120)}" }
                }
                Thread.sleep(1500)
                val text = try { log.readText() } catch (_: Exception) { "" }
                val tail = text.lines().filter { it.isNotBlank() }.takeLast(60).joinToString("\n")
                (if (portUp) "" else "xray socks port did not come up\n") + attempt + "\n--- core log ---\n" + tail
            }
        } finally {
            log.delete()
        }
    }

    fun speed(node: JSONObject, url: String): Speed {
        val prepared = prepare(node)
        prepared.error?.let { return Speed(false, 0, 0, 0.0, it) }
        return withCore(node, null, "warning", null, prepared.hosts) { port, process ->
            if (!waitPort(port, 10000, process)) return@withCore Speed(false, 0, 0, 0.0, "socks port did not come up")
            val started = System.nanoTime()
            var total = 0L
            try {
                socksClient(port, 25).newCall(Request.Builder().url(url).build()).execute().use { r ->
                    if (!r.isSuccessful) return@withCore Speed(false, 0, 0, 0.0, "HTTP ${r.code}")
                    val buf = ByteArray(64 * 1024)
                    val body = r.body ?: return@withCore Speed(false, 0, 0, 0.0, "empty body")
                    body.byteStream().use { s ->
                        while (total < SPEED_MAX_BYTES) {
                            val n = s.read(buf)
                            if (n < 0) break
                            total += n
                            if ((System.nanoTime() - started) / 1_000_000 > SPEED_MAX_MS) break
                        }
                    }
                }
            } catch (e: Exception) {
                if (total == 0L) return@withCore Speed(false, 0, 0, 0.0, (e.message ?: e.javaClass.simpleName).take(80))
            }
            val ms = (System.nanoTime() - started) / 1_000_000
            val mbps = if (ms > 0) total * 8.0 / ms / 1000.0 else 0.0
            Speed(total > 0, total, ms, mbps, "")
        }
    }

    fun refusal(node: JSONObject): NodeRules.Refusal? = NodeRules.refusal(node)

    fun resolve(node: JSONObject, lookup: (String) -> List<InetAddress>): NodeRules.Resolved =
        NodeRules.resolve(node, RESOLVE_MS, lookup)

    private class Prepared(val error: String?, val hosts: Map<String, List<String>>)

    private fun prepare(node: JSONObject): Prepared {
        refusal(node)?.let { return Prepared(it.reason, emptyMap()) }
        val resolved = resolve(node) { host -> InetAddress.getAllByName(host).toList() }
        resolved.refusal?.let { return Prepared(it.reason, emptyMap()) }
        resolved.dead?.let { return Prepared(it, emptyMap()) }
        if (resolved.unanswered) return Prepared(NodeRules.DNS_TIMEOUT, emptyMap())
        return Prepared(null, resolved.hosts)
    }

    private fun coreDir() = File(context.cacheDir, "xray").apply { mkdirs() }

    private inline fun <T> withCore(node: JSONObject?, via: Via?, loglevel: String, log: File? = null,
                                    hosts: Map<String, List<String>> = emptyMap(),
                                    block: (port: Int, process: Process) -> T): T {
        val dir = coreDir()
        val port = Ports.take()
        val cfg = File(dir, "cfg_${port}_${UUID.randomUUID()}.json")
        val user = "a" + UUID.randomUUID().toString().take(8)
        val pass = UUID.randomUUID().toString().replace("-", "")
        var process: Process? = null
        try {
            SocksAuth.register(port, user, pass)
            val started = try {
                cfg.writeText(buildConfig(node, port, via, loglevel, Socks(user, pass), hosts).toString())
                ProcessBuilder(corePath().absolutePath, "run", "-c", cfg.absolutePath)
                    .directory(dir)
                    .redirectErrorStream(true)
                    .redirectOutput(log ?: File("/dev/null"))
                    .start()
            } catch (e: IOException) {
                throw CoreStartError(e)
            }
            process = started
            return block(port, started)
        } finally {
            process?.let(::stop)
            cfg.delete()
            SocksAuth.unregister(port)
            Ports.release(port)
        }
    }

    private class Socks(val user: String, val pass: String)

    private fun buildConfig(node: JSONObject?, port: Int, via: Via?, loglevel: String, socks: Socks,
                            hosts: Map<String, List<String>>): JSONObject = JSONObject().apply {
        put("log", JSONObject().put("loglevel", loglevel))
        put("inbounds", JSONArray().put(JSONObject().apply {
            put("port", port); put("listen", "127.0.0.1"); put("protocol", "socks")
            put("settings", JSONObject().put("udp", false).put("auth", "password")
                .put("accounts", JSONArray().put(JSONObject().put("user", socks.user).put("pass", socks.pass))))
        }))
        if (hosts.isNotEmpty()) {
            val pinned = JSONObject()
            for ((host, ips) in hosts) pinned.put("full:$host", JSONArray(ips))
            put("dns", JSONObject().put("hosts", pinned))
        }
        val outs = JSONArray()
        val main = node?.optJSONObject("outbound")
        if (node != null && main != null) {
            for (ob in listOf(main) + NodeRules.extrasOf(node).orEmpty()) {
                val copy = JSONObject(ob.toString())
                if (via != null) copy.put("sendThrough", via.ip)
                if (hosts.isNotEmpty()) NodeRules.pinDialing(copy)
                via?.device?.let { NodeRules.bindDevice(copy, it) }
                outs.put(copy)
            }
        }
        val freedom = JSONObject().put("protocol", "freedom").put("tag", DIRECT_TAG)
            .put("settings", JSONObject().put("domainStrategy", "UseIP"))
        if (via != null) freedom.put("sendThrough", via.ip)
        via?.device?.let { NodeRules.bindDevice(freedom, it) }
        outs.put(freedom)
        outs.put(JSONObject().put("protocol", "blackhole").put("tag", BLOCK_TAG))
        put("outbounds", outs)
        put("routing", JSONObject().apply {
            put("domainStrategy", if (main == null) "IPOnDemand" else "AsIs")
            put("rules", JSONArray().put(JSONObject().put("type", "field")
                .put("ip", JSONArray(PRIVATE_CIDRS)).put("outboundTag", BLOCK_TAG)))
        })
    }

    private fun socksClient(port: Int, timeoutSec: Long = 12): OkHttpClient =
        OkHttpClient.Builder().proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
            .connectTimeout(timeoutSec, TimeUnit.SECONDS).readTimeout(timeoutSec, TimeUnit.SECONDS).build()

    private fun stop(process: Process) {
        process.destroy()
        try { process.waitFor(2, TimeUnit.SECONDS) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        if (process.isAlive) process.destroyForcibly()
    }

    private fun waitPort(port: Int, timeoutMs: Long, process: Process): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive) return false
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300); return true }
            } catch (_: Exception) {
                Thread.sleep(250)
            }
        }
        return false
    }

    private object Ports {
        private val used = HashSet<Int>()

        @Synchronized
        fun take(): Int {
            repeat(20) {
                val port = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { socket -> socket.localPort }
                if (used.add(port)) return port
            }
            error("no free local port")
        }

        @Synchronized
        fun release(port: Int) {
            used.remove(port)
        }
    }

    private object SocksAuth : Authenticator() {
        private val accounts = ConcurrentHashMap<Int, PasswordAuthentication>()

        init {
            Authenticator.setDefault(this)
        }

        fun register(port: Int, user: String, pass: String) {
            accounts[port] = PasswordAuthentication(user, pass.toCharArray())
        }

        fun unregister(port: Int) {
            accounts.remove(port)
        }

        override fun getPasswordAuthentication(): PasswordAuthentication? = accounts[requestingPort]
    }

    companion object {
        private const val SPEED_MAX_BYTES = 8_000_000L
        private const val SPEED_MAX_MS = 20_000L
        private const val DIRECT_LOG_LINES = 20
        private const val BLOCK_TAG = NodeRules.BLOCK_TAG
        private const val DIRECT_TAG = NodeRules.DIRECT_TAG
        const val RESOLVE_MS = 5000L
        private val PRIVATE_CIDRS: List<String> = SiteCheck.PRIVATE_V4_CIDRS.flatMap { cidr ->
            val (ip, bits) = cidr.split('/')
            val o = ip.split('.').map { it.toInt() }
            val hex = Integer.toHexString(o[0] * 256 + o[1]) + ":" + Integer.toHexString(o[2] * 256 + o[3])
            listOf(cidr, "64:ff9b::$hex/${96 + bits.toInt()}", "2002:$hex::/${16 + bits.toInt()}")
        } + listOf("::/128", "::1/128", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8")
    }
}
