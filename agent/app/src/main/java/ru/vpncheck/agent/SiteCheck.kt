package ru.vpncheck.agent

import android.net.Network
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.InterruptedIOException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketAddress
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.SocketFactory
import javax.net.ssl.SSLException

object SiteCheck {
    data class Result(val ok: Boolean, val code: Int, val ms: Long?, val error: String, val errorRes: Int? = null)

    class PrivateAddress(host: String) : UnknownHostException("private address: $host")

    fun isPrivate(address: InetAddress): Boolean {
        if (address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress ||
            address.isAnyLocalAddress || address.isMulticastAddress) return true
        val b = address.address
        return if (address is Inet6Address) isPrivate6(b) else isPrivate4(b)
    }

    private fun isPrivate4(b: ByteArray): Boolean {
        val a0 = b[0].toInt() and 0xff
        val a1 = b[1].toInt() and 0xff
        val a2 = b[2].toInt() and 0xff
        return a0 == 0 || a0 == 10 || a0 == 127 || a0 >= 224 ||
            (a0 == 172 && a1 in 16..31) || (a0 == 192 && a1 == 168) || (a0 == 169 && a1 == 254) ||
            (a0 == 100 && a1 in 64..127) || (a0 == 198 && a1 in 18..19) || (a0 == 192 && a1 == 0 && a2 == 0)
    }

    private fun isPrivate6(b: ByteArray): Boolean {
        val first = b[0].toInt() and 0xff
        val second = b[1].toInt() and 0xff
        if (first and 0xfe == 0xfc) return true
        if (first == 0xfe && (second and 0xc0) == 0x80) return true
        val embedded = when {
            (0 until 10).all { b[it].toInt() == 0 } && (b[10].toInt() and 0xff) == 0xff && (b[11].toInt() and 0xff) == 0xff ->
                b.copyOfRange(12, 16)
            startsWith(b, NAT64_LOCAL) -> return true
            startsWith(b, NAT64_WELL_KNOWN) -> b.copyOfRange(12, 16)
            first == 0x20 && second == 0x02 -> b.copyOfRange(2, 6)
            else -> return false
        }
        return isPrivate4(embedded)
    }

    private fun startsWith(b: ByteArray, prefix: ByteArray): Boolean = prefix.indices.all { b[it] == prefix[it] }

    private val NAT64_WELL_KNOWN = byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte(), 0, 0, 0, 0, 0, 0, 0, 0)
    private val NAT64_LOCAL = byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte(), 0, 1)

    val PRIVATE_V4_CIDRS = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"
    )

    private val IPV4_LITERAL = Regex("^[0-9]{1,3}([.][0-9]{1,3}){3}$")

    fun literalAddress(host: String): InetAddress? {
        val h = host.trim().trim('[', ']')
        if (h.isEmpty()) return null
        val ipv6 = h.contains(':') && h.all { it.isLetterOrDigit() || it == ':' || it == '.' || it == '%' }
        if (!IPV4_LITERAL.matches(h) && !ipv6) return null
        return try { InetAddress.getByName(h) } catch (_: Exception) { null }
    }

    fun lookupWithin(timeoutMs: Long, resolve: () -> List<InetAddress>): List<InetAddress> =
        lookupWithin(timeoutMs, emptyList(), resolve)

    fun <T> lookupWithin(timeoutMs: Long, fallback: T, resolve: () -> T): T {
        val found = AtomicReference(fallback)
        val thread = Thread { found.set(try { resolve() } catch (_: Exception) { fallback }) }
        thread.isDaemon = true
        thread.start()
        try {
            thread.join(timeoutMs)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        return found.get()
    }

    fun isPublicUrl(url: String, httpsOnly: Boolean = false): Boolean {
        val parsed = url.toHttpUrlOrNull() ?: return false
        if (httpsOnly && !parsed.isHttps) return false
        val host = parsed.host.lowercase().trimEnd('.')
        if (host == "localhost" || host.endsWith(".localhost")) return false
        val literal = literalAddress(host) ?: return true
        return !isPrivate(literal)
    }

    private class GuardedSocketFactory(private val net: Network?) : SocketFactory() {
        override fun createSocket(): Socket = object : Socket() {
            override fun connect(endpoint: SocketAddress?, timeout: Int) {
                val target = endpoint as? InetSocketAddress ?: throw PrivateAddress(endpoint.toString())
                val address = target.address ?: throw PrivateAddress(target.hostString)
                if (isPrivate(address)) throw PrivateAddress(address.hostAddress ?: target.hostString)
                net?.bindSocket(this)
                super.connect(endpoint, timeout)
            }
        }

        override fun createSocket(host: String, port: Int): Socket =
            createSocket().apply { connect(InetSocketAddress(host, port)) }

        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
            createSocket().apply { bind(InetSocketAddress(localHost, localPort)); connect(InetSocketAddress(host, port)) }

        override fun createSocket(host: InetAddress, port: Int): Socket =
            createSocket().apply { connect(InetSocketAddress(host, port)) }

        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
            createSocket().apply { bind(InetSocketAddress(localAddress, localPort)); connect(InetSocketAddress(address, port)) }
    }

    private fun publicDns(resolve: (String) -> List<InetAddress>) = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val host = hostname.lowercase().trimEnd('.')
            if (host == "localhost" || host.endsWith(".localhost")) throw PrivateAddress(hostname)
            val found = resolve(hostname).filterNot(::isPrivate)
            if (found.isEmpty()) throw PrivateAddress(hostname)
            return found
        }
    }

    private val guard = Interceptor { chain ->
        val remote = chain.connection()?.route()?.socketAddress?.address
        if (remote != null && isPrivate(remote)) throw PrivateAddress(chain.request().url.host)
        chain.proceed(chain.request())
    }

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS).readTimeout(10, TimeUnit.SECONDS).callTimeout(12, TimeUnit.SECONDS)
        .proxy(Proxy.NO_PROXY).socketFactory(GuardedSocketFactory(null))
        .dns(publicDns(Dns.SYSTEM::lookup)).addNetworkInterceptor(guard)
        .followRedirects(true).followSslRedirects(true).build()

    fun clientFor(net: Network): OkHttpClient = client.newBuilder()
        .socketFactory(GuardedSocketFactory(net))
        .dns(publicDns { host -> net.getAllByName(host).toList() })
        .connectionPool(ConnectionPool())
        .build()

    fun direct(url: String, via: OkHttpClient = client): Result {
        if (url.toHttpUrlOrNull() != null && !isPublicUrl(url)) return Result(false, 0, null, "private address", R.string.site_err_private)
        val started = System.nanoTime()
        return try {
            val request = Request.Builder().url(url).header("User-Agent", "VPNCheckAgent/1")
                .header("Range", "bytes=0-1023").build()
            via.newCall(request).execute().use { r ->
                val ms = (System.nanoTime() - started) / 1_000_000
                r.body?.source()?.request(1024)
                val ok = r.code in 200..399 || r.code == 416
                Result(ok, r.code, ms, if (ok) "" else "HTTP ${r.code}")
            }
        } catch (_: PrivateAddress) {
            Result(false, 0, null, "private address", R.string.site_err_private)
        } catch (_: UnknownHostException) {
            Result(false, 0, null, "DNS not responding", R.string.site_err_dns)
        } catch (_: InterruptedIOException) {
            Result(false, 0, null, "timeout", R.string.site_err_timeout)
        } catch (_: SSLException) {
            Result(false, 0, null, "TLS dropped", R.string.site_err_tls)
        } catch (e: Exception) {
            Result(false, 0, null, (e.message ?: e.javaClass.simpleName).take(40))
        }
    }
}
