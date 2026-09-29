package ru.vpncheck.agent

import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

object NodeRules {
    const val REJECTED = "rejected"
    const val UNSUPPORTED = "unsupported"
    const val DNS_SINKHOLE = "dns-sinkhole"
    const val DNS_FAIL = "dns-fail"
    const val DNS_TIMEOUT = "dns-timeout"
    const val CORE_DIRECT = "core-direct"
    const val VPN = "vpn"
    const val BLOCK_TAG = "vc-block"
    const val DIRECT_TAG = "vc-direct"
    private const val MAX_EXTRAS = 8
    private const val MAX_DOWNLOAD_DEPTH = 4
    private const val MAX_KEY_DEPTH = 64
    private val RESERVED_TAGS = setOf(BLOCK_TAG, DIRECT_TAG)
    private val ALLOWED_PROTOCOLS = setOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria")
    private val EXTRA_PROTOCOLS = ALLOWED_PROTOCOLS + "freedom"
    private val UNKNOWN_TO_CORE = setOf("hysteria2")
    private const val HAPPY_EYEBALLS_MS = 250
    private val XHTTP_KEYS = listOf("xhttpSettings", "splithttpSettings")
    private const val FORCE_IP = "ForceIP"
    private val BASE64 = Regex("^[A-Za-z0-9+/]*={0,2}$")
    private val GUARDED_KEYS = setOf(
        "address", "server", "port", "vnext", "servers", "settings", "streamSettings", "sockopt", "dialerProxy",
        "proxySettings", "tag", "xhttpSettings", "splithttpSettings", "extra", "downloadSettings", "redirect",
        "domainStrategy", "tlsSettings", "echConfigList", "protocol", "allowInsecure",
    ).associateBy(::fold)
    private const val MUX = "mux"
    private const val MUX_ENABLED = "enabled"
    private val FREEDOM_SETTINGS = setOf("domainstrategy", "fragment", "noises", "userlevel", "redirect")
    private const val PORT_STRATEGY = "addressportstrategy"
    private const val HEADERS = "headers"
    private const val INTERFACE = "interface"
    private val AGENT_SOCKOPT = setOf(INTERFACE, "mark", "customsockopt")
    private val NAT64_PREFIX = byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte(), 0, 0, 0, 0, 0, 0, 0, 0)
    private const val SETTINGS = "settings"
    private const val ENV_PREFIX = "env:"
    private const val EXTRA_SPACES = "\u1680\u2028\u2029\u202F\u205F\u3000\uFEFF"
    private val FIELDS = NodeFields.FIELDS.mapValues { (_, fields) -> fields.mapKeys { fold(it.key) } }

    class Refusal(val code: String, val reason: String)

    class Resolved(
        val refusal: Refusal?,
        val dead: String?,
        val hosts: Map<String, List<String>>,
        val unanswered: Boolean = false,
    )

    fun refusal(node: JSONObject): Refusal? {
        if (ambiguousKeys(node.opt("outbound"), 1) || ambiguousKeys(node.opt("extra_outbounds"), 1)) {
            return Refusal(UNSUPPORTED, "keys differ from core names only in case")
        }
        val outbound = node.optJSONObject("outbound") ?: return Refusal(REJECTED, "node has no outbound")
        addressRefusal(outbound, ALLOWED_PROTOCOLS)?.let { return Refusal(REJECTED, it) }
        val extras = extrasOf(node) ?: return Refusal(UNSUPPORTED, "extra_outbounds is not a list of outbounds")
        if (extras.size > MAX_EXTRAS) return Refusal(UNSUPPORTED, "too many extra outbounds")
        val tags = HashSet<String>()
        for (extra in extras) {
            val tag = str(extra, "tag")
            if (tag.isEmpty() || tag in RESERVED_TAGS || !tags.add(tag)) {
                return Refusal(UNSUPPORTED, "extra outbound tag missing or repeated")
            }
            addressRefusal(extra, EXTRA_PROTOCOLS)?.let { return Refusal(REJECTED, it) }
            if (redirects(extra)) return Refusal(REJECTED, "freedom redirect not allowed")
            if (freedomExtras(extra)) return Refusal(UNSUPPORTED, "freedom settings outside the allowed list")
            if (muxed(extra)) return Refusal(UNSUPPORTED, "mux on a chained outbound")
        }
        if (!outbound.isNull("tag") && outbound.opt("tag") !is String) return Refusal(UNSUPPORTED, "outbound tag is not a string")
        val mainTag = str(outbound, "tag")
        if (mainTag in RESERVED_TAGS || mainTag in tags) return Refusal(UNSUPPORTED, "outbound tag repeated")
        val all = listOf(outbound) + extras
        if (all.any { echServer(it) }) return Refusal(REJECTED, "echConfigList must be an inline config")
        val unsupported = featureRefusal(all) ?: chainRefusal(outbound, extras.associateBy { str(it, "tag") })
        return unsupported?.let { Refusal(UNSUPPORTED, it) }
    }

    private fun featureRefusal(all: List<JSONObject>): String? = when {
        all.any(::fieldsRefused) -> "field outside the allowed list"
        all.any { downloadsOf(it, MAX_DOWNLOAD_DEPTH + 1).size > downloadsOf(it).size } -> "download settings nested too deep"
        all.any { str(it, "protocol").lowercase() in UNKNOWN_TO_CORE } -> "outbound protocol not supported by the core"
        all.any { insecure(it) } -> "allowInsecure was removed from the core"
        all.any(::portStrategy) -> "addressPortStrategy looks up the address outside the pin"
        all.any(::agentSockopt) -> "sockopt interface, mark and customSockopt are set by the agent"
        all.flatMap(::downloadsOf).any(::chained) -> "download settings go through another outbound"
        else -> null
    }

    fun chainRefusal(main: JSONObject, byTag: Map<String, JSONObject>): String? {
        val seen = HashSet<String>()
        val queue = ArrayDeque(linkedTags(main))
        while (queue.isNotEmpty()) {
            val tag = queue.removeFirst()
            val next = byTag[tag] ?: return "linked outbound missing: ${tag.take(20)}"
            if (!seen.add(tag)) return "outbound chain loops"
            queue.addAll(linkedTags(next))
        }
        return if (seen.size < byTag.size) "extra outbound not linked" else null
    }

    fun resolve(node: JSONObject, timeoutMs: Long, lookup: (String) -> List<InetAddress>): Resolved {
        val raw = dialedHere(node).map { it.trim() }
            .filter { bareHost(it).isNotEmpty() && SiteCheck.literalAddress(bareHost(it)) == null }.distinct()
        if (raw.isEmpty()) return Resolved(null, null, emptyMap())
        val tasks = raw.map(::bareHost).distinct().associateWith { name ->
            FutureTask { answer(name, lookup) }.also { Thread(it).apply { isDaemon = true }.start() }
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        return classify(raw, tasks.mapValues { (_, task) -> await(task, deadline) })
    }

    private fun answer(name: String, lookup: (String) -> List<InetAddress>): List<InetAddress>? = try {
        lookup(name)
    } catch (e: UnknownHostException) {
        if (retryable(e)) null else emptyList()
    } catch (_: Exception) {
        null
    }

    private fun retryable(error: Throwable): Boolean =
        generateSequence(error) { it.cause }.take(4).any { it.message.orEmpty().contains("EAI_AGAIN") }

    private fun await(task: FutureTask<List<InetAddress>?>, deadline: Long): List<InetAddress>? = try {
        task.get((deadline - System.currentTimeMillis()).coerceAtLeast(0), TimeUnit.MILLISECONDS)
    } catch (_: TimeoutException) {
        null
    } catch (_: ExecutionException) {
        null
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        null
    }

    private fun classify(raw: List<String>, found: Map<String, List<InetAddress>?>): Resolved {
        val pinned = LinkedHashMap<String, List<String>>()
        var sinkhole = false
        var unresolved = false
        var unanswered = false
        for (name in raw.map(::bareHost).distinct()) {
            val ips = found[name]
            if (ips == null) {
                unanswered = true
                continue
            }
            val real = ips.filterNot(::isSinkhole)
            if (real.any(SiteCheck::isPrivate)) {
                return Resolved(Refusal(REJECTED, "node address resolves to a private network"), null, emptyMap())
            }
            when {
                ips.isEmpty() -> unresolved = true
                real.isEmpty() -> sinkhole = true
                else -> pinned[name] = real.mapNotNull { it.hostAddress?.substringBefore('%') }
            }
        }
        if (sinkhole) return Resolved(null, DNS_SINKHOLE, emptyMap())
        if (unresolved) return Resolved(null, DNS_FAIL, emptyMap())
        if (unanswered) return Resolved(null, null, emptyMap(), unanswered = true)
        for (host in raw) pinned[bareHost(host)]?.let { pinned.putIfAbsent(host.trim('[', ']'), it) }
        return Resolved(null, null, pinned)
    }

    fun isSinkhole(address: InetAddress): Boolean {
        val b = address.address
        if (address is Inet4Address) return (b[0].toInt() and 0xff) in setOf(0, 127)
        if (address.isAnyLocalAddress || address.isLoopbackAddress) return true
        return NAT64_PREFIX.indices.all { b[it] == NAT64_PREFIX[it] } && (b[12].toInt() and 0xff) in setOf(0, 127)
    }

    fun preferV4(hosts: Map<String, List<String>>, v4Only: Boolean): Map<String, List<String>> =
        if (!v4Only) hosts else hosts.mapValues { (_, ips) -> ips.filter { !it.contains(':') }.ifEmpty { ips } }

    fun pinDialing(outbound: JSONObject) {
        val freedom = str(outbound, "protocol").lowercase() == "freedom"
        if (freedom) outbound.optJSONObject("settings")?.put("domainStrategy", "AsIs")
        for (sockopt in dialSockopts(outbound)) {
            sockopt.put("domainStrategy", FORCE_IP)
            if (sockopt.opt("happyEyeballs") !is JSONObject) {
                sockopt.put("happyEyeballs", JSONObject().put("tryDelayMs", HAPPY_EYEBALLS_MS))
            }
        }
    }

    fun bindDevice(outbound: JSONObject, device: String) {
        for (sockopt in dialSockopts(outbound)) {
            sockopt.keys().asSequence().filter { fold(it) in AGENT_SOCKOPT }.toList().forEach(sockopt::remove)
            sockopt.put(INTERFACE, device)
        }
    }

    private fun dialSockopts(outbound: JSONObject): List<JSONObject> {
        val targets = mutableListOf<JSONObject>()
        if (linkedTags(outbound).isEmpty()) {
            targets.add(outbound.optJSONObject("streamSettings") ?: JSONObject().also { outbound.put("streamSettings", it) })
        }
        targets.addAll(downloadsOf(outbound))
        return targets.map { target -> target.optJSONObject("sockopt") ?: JSONObject().also { target.put("sockopt", it) } }
    }

    fun uncheckedReasons(results: JSONObject, limit: Int): JSONObject? {
        val reasons = JSONObject()
        for (key in results.keys()) {
            if (reasons.length() >= limit) break
            val result = results.optJSONObject(key) ?: continue
            if (key.isNotEmpty() && result.optBoolean("unchecked")) reasons.put(key, result.text("error", REJECTED))
        }
        return reasons.takeIf { it.length() > 0 }
    }

    fun extrasOf(node: JSONObject): List<JSONObject>? {
        if (node.isNull("extra_outbounds")) return emptyList()
        val list = node.optJSONArray("extra_outbounds") ?: return null
        return (0 until list.length()).map { list.optJSONObject(it) ?: return null }
    }

    private fun str(obj: JSONObject?, key: String): String = (obj?.opt(key) as? String).orEmpty()

    private fun truthy(value: Any?): Boolean = when (value) {
        null, JSONObject.NULL, false -> false
        is String -> value.isNotEmpty()
        is Number -> value.toDouble() != 0.0
        is JSONObject -> value.length() > 0
        is JSONArray -> value.length() > 0
        else -> true
    }

    private fun redirects(outbound: JSONObject): Boolean =
        str(outbound, "protocol").lowercase() == "freedom" && truthy(outbound.optJSONObject("settings")?.opt("redirect"))

    private fun linkedTags(outbound: JSONObject): List<String> = listOf(
        str(outbound.optJSONObject("streamSettings")?.optJSONObject("sockopt"), "dialerProxy"),
        str(outbound.optJSONObject("proxySettings"), "tag"),
    ).filter { it.isNotEmpty() }

    private fun dialedHere(node: JSONObject): List<String> {
        val outbound = node.optJSONObject("outbound") ?: return emptyList()
        val extras = extrasOf(node).orEmpty()
        val byTag = extras.associateBy { str(it, "tag") }
        return (listOf(outbound) + extras).flatMap { item ->
            val own = if (throughProxy(item, byTag, 0)) emptyList() else serverAddresses(item)
            own + downloadsOf(item).map { str(it, "address") }.filter { it.isNotEmpty() }
        }
    }

    private fun throughProxy(outbound: JSONObject, byTag: Map<String, JSONObject>, depth: Int): Boolean =
        linkedTags(outbound).any { tag ->
            val next = byTag[tag]
            next == null || depth >= MAX_EXTRAS || str(next, "protocol").lowercase() != "freedom" ||
                throughProxy(next, byTag, depth + 1)
        }

    private fun chained(download: JSONObject): Boolean =
        truthy(download.optJSONObject("sockopt")?.opt("dialerProxy")) || truthy(download.opt("proxySettings"))

    private fun downloadsOf(outbound: JSONObject, limit: Int = MAX_DOWNLOAD_DEPTH): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        collectDownloads(outbound.optJSONObject("streamSettings"), out, limit)
        return out
    }

    private fun collectDownloads(stream: JSONObject?, out: MutableList<JSONObject>, left: Int) {
        if (stream == null || left <= 0) return
        for (key in XHTTP_KEYS) {
            val xhttp = stream.optJSONObject(key) ?: continue
            for (holder in listOfNotNull(xhttp, xhttp.optJSONObject("extra"))) {
                val download = holder.optJSONObject("downloadSettings") ?: continue
                out.add(download)
                collectDownloads(download, out, left - 1)
            }
        }
    }

    private fun fold(key: String): String = key.replace('\u017f', 's').replace('\u212a', 'k').lowercase(Locale.ROOT)

    private fun ambiguousKeys(value: Any?, depth: Int): Boolean = when {
        depth > MAX_KEY_DEPTH -> true
        value is JSONObject -> {
            val seen = HashSet<String>()
            value.keys().asSequence().any { key ->
                val folded = fold(key)
                !seen.add(folded) || GUARDED_KEYS[folded].let { it != null && it != key } ||
                    (folded != HEADERS && ambiguousKeys(value.opt(key), depth + 1))
            }
        }
        value is JSONArray -> (0 until value.length()).any { ambiguousKeys(value.opt(it), depth + 1) }
        else -> false
    }

    private fun muxed(outbound: JSONObject): Boolean = outbound.keys().asSequence().any { key ->
        val mux = outbound.opt(key)
        fold(key) == MUX && mux is JSONObject && mux.keys().asSequence().any { fold(it) == MUX_ENABLED && truthy(mux.opt(it)) }
    }

    private fun freedomExtras(outbound: JSONObject): Boolean {
        if (str(outbound, "protocol").lowercase() != "freedom") return false
        val settings = outbound.optJSONObject("settings") ?: return false
        return settings.keys().asSequence().any { fold(it) !in FREEDOM_SETTINGS }
    }

    private fun ownSockopts(outbound: JSONObject): List<JSONObject> =
        (listOfNotNull(outbound.optJSONObject("streamSettings")) + downloadsOf(outbound)).mapNotNull { it.optJSONObject("sockopt") }

    private fun portStrategy(outbound: JSONObject): Boolean = ownSockopts(outbound).any { sockopt ->
        sockopt.keys().asSequence().any { key ->
            val value = sockopt.opt(key)
            fold(key) == PORT_STRATEGY && value != JSONObject.NULL && (value as? String)?.lowercase(Locale.ROOT) != "none"
        }
    }

    private fun agentSockopt(outbound: JSONObject): Boolean = ownSockopts(outbound).any { sockopt ->
        sockopt.keys().asSequence().any { fold(it) in AGENT_SOCKOPT && truthy(sockopt.opt(it)) }
    }

    private fun echServer(value: Any?, depth: Int = 0): Boolean = when {
        depth > MAX_KEY_DEPTH -> true
        value is JSONObject -> value.keys().asSequence().any { key ->
            val item = value.opt(key)
            if (key == "echConfigList") !inlineEch(item) else echServer(item, depth + 1)
        }
        value is JSONArray -> (0 until value.length()).any { echServer(value.opt(it), depth + 1) }
        else -> false
    }

    private fun inlineEch(value: Any?): Boolean =
        value == null || value == JSONObject.NULL || (value is String && value.length % 4 == 0 && BASE64.matches(value))

    private fun insecure(value: Any?, depth: Int = 0): Boolean = when {
        depth > MAX_KEY_DEPTH -> true
        value is JSONObject -> value.keys().asSequence().any { key ->
            (key == "allowInsecure" && value.opt(key) != false) || insecure(value.opt(key), depth + 1)
        }
        value is JSONArray -> (0 until value.length()).any { insecure(value.opt(it), depth + 1) }
        else -> false
    }

    private fun fieldsRefused(outbound: JSONObject): Boolean =
        fieldsRefused(outbound, "outbound", str(outbound, "protocol").lowercase())

    private fun fieldsRefused(value: Any?, context: String, protocol: String): Boolean = when (value) {
        is JSONArray -> (0 until value.length()).any { fieldsRefused(value.opt(it), context, protocol) }
        is JSONObject -> {
            val fields = FIELDS[if (context == SETTINGS) "$SETTINGS.$protocol" else context]
            fields == null || value.keys().asSequence().any { fieldRefused(fields[fold(it)], value.opt(it), protocol) }
        }
        else -> false
    }

    private fun fieldRefused(spec: String?, item: Any?, protocol: String): Boolean = when {
        spec == null -> true
        spec.startsWith("!") -> truthy(item) && (item as? String)?.lowercase() !in spec.drop(1).split(",")
        spec.startsWith("@") -> fieldsRefused(item, spec.drop(1), protocol)
        else -> false
    }

    fun oddAddress(address: String): Boolean = address.startsWith(ENV_PREFIX, ignoreCase = true) ||
        address.any { it == '%' || it.code <= 0x20 || it.code in 0x7F..0xA0 || it.code in 0x2000..0x200A || it in EXTRA_SPACES }

    private fun addressRefusal(outbound: JSONObject, allowed: Set<String>): String? {
        val protocol = str(outbound, "protocol").lowercase()
        if (protocol !in allowed) return "outbound protocol not allowed: ${protocol.take(20)}"
        if (addressesOf(outbound).any(::oddAddress)) return "node address has spaces, control characters, a zone or env:"
        for (host in addressesOf(outbound).map(::bareHost)) {
            if (host == "localhost" || host.endsWith(".localhost")) return "node address is local"
            val literal = SiteCheck.literalAddress(host) ?: continue
            if (SiteCheck.isPrivate(literal)) return "node address is private"
        }
        return null
    }

    private fun bareHost(address: String): String = address.trim().trim('[', ']').lowercase().trimEnd('.')

    private fun addressesOf(outbound: JSONObject): List<String> =
        serverAddresses(outbound) + downloadsOf(outbound).map { str(it, "address") }.filter { it.isNotEmpty() }

    private fun serverAddresses(outbound: JSONObject): List<String> {
        val addresses = mutableListOf<String>()
        val settings = outbound.optJSONObject("settings")
        if (settings != null) {
            for (field in listOf("address", "server")) str(settings, field).takeIf { it.isNotEmpty() }?.let(addresses::add)
            for (listName in listOf("vnext", "servers")) {
                val list = settings.optJSONArray(listName) ?: continue
                for (i in 0 until list.length()) str(list.optJSONObject(i), "address").takeIf { it.isNotEmpty() }?.let(addresses::add)
            }
        }
        return addresses
    }
}
