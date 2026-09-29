package ru.vpncheck.agent

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetAddress
import java.net.UnknownHostException

class NodeRulesTest {
    private val cases: JSONObject by lazy {
        val path = System.getProperty("chainCases") ?: "../../tests/data/chain_cases.json"
        JSONObject(File(path).readText())
    }

    private fun each(section: String, block: (JSONObject) -> Unit) {
        val list = cases.getJSONArray(section)
        check(list.length() > 0) { "no cases in $section" }
        for (i in 0 until list.length()) block(list.getJSONObject(i))
    }

    private fun strings(array: JSONArray?): List<String> = (0 until (array?.length() ?: 0)).map { array!!.getString(it) }

    private fun hostsOf(obj: JSONObject?): Map<String, List<String>> =
        obj?.keys()?.asSequence()?.map { it as String }?.associateWith { strings(obj.getJSONArray(it)) }.orEmpty()

    @Test
    fun refusalMatchesSharedCases() {
        each("chain") { case ->
            val expected = if (case.isNull("refusal")) null else case.getString("refusal")
            val refusal = NodeRules.refusal(case.getJSONObject("node"))
            assertEquals(case.getString("name") + ": " + refusal?.reason, expected, refusal?.code)
        }
    }

    @Test
    fun fieldsMatchSharedList() {
        val path = System.getProperty("nodeFields") ?: "../../stand/node_fields.json"
        val shared = JSONObject(File(path).readText())
        val expected = shared.keys().asSequence().map { it as String }.associateWith { context ->
            val fields = shared.getJSONObject(context)
            fields.keys().asSequence().map { it as String }.associateWith { fields.getString(it) }
        }
        assertEquals(expected, NodeFields.FIELDS)
    }

    @Test
    fun oddAddressesAreRefused() {
        for (address in listOf("env:HOME", "ENV:x", "1.2.3.4\u0085", "a.com\u00A0", "\t1.2.3.4", "a\u2028b.com", "a.com\u3000")) {
            assertTrue(address, NodeRules.oddAddress(address))
        }
        for (address in listOf("1.2.3.4", "a.example.com", "[2001:db8::1]", "xn--e1afmkfd.xn--p1ai")) {
            assertFalse(address, NodeRules.oddAddress(address))
        }
    }

    @Test
    fun chainRefusalAgreesWithRefusal() {
        each("chain") { case ->
            val node = case.getJSONObject("node")
            val extras = NodeRules.extrasOf(node) ?: return@each
            val byTag = extras.associateBy { (it.opt("tag") as? String).orEmpty() }
            val chain = NodeRules.chainRefusal(node.getJSONObject("outbound"), byTag)
            if (case.isNull("refusal")) assertNull(case.getString("name"), chain)
        }
    }

    @Test
    fun privateAndSinkholeAddresses() {
        each("addresses") { case ->
            val address = InetAddress.getByName(case.getString("address"))
            val name = case.getString("address")
            assertEquals("$name private", case.getBoolean("private"), SiteCheck.isPrivate(address))
            assertEquals("$name sinkhole", case.getBoolean("sinkhole"), NodeRules.isSinkhole(address))
        }
    }

    @Test
    fun resolvedAddressesArePinnedOrRefused() {
        each("resolve") { case ->
            val name = case.getString("name")
            val lookup = hostsOf(case.getJSONObject("lookup"))
            val slow = strings(case.optJSONArray("slow")).toSet()
            val started = System.currentTimeMillis()
            val resolved = NodeRules.resolve(case.getJSONObject("node"), RESOLVE_MS) { host ->
                if (host in slow) Thread.sleep(RESOLVE_MS * 3)
                lookup[host]?.map { InetAddress.getByName(it) } ?: throw UnknownHostException(host)
            }
            assertTrue(name, System.currentTimeMillis() - started < RESOLVE_MS * 2)
            val got = when {
                resolved.refusal != null -> resolved.refusal.code
                resolved.dead == NodeRules.DNS_SINKHOLE -> "sinkhole"
                resolved.dead == NodeRules.DNS_FAIL -> "dead-dns"
                resolved.unanswered -> "unchecked"
                else -> "pinned"
            }
            assertEquals(name, case.getString("expect"), got)
            assertEquals(name, canonical(hostsOf(case.getJSONObject("hosts"))), canonical(resolved.hosts))
        }
    }

    @Test
    fun namesAreLookedUpInParallel() {
        val node = JSONObject().put("outbound", JSONObject().put("protocol", "vless").put("settings", JSONObject()
            .put("vnext", JSONArray().put(JSONObject().put("address", "a.example.com")).put(JSONObject().put("address", "b.example.com")))))
        val resolved = NodeRules.resolve(node, RESOLVE_MS) { host ->
            Thread.sleep(RESOLVE_MS * 2 / 3)
            listOf(InetAddress.getByName(if (host.startsWith("a")) "203.0.113.5" else "203.0.113.6"))
        }
        assertEquals(setOf("a.example.com", "b.example.com"), resolved.hosts.keys)
    }

    @Test
    fun retryableLookupErrorLeavesNodeUnchecked() {
        val node = JSONObject().put("outbound", JSONObject().put("protocol", "vless").put("settings", JSONObject()
            .put("vnext", JSONArray().put(JSONObject().put("address", "a.example.com")))))
        val again = NodeRules.resolve(node, RESOLVE_MS) {
            throw UnknownHostException("Unable to resolve host").apply { initCause(Exception("getaddrinfo failed: EAI_AGAIN")) }
        }
        assertNull(again.dead)
        assertTrue(again.unanswered)
        assertEquals(emptyMap<String, List<String>>(), again.hosts)
        val missing = NodeRules.resolve(node, RESOLVE_MS) { throw UnknownHostException("EAI_NODATA") }
        assertEquals(NodeRules.DNS_FAIL, missing.dead)
        assertFalse(missing.unanswered)
    }

    @Test
    fun uncheckedReasonsMatchSharedCases() {
        each("unchecked") { case ->
            val reasons = NodeRules.uncheckedReasons(case.getJSONObject("results"), 300)
            val expected = if (case.isNull("reasons")) null else hostsOfText(case.getJSONObject("reasons"))
            assertEquals(case.getString("name"), expected, reasons?.let(::hostsOfText))
        }
    }

    @Test
    fun uncheckedReasonsAreLimited() {
        val results = JSONObject()
        for (i in 0 until 10) results.put("k$i", JSONObject().put("ok", false).put("unchecked", true))
        assertEquals(3, NodeRules.uncheckedReasons(results, 3)?.length())
    }

    @Test
    fun pinDialingResolvesThroughPinnedHosts() {
        val vless = JSONObject().put("protocol", "vless").put("streamSettings", JSONObject()
            .put("sockopt", JSONObject().put("dialerProxy", JSONObject.NULL))
            .put("xhttpSettings", JSONObject().put("extra", JSONObject().put("downloadSettings", JSONObject()))))
        NodeRules.pinDialing(vless)
        val stream = vless.getJSONObject("streamSettings")
        assertPinned(stream)
        assertPinned(stream.getJSONObject("xhttpSettings").getJSONObject("extra").getJSONObject("downloadSettings"))
        val freedom = JSONObject().put("protocol", "freedom").put("settings", JSONObject().put("domainStrategy", "UseIPv4"))
        NodeRules.pinDialing(freedom)
        assertEquals("AsIs", freedom.getJSONObject("settings").getString("domainStrategy"))
        assertPinned(freedom.getJSONObject("streamSettings"))
        val plain = JSONObject().put("protocol", "freedom").put("settings", JSONObject().put("domainStrategy", JSONObject.NULL))
        NodeRules.pinDialing(plain)
        assertEquals("AsIs", plain.getJSONObject("settings").getString("domainStrategy"))
        assertPinned(plain.getJSONObject("streamSettings"))
    }

    @Test
    fun pinDialingLeavesLinkedDialingToTheLink() {
        val viaDialer = JSONObject().put("protocol", "vless").put("streamSettings", JSONObject()
            .put("sockopt", JSONObject().put("dialerProxy", "hop"))
            .put("xhttpSettings", JSONObject().put("downloadSettings", JSONObject())))
        NodeRules.pinDialing(viaDialer)
        val stream = viaDialer.getJSONObject("streamSettings")
        assertFalse(stream.getJSONObject("sockopt").has("domainStrategy"))
        assertPinned(stream.getJSONObject("xhttpSettings").getJSONObject("downloadSettings"))
        val viaProxy = JSONObject().put("protocol", "vless").put("proxySettings", JSONObject().put("tag", "hop"))
            .put("streamSettings", JSONObject().put("xhttpSettings", JSONObject().put("downloadSettings", JSONObject())))
        NodeRules.pinDialing(viaProxy)
        val proxied = viaProxy.getJSONObject("streamSettings")
        assertFalse(proxied.has("sockopt"))
        assertPinned(proxied.getJSONObject("xhttpSettings").getJSONObject("downloadSettings"))
        val kept = JSONObject().put("happyEyeballs", JSONObject().put("tryDelayMs", 100)).put("domainStrategy", "UseIPv4")
        val own = JSONObject().put("protocol", "vless").put("streamSettings", JSONObject().put("sockopt", kept))
        NodeRules.pinDialing(own)
        assertEquals("ForceIP", kept.getString("domainStrategy"))
        assertEquals(100, kept.getJSONObject("happyEyeballs").getInt("tryDelayMs"))
    }

    @Test
    fun pinDialingOverridesNodeFamily() {
        val download = JSONObject().put("sockopt", JSONObject().put("domainStrategy", "UseIPv4"))
        val node = JSONObject().put("protocol", "vless").put("streamSettings", JSONObject()
            .put("sockopt", JSONObject().put("domainStrategy", "UseIPv6"))
            .put("xhttpSettings", JSONObject().put("downloadSettings", download)))
        NodeRules.pinDialing(node)
        assertPinned(node.getJSONObject("streamSettings"))
        assertPinned(download)
    }

    @Test
    fun bindDeviceSendsEveryOwnDialThroughTheNetwork() {
        val download = JSONObject().put("sockopt", JSONObject().put("Interface", "wlan0").put("Mark", 7)
            .put("cuſtomSockopt", JSONArray().put(JSONObject().put("opt", "25"))))
        val node = JSONObject().put("protocol", "vless").put("streamSettings", JSONObject()
            .put("xhttpSettings", JSONObject().put("downloadSettings", download)))
        NodeRules.bindDevice(node, "rmnet0")
        assertEquals("rmnet0", node.getJSONObject("streamSettings").getJSONObject("sockopt").getString("interface"))
        val sockopt = download.getJSONObject("sockopt")
        assertEquals("rmnet0", sockopt.getString("interface"))
        assertFalse(sockopt.has("Interface"))
        assertEquals(setOf("interface"), sockopt.keys().asSequence().toSet())
        val linked = JSONObject().put("protocol", "vless").put("proxySettings", JSONObject().put("tag", "hop"))
        NodeRules.bindDevice(linked, "rmnet0")
        assertFalse(linked.has("streamSettings"))
        val freedom = JSONObject().put("protocol", "freedom")
        NodeRules.bindDevice(freedom, "v4-rmnet0")
        assertEquals("v4-rmnet0", freedom.getJSONObject("streamSettings").getJSONObject("sockopt").getString("interface"))
    }

    @Test
    fun androidJsonKeepsLastDuplicateKey() {
        val obj = JSONObject("{\"address\":\"203.0.113.10\",\"address\":\"127.0.0.1\"}")
        assertEquals("127.0.0.1", obj.getString("address"))
        assertEquals(1, obj.length())
    }

    @Test
    fun androidJsonTurnsNullIntoText() {
        val obj = JSONObject().put("tag", JSONObject.NULL)
        assertEquals("null", obj.optString("tag"))
    }

    private fun assertPinned(target: JSONObject) {
        val sockopt = target.getJSONObject("sockopt")
        assertEquals("ForceIP", sockopt.getString("domainStrategy"))
        assertEquals(250, sockopt.getJSONObject("happyEyeballs").getInt("tryDelayMs"))
    }

    @Test
    fun preferV4KeepsV6OnlyHosts() {
        val hosts = mapOf("a" to listOf("2606:4700::1", "1.2.3.4"), "b" to listOf("2606:4700::2"))
        assertEquals(mapOf("a" to listOf("1.2.3.4"), "b" to listOf("2606:4700::2")), NodeRules.preferV4(hosts, true))
        assertEquals(hosts, NodeRules.preferV4(hosts, false))
    }

    private companion object {
        const val RESOLVE_MS = 600L
    }

    private fun canonical(hosts: Map<String, List<String>>): Map<String, List<String>> =
        hosts.mapValues { (_, ips) -> ips.map { InetAddress.getByName(it).hostAddress } }

    private fun hostsOfText(obj: JSONObject): Map<String, String> = obj.keys().asSequence().map { it as String }.associateWith { obj.getString(it) }
}
