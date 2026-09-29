package ru.vpncheck.agent

import android.content.Context
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

object Commands {
    private const val SPEED_URL = "https://speed.cloudflare.com/__down?bytes=8000000"
    private const val LOG_TEST_URL = "https://api.ipify.org"
    private const val BANNER_HOST = "neverssl.com"
    private const val BANNER_MAX_BYTES = 256 * 1024

    fun dispatch(context: Context, action: String, text: String = "", seq: Long = 0) {
        val prefs = Prefs(context)
        if (!prefs.consented || prefs.paused) return
        when (action) {
            "check" -> if (!prefs.running) Scheduler.runNow(context)
            "locate" -> Thread { LocateTask.run(context) }.start()
            "update" -> Thread { pullUpdate(context) }.start()
            "message" -> if (text.isNotEmpty()) {
                prefs.serverMessage = text
                notify(context, context.getString(R.string.notif_message_title), text)
            }
            "vpn_off" -> {
                prefs.serverMessage = context.getString(R.string.vpn_off_message)
                notify(context, context.getString(R.string.vpn_off_title), context.getString(R.string.vpn_off_text))
            }
            "site_check" -> if (text.isNotEmpty()) withResult(context, prefs, action, seq) { siteCheck(context, text) }
            "diag" -> withResult(context, prefs, action, seq) { Diag.collect(context) }
            "xray_log" -> if (text.isNotEmpty()) withResult(context, prefs, action, seq) { xrayLog(context, text) }
            "speed" -> if (text.isNotEmpty()) withResult(context, prefs, action, seq) { speed(context, text) }
            "whitelist_banner" -> withResult(context, prefs, action, seq) { whitelistBanner() }
        }
    }

    private fun withResult(context: Context, prefs: Prefs, action: String, seq: Long, task: () -> JSONObject) {
        Thread {
            val result = try {
                task()
            } catch (e: Exception) {
                ErrorLog.record(context, "cmd-$action", e)
                JSONObject().put("error", (e.message ?: e.javaClass.simpleName).take(200))
            }
            try {
                Api.postResult(prefs.agentId, action, seq, result)
            } catch (ignored: IOException) {
            } catch (e: Exception) {
                ErrorLog.record(context, "cmd-result", e)
            }
        }.start()
    }

    private fun siteCheck(context: Context, url: String): JSONObject {
        val r = SiteCheck.direct(url)
        return JSONObject().put("url", url).put("ok", r.ok).put("code", r.code)
            .put("ms", r.ms ?: JSONObject.NULL).put("error", r.error)
            .put("network", NetInfo.describe(context))
    }

    private fun findNode(context: Context, key: String): JSONObject? {
        val nodes = Api.config(context).optJSONArray("nodes") ?: return null
        for (i in 0 until nodes.length()) {
            val n = nodes.getJSONObject(i)
            if (n.optString("key") == key) return n
        }
        return null
    }

    private fun withNode(context: Context, key: String, task: (node: JSONObject) -> JSONObject): JSONObject {
        val node = findNode(context, key)
            ?: return JSONObject().put("node", key).put("error", "node not found in current list")
        if (node.optJSONObject("outbound") == null) return JSONObject().put("node", key).put("error", "node has no outbound")
        return task(node).put("node", key).put("location", node.optString("location"))
            .put("network", NetInfo.describe(context))
    }

    private fun xrayLog(context: Context, key: String): JSONObject = withNode(context, key) { node ->
        val log = XrayRunner(context).captureLog(node, LOG_TEST_URL)
        JSONObject().put("log", log.take(12_000))
    }

    private fun speed(context: Context, key: String): JSONObject = withNode(context, key) { node ->
        val s = XrayRunner(context).speed(node, SPEED_URL)
        JSONObject().put("ok", s.ok).put("bytes", s.bytes).put("ms", s.ms)
            .put("mbps", Math.round(s.mbps * 10) / 10.0).put("error", s.error)
    }

    private fun whitelistBanner(): JSONObject {
        val host = BANNER_HOST
        return try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress(host, 80), 10000)
                sock.soTimeout = 10000
                val req = "GET / HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\n" +
                    "Accept: text/html\r\nConnection: close\r\n\r\n"
                sock.getOutputStream().apply { write(req.toByteArray()); flush() }
                val raw = readLimited(sock.getInputStream(), BANNER_MAX_BYTES).toString(Charsets.UTF_8)
                val head = raw.substringBefore("\r\n\r\n", raw)
                val body = raw.substringAfter("\r\n\r\n", "")
                val status = head.lineSequence().firstOrNull()?.trim().orEmpty()
                val code = Regex("HTTP/\\d\\.\\d\\s+(\\d+)").find(status)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                val location = Regex("(?im)^location:\\s*(.+)$").find(head)?.groupValues?.get(1)?.trim().orEmpty()
                val title = Regex("<title[^>]*>(.*?)</title>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                    .find(body)?.groupValues?.get(1)?.trim().orEmpty()
                val text = body.replace(Regex("<script.*?</script>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE)), "")
                    .replace(Regex("<[^>]+>"), " ").replace(Regex("\\s+"), " ").trim()
                val banner = code in 300..399 || location.isNotEmpty() ||
                    (!title.contains("neverssl", true) && title.isNotEmpty()) ||
                    text.contains("белы", true) || text.contains("заблок", true) || text.contains("ограничен", true)
                JSONObject().put("host", host).put("status", status).put("code", code)
                    .put("location", location).put("title", title.take(200)).put("snippet", text.take(1500))
                    .put("looks_like_banner", banner)
            }
        } catch (e: Exception) {
            JSONObject().put("host", host).put("error", (e.message ?: e.javaClass.simpleName).take(120))
        }
    }

    private fun readLimited(input: InputStream, limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() < limit) {
            val n = input.read(buf, 0, minOf(buf.size, limit - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun pullUpdate(context: Context) {
        try {
            Updater(context).fetchAndApply()
        } catch (ignored: IOException) {
        } catch (e: Exception) {
            ErrorLog.record(context, "cmd-update", e)
        }
    }

    private fun notify(context: Context, title: String, body: String) {
        Notifications.show(context, Notifications.MESSAGE, android.R.drawable.ic_dialog_info, title, body,
            Notifications.openApp(context, Notifications.MESSAGE))
    }
}
