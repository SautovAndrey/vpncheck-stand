package ru.vpncheck.agent

import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

object ErrorLog {
    private const val MAX = 30
    private const val PER_SEND = 10
    private const val LIMITED_EVERY_MS = 3600_000L
    private const val KEYED_KEEP_MS = 24 * 3600_000L
    private val inFlight = HashSet<String>()

    private fun file(context: Context) = File(context.filesDir, "errors.json")

    @Synchronized
    fun record(context: Context, kind: String, error: Throwable?, text: String? = null) {
        val body = text ?: error?.let { it.javaClass.simpleName + ": " + it.message.orEmpty() + "\n" + it.stackTraceToString().take(2000) }
            .orEmpty()
        val items = readAll(context)
        items.put(JSONObject().put("ts", System.currentTimeMillis()).put("kind", kind).put("text", body.take(2500)))
        while (items.length() > MAX) items.remove(0)
        write(context, items)
    }

    fun recordLimited(context: Context, kind: String, error: Throwable?, everyMs: Long = LIMITED_EVERY_MS, text: String? = null,
                      dueKey: String = kind) {
        val prefs = Prefs(context)
        if (!prefs.due("error_$dueKey", everyMs)) return
        if (dueKey != kind) prefs.pruneDue("error_$kind:", KEYED_KEEP_MS)
        record(context, kind, error, text)
    }

    @Synchronized
    fun readAll(context: Context): JSONArray = try {
        JsonStore.read(file(context))
    } catch (_: Exception) { JSONArray() }

    @Synchronized
    fun claim(context: Context): JSONArray {
        val all = readAll(context)
        val out = JSONArray()
        for (i in 0 until all.length()) {
            if (out.length() >= PER_SEND) break
            if (inFlight.add(all.get(i).toString())) out.put(all.get(i))
        }
        return out
    }

    @Synchronized
    fun release(sent: JSONArray) {
        for (i in 0 until sent.length()) inFlight.remove(sent.get(i).toString())
    }

    @Synchronized
    fun forget(context: Context, sent: JSONArray) {
        if (sent.length() == 0) return
        val sentKeys = (0 until sent.length()).map { sent.get(it).toString() }.toSet()
        inFlight.removeAll(sentKeys)
        val current = readAll(context)
        val left = JSONArray()
        for (i in 0 until current.length()) {
            if (current.get(i).toString() !in sentKeys) left.put(current.get(i))
        }
        write(context, left)
    }

    private fun write(context: Context, items: JSONArray) {
        try {
            JsonStore.write(file(context), items)
        } catch (ignored: Exception) {
        }
    }

    fun flush(context: Context) {
        val items = claim(context)
        if (items.length() == 0) return
        Thread {
            try {
                Api.postErrors(JSONObject().apply {
                    put("agent_id", Prefs(context).agentId)
                    put("app_version", BuildConfig.VERSION_NAME)
                    put("device", JSONObject().put("model", Build.MODEL).put("android", Build.VERSION.RELEASE))
                    put("errors", items)
                })
                forget(context, items)
            } catch (_: Exception) {
                release(items)
            }
        }.start()
    }

    fun install(context: Context) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            record(context, "crash", error)
            previous?.uncaughtException(thread, error)
        }
    }
}
