package ru.vpncheck.agent

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

object PendingReports {
    private const val MAX = 4
    private const val MAX_AGE_MS = 12 * 3600_000L
    private const val MAX_AHEAD_MS = 24 * 3600_000L
    private val flushing = AtomicBoolean(false)

    private fun file(context: Context) = File(context.filesDir, "pending_reports.json")

    @Synchronized
    fun save(context: Context, payload: JSONObject) {
        val copy = JSONObject(payload.toString())
        copy.remove("errors")
        copy.remove("report_via")
        val items = fresh(context)
        items.put(JSONObject().put("saved_at", System.currentTimeMillis()).put("payload", copy))
        while (items.length() > MAX) items.remove(0)
        write(context, items)
    }

    @Synchronized
    fun count(context: Context): Int = fresh(context).length()

    fun flush(context: Context): Int {
        if (!flushing.compareAndSet(false, true)) return 0
        try {
            val items = synchronized(this) { fresh(context) }
            val done = HashSet<String>()
            var sent = 0
            for (i in 0 until items.length()) {
                val item = items.getJSONObject(i)
                val key = keyOf(item)
                when (sendOne(context, item)) {
                    Outcome.SENT -> { sent++; done.add(key) }
                    Outcome.DROP -> done.add(key)
                    Outcome.KEEP -> break
                }
            }
            if (done.isNotEmpty()) forget(context, done)
            return sent
        } finally {
            flushing.set(false)
        }
    }

    @Synchronized
    private fun forget(context: Context, done: Set<String>) {
        val current = fresh(context)
        val left = JSONArray()
        for (i in 0 until current.length()) {
            val item = current.getJSONObject(i)
            if (keyOf(item) !in done) left.put(item)
        }
        write(context, left)
    }

    private fun keyOf(item: JSONObject): String =
        item.optLong("saved_at").toString() + "/" + item.optJSONObject("payload")?.optString("report_id").orEmpty()

    private enum class Outcome { SENT, DROP, KEEP }

    private fun sendOne(context: Context, item: JSONObject): Outcome {
        val payload = item.optJSONObject("payload") ?: return Outcome.DROP
        val ageS = ((System.currentTimeMillis() - item.optLong("saved_at")) / 1000).coerceAtLeast(0)
        payload.put("report_via", "default").put("deferred_s", ageS)
        return try {
            Api.report(payload)
            Outcome.SENT
        } catch (e: Api.HttpError) {
            if (e.code in 400..499 && e.code != 429) {
                ErrorLog.recordLimited(context, "report-deferred", e)
                Outcome.DROP
            } else {
                Outcome.KEEP
            }
        } catch (_: IOException) {
            Outcome.KEEP
        }
    }

    private fun fresh(context: Context): JSONArray {
        val all = try {
            JsonStore.read(file(context))
        } catch (_: Exception) {
            JSONArray()
        }
        val now = System.currentTimeMillis()
        val out = JSONArray()
        for (i in 0 until all.length()) {
            val item = all.optJSONObject(i) ?: continue
            if (isFresh(item.optLong("saved_at"), now)) out.put(item)
        }
        return out
    }

    fun isFresh(savedAt: Long, now: Long): Boolean = savedAt > 0 && savedAt - now <= MAX_AHEAD_MS && now - savedAt < MAX_AGE_MS

    private fun write(context: Context, items: JSONArray) {
        try {
            JsonStore.write(file(context), items)
        } catch (e: IOException) {
            ErrorLog.recordLimited(context, "report-deferred", e)
        }
    }
}
