package ru.vpncheck.agent

import android.content.Context
import java.util.UUID

class Prefs(context: Context) {
    private val sp = context.getSharedPreferences("agent", Context.MODE_PRIVATE)

    val agentId: String
        get() = sp.getString("agent_id", null) ?: synchronized(LOCK) {
            sp.getString("agent_id", null) ?: UUID.randomUUID().toString().also {
                sp.edit().putString("agent_id", it).commit()
            }
        }

    var consented: Boolean
        get() = sp.getBoolean("consented", false)
        set(value) = sp.edit().putBoolean("consented", value).apply()

    var paused: Boolean
        get() = sp.getBoolean("paused", false)
        set(value) = sp.edit().putBoolean("paused", value).apply()

    var intervalMin: Int
        get() = sp.getInt("interval_min", 180)
        set(value) = sp.edit().putInt("interval_min", value).apply()

    var lastCheck: Long
        get() = sp.getLong("last_check", 0)
        set(value) = sp.edit().putLong("last_check", value).apply()

    var lastSummary: String
        get() = sp.getString("last_summary", "").orEmpty()
        set(value) = sp.edit().putString("last_summary", value).apply()

    var lastDetails: String
        get() = sp.getString("last_details", "").orEmpty()
        set(value) = sp.edit().putString("last_details", value).apply()

    var lastRegion: String
        get() = sp.getString("last_region", "").orEmpty()
        set(value) = sp.edit().putString("last_region", value).apply()

    var running: Boolean
        get() = sp.getBoolean("running", false)
        set(value) = sp.edit().putBoolean("running", value).apply()

    var apkShaCache: String
        get() = sp.getString("apk_sha_cache", "").orEmpty()
        set(value) = sp.edit().putString("apk_sha_cache", value).apply()

    var pendingApk: String
        get() = sp.getString("pending_apk", "").orEmpty()
        set(value) = sp.edit().putString("pending_apk", value).apply()

    var pushToken: String
        get() = sp.getString("push_token", "").orEmpty()
        set(value) = sp.edit().putString("push_token", value).apply()

    var pushTokenSent: Boolean
        get() = sp.getBoolean("push_token_sent", false)
        set(value) = sp.edit().putBoolean("push_token_sent", value).apply()

    var lastRunNowSeen: Double
        get() = getExactDouble("run_now_seen")
        set(value) = putExactDouble("run_now_seen", value)

    var lastUpdateNowSeen: Double
        get() = getExactDouble("update_now_seen")
        set(value) = putExactDouble("update_now_seen", value)

    var lastLocateSeen: Double
        get() = getExactDouble("locate_now_seen")
        set(value) = putExactDouble("locate_now_seen", value)

    var lastLocateRun: Long
        get() = sp.getLong("locate_run", 0)
        set(value) = sp.edit().putLong("locate_run", value).apply()

    var linkErrorAt: Long
        get() = sp.getLong("link_error_at", 0)
        set(value) = sp.edit().putLong("link_error_at", value).apply()

    var lastManifestIssued: Long
        get() = sp.getLong("manifest_issued", 0)
        set(value) = sp.edit().putLong("manifest_issued", value).apply()

    var pendingApkCode: Int
        get() = sp.getInt("pending_apk_code", 0)
        set(value) = sp.edit().putInt("pending_apk_code", value).apply()

    var pendingApkVersion: String
        get() = sp.getString("pending_apk_version", "").orEmpty()
        set(value) = sp.edit().putString("pending_apk_version", value).apply()

    var locLat: Float
        get() = sp.getFloat("loc_lat", 0f)
        set(value) = sp.edit().putFloat("loc_lat", value).apply()

    var locLon: Float
        get() = sp.getFloat("loc_lon", 0f)
        set(value) = sp.edit().putFloat("loc_lon", value).apply()

    var locCity: String
        get() = sp.getString("loc_city", "").orEmpty()
        set(value) = sp.edit().putString("loc_city", value).apply()

    var locRegion: String
        get() = sp.getString("loc_region", "").orEmpty()
        set(value) = sp.edit().putString("loc_region", value).apply()

    var locShown: String
        get() = sp.getString("loc_shown", "").orEmpty()
        set(value) = sp.edit().putString("loc_shown", value).apply()

    var locationAsked: Boolean
        get() = sp.getBoolean("location_asked", false)
        set(value) = sp.edit().putBoolean("location_asked", value).apply()

    var locRound: Float
        get() = sp.getFloat("loc_round", DEFAULT_ROUND).takeIf { it.isFinite() }?.coerceIn(1f, 5000f) ?: DEFAULT_ROUND
        set(value) = sp.edit().putFloat("loc_round", value).apply()

    var locAccuracy: Float
        get() = sp.getFloat("loc_accuracy", 0f)
        set(value) = sp.edit().putFloat("loc_accuracy", value).apply()

    var locateRequested: Boolean
        get() = sp.getBoolean("locate_requested", false)
        set(value) = sp.edit().putBoolean("locate_requested", value).apply()

    var locTs: Long
        get() = sp.getLong("loc_ts", 0)
        set(value) = sp.edit().putLong("loc_ts", value).apply()

    var serverMessage: String
        get() = sp.getString("server_message", "").orEmpty()
        set(value) = sp.edit().putString("server_message", value).apply()

    var linkAfter: Long
        get() = sp.getLong("link_after", 0)
        set(value) = sp.edit().putLong("link_after", value).apply()

    var serverUrl: String
        get() = sp.getString("server_url", null)?.takeIf { it.isNotEmpty() } ?: BuildConfig.SERVER
        set(value) = sp.edit().putString("server_url", value.trimEnd('/')).apply()

    var manifestKey: String
        get() = sp.getString("manifest_key", null)?.takeIf { it.isNotEmpty() } ?: BuildConfig.MANIFEST_PUBKEY
        set(value) = sp.edit().putString("manifest_key", value.lowercase()).apply()

    var tls: PinnedTls?
        get() {
            if (sp.getString("tls_server", "") != serverUrl) return null
            return PinnedTls.parse(
                serverUrl,
                org.json.JSONObject().put("port", sp.getInt("tls_port", 0)).put("pin", sp.getString("tls_pin", "").orEmpty()),
            )
        }
        set(value) {
            val edit = sp.edit()
            if (value == null) edit.remove("tls_server").remove("tls_port").remove("tls_pin")
            else edit.putString("tls_server", serverUrl).putInt("tls_port", value.port).putString("tls_pin", value.pin)
            edit.apply()
        }

    var tlsIssued: Long
        get() = sp.getLong("tls_issued", 0)
        set(value) = sp.edit().putLong("tls_issued", value).apply()

    var rejectedApk: String
        get() = sp.getString("rejected_apk", "").orEmpty()
        set(value) = sp.edit().putString("rejected_apk", value).apply()

    var linkOkAt: Long
        get() = sp.getLong("link_ok_at", 0)
        set(value) = sp.edit().putLong("link_ok_at", value).apply()

    fun due(key: String, everyMs: Long, now: Long = System.currentTimeMillis()): Boolean = synchronized(LOCK) {
        val last = sp.getLong("due_$key", 0)
        if (now - last in 0 until everyMs) return false
        sp.edit().putLong("due_$key", now).apply()
        true
    }

    fun pruneDue(prefix: String, keepMs: Long, now: Long = System.currentTimeMillis()) = synchronized(LOCK) {
        val stale = sp.all.filter { (key, value) -> key.startsWith("due_$prefix") && value is Long && now - value !in 0 until keepMs }
        if (stale.isNotEmpty()) sp.edit().apply { stale.keys.forEach { remove(it) } }.apply()
    }

    fun addDetailLine(line: String) = editDetails { if (it.contains(line)) it else (it + "\n" + line).trim() }

    fun editDetails(change: (String) -> String) = synchronized(LOCK) { lastDetails = change(lastDetails) }

    private fun getExactDouble(key: String): Double =
        if (sp.contains("${key}_bits")) java.lang.Double.longBitsToDouble(sp.getLong("${key}_bits", 0))
        else sp.getFloat(key, 0f).toDouble()

    private fun putExactDouble(key: String, value: Double) =
        sp.edit().putLong("${key}_bits", java.lang.Double.doubleToRawLongBits(value)).remove(key).apply()

    private companion object {
        const val DEFAULT_ROUND = 200f
        val LOCK = Any()
    }
}
