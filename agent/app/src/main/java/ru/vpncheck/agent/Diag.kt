package ru.vpncheck.agent

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.telephony.TelephonyManager
import org.json.JSONArray
import org.json.JSONObject

object Diag {
    fun collect(context: Context): JSONObject {
        val prefs = Prefs(context)
        val out = JSONObject()
        out.put("app_version", BuildConfig.VERSION_NAME).put("app_code", BuildConfig.VERSION_CODE)
        out.put("core_version", XrayRunner(context).coreVersion())
        out.put("android", Build.VERSION.RELEASE).put("model", Build.MODEL).put("brand", Build.BRAND)

        try {
            val batt = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val level = batt?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = batt?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
            val status = batt?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
            out.put("battery_pct", if (level >= 0) level * 100 / scale else -1)
            out.put("charging", status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL)
        } catch (ignored: Exception) {}

        try {
            val pm = context.getSystemService(PowerManager::class.java)
            out.put("ignores_battery_optimizations", pm.isIgnoringBatteryOptimizations(context.packageName))
            out.put("power_save_mode", pm.isPowerSaveMode)
        } catch (ignored: Exception) {}
        try {
            val am = context.getSystemService(ActivityManager::class.java)
            if (Build.VERSION.SDK_INT >= 28) out.put("background_restricted", am.isBackgroundRestricted)
        } catch (ignored: Exception) {}

        out.put("network", NetInfo.describe(context))
        try {
            val tm = context.getSystemService(TelephonyManager::class.java)
            if (Build.VERSION.SDK_INT >= 28) tm.signalStrength?.let { out.put("signal_level", it.level) }
            out.put("sim_state", tm.simState)
        } catch (ignored: Exception) {}
        try {
            out.put("usable_networks", NetInfo.usableNetworkCount(context))
        } catch (ignored: Exception) {}

        out.put("consented", prefs.consented).put("paused", prefs.paused).put("running", prefs.running)
        out.put("interval_min", prefs.intervalMin)
        out.put("last_check", prefs.lastCheck).put("last_summary", prefs.lastSummary)
        out.put("push_token_present", prefs.pushToken.isNotEmpty())
        out.put("location_granted", Locator.granted(context))

        try {
            val errs = ErrorLog.readAll(context)
            val last = JSONArray()
            val from = maxOf(0, errs.length() - 5)
            for (i in from until errs.length()) last.put(errs.get(i))
            out.put("recent_errors", last)
        } catch (ignored: Exception) {}
        return out
    }
}
