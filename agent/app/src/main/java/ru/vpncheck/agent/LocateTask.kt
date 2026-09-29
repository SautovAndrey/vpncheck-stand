package ru.vpncheck.agent

import android.content.Context
import org.json.JSONObject
import java.io.IOException

object LocateTask {
    private const val REPEAT_MS = 10 * 60_000L

    fun run(context: Context, force: Boolean = false) {
        val prefs = Prefs(context)
        if (!prefs.consented) return
        synchronized(this) {
            val now = System.currentTimeMillis()
            if (!force && now - prefs.lastLocateRun in 0 until REPEAT_MS) return
            prefs.lastLocateRun = now
        }
        val location = Locator.precise(context)
        if (location == null) {
            prefs.locateRequested = true
            Notifications.show(
                context, Notifications.LOCATE, android.R.drawable.ic_menu_mylocation,
                context.getString(R.string.locate_notif_title), context.getString(R.string.locate_notif_text),
                Notifications.openApp(context, Notifications.LOCATE)
            )
            return
        }
        val accuracy = if (location.hasAccuracy()) location.accuracy else 0f
        val place = Locator.placeOf(context, location.latitude, location.longitude)
        val (city, region) = place
        val shown = Locator.shownPlace(context, location.latitude, location.longitude, place)
        val line = try {
            val answer = Api.postLocation(JSONObject().apply {
                put("agent_id", prefs.agentId)
                put("lat", location.latitude); put("lon", location.longitude)
                put("accuracy", accuracy.toDouble())
                put("city", city); put("region", region); put("source", "gps")
            })
            if (!answer.optBoolean("ok", true)) {
                context.getString(R.string.loc_not_accepted)
            } else {
                prefs.locateRequested = false
                if (city.isNotEmpty()) prefs.locCity = city
                if (region.isNotEmpty()) prefs.locRegion = region
                if (city.isNotEmpty() || region.isNotEmpty()) prefs.locShown = Locator.joinPlace(shown)
                val label = shown.first.ifEmpty { context.getString(R.string.loc_coords_sent) }
                context.getString(R.string.loc_refined, label, accuracy)
            }
        } catch (e: Api.HttpError) {
            if (e.code != 429) ErrorLog.record(context, "locate", e)
            context.getString(if (e.code == 429) R.string.loc_too_often else R.string.loc_not_accepted)
        } catch (_: IOException) {
            context.getString(R.string.loc_not_sent)
        } catch (e: Exception) {
            ErrorLog.record(context, "locate", e)
            context.getString(R.string.loc_not_sent)
        }
        prefs.editDetails { details ->
            val rest = details.lines().filterNot { it.trimStart().startsWith("📍") }.joinToString("\n")
            (line + "\n" + rest).trim()
        }
    }
}
