package ru.vpncheck.agent

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

class PingWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val ctx = applicationContext
        val prefs = Prefs(ctx)
        if (!prefs.consented || prefs.paused) return@withContext Result.success()
        try {
            PendingReports.flush(ctx)
        } catch (e: Exception) {
            ErrorLog.recordLimited(ctx, "report-deferred", e)
        }
        if (System.currentTimeMillis() - prefs.linkOkAt in 0 until LinkService.LINK_FRESH_MS) {
            return@withContext Result.success()
        }
        try {
            val answer = Api.ping(prefs.agentId)
            val runNow = answer.optDouble("run_now", 0.0)
            if (runNow > prefs.lastRunNowSeen) {
                prefs.lastRunNowSeen = runNow
                if (!prefs.running) Scheduler.runNow(ctx)
            }
            val updateNow = answer.optDouble("update_now", 0.0)
            if (updateNow > prefs.lastUpdateNowSeen) {
                prefs.lastUpdateNowSeen = updateNow
                Updater(ctx).fetchAndApply()
            }
            val locateNow = answer.optDouble("locate_now", 0.0)
            if (locateNow > prefs.lastLocateSeen) {
                prefs.lastLocateSeen = locateNow
                LocateTask.run(ctx)
            }
            Scheduler.updateInterval(ctx, prefs, answer.optInt("interval_min", prefs.intervalMin))
        } catch (ignored: IOException) {
        } catch (e: Exception) {
            ErrorLog.record(ctx, "ping", e)
        }
        Result.success()
    }
}
