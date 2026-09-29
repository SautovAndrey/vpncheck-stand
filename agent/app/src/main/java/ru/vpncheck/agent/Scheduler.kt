package ru.vpncheck.agent

import android.content.Context
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

object Scheduler {
    private const val PERIODIC = "agent-periodic"
    private const val ONCE = "agent-once"
    private const val LATER = "agent-later"
    private const val PING = "agent-ping"
    private const val UPDATE = "agent-update"
    const val KEY_ONCE = "once"

    private fun connected() = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    private fun onceData() = Data.Builder().putBoolean(KEY_ONCE, true).build()

    fun ensure(context: Context, intervalMin: Int = Prefs(context).intervalMin) {
        val workManager = WorkManager.getInstance(context)
        val constraints = connected()
        val check = PeriodicWorkRequestBuilder<CheckWorker>(
            intervalMin.coerceAtLeast(15).toLong(), TimeUnit.MINUTES
        ).setConstraints(constraints).build()
        workManager.enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.UPDATE, check)
        val ping = PeriodicWorkRequestBuilder<PingWorker>(15, TimeUnit.MINUTES).setConstraints(constraints).build()
        workManager.enqueueUniquePeriodicWork(PING, ExistingPeriodicWorkPolicy.UPDATE, ping)
    }

    fun updateInterval(context: Context, prefs: Prefs, intervalMin: Int) {
        if (intervalMin == prefs.intervalMin) return
        prefs.intervalMin = intervalMin
        ensure(context, intervalMin)
    }

    fun runNow(context: Context) {
        if (Prefs(context).running) return
        enqueueOnce(context, ExistingWorkPolicy.KEEP)
    }

    fun runNowFromUser(context: Context): Boolean {
        val app = context.applicationContext
        if (Prefs(app).running || CheckWorker.active) return false
        Thread {
            val policy = try {
                userPolicy(WorkManager.getInstance(app).getWorkInfosForUniqueWork(ONCE).get(5, TimeUnit.SECONDS))
            } catch (_: Exception) {
                ExistingWorkPolicy.KEEP
            }
            if (!Prefs(app).running && !CheckWorker.active) enqueueOnce(app, policy)
        }.start()
        return true
    }

    private fun userPolicy(infos: List<WorkInfo>): ExistingWorkPolicy =
        if (infos.any { it.state == WorkInfo.State.ENQUEUED && it.runAttemptCount > 0 } &&
            infos.none { it.state == WorkInfo.State.RUNNING }
        ) {
            ExistingWorkPolicy.REPLACE
        } else {
            ExistingWorkPolicy.KEEP
        }

    private fun enqueueOnce(context: Context, policy: ExistingWorkPolicy) {
        val request = OneTimeWorkRequestBuilder<CheckWorker>().setConstraints(connected()).setInputData(onceData()).build()
        WorkManager.getInstance(context).enqueueUniqueWork(ONCE, policy, request)
    }

    fun runLater(context: Context, minutes: Long) {
        val request = OneTimeWorkRequestBuilder<CheckWorker>().setInitialDelay(minutes, TimeUnit.MINUTES)
            .setConstraints(connected()).setInputData(onceData()).build()
        WorkManager.getInstance(context).enqueueUniqueWork(LATER, ExistingWorkPolicy.REPLACE, request)
    }

    fun fetchUpdate(context: Context) {
        val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build()
        val request = OneTimeWorkRequestBuilder<UpdateWorker>().setConstraints(constraints).build()
        WorkManager.getInstance(context).enqueueUniqueWork(UPDATE, ExistingWorkPolicy.KEEP, request)
    }

    fun cancel(context: Context) {
        val workManager = WorkManager.getInstance(context)
        for (name in listOf(PERIODIC, ONCE, LATER, PING, UPDATE)) workManager.cancelUniqueWork(name)
    }
}
