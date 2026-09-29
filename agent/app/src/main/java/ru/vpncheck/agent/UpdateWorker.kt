package ru.vpncheck.agent

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

class UpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val ctx = applicationContext
        val prefs = Prefs(ctx)
        if (!prefs.consented || prefs.paused || !Api.paired()) return@withContext Result.success()
        try {
            Updater(ctx).fetchAndApply()
            Result.success()
        } catch (_: IOException) {
            if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.success()
        } catch (e: Exception) {
            ErrorLog.record(ctx, "update", e)
            Result.success()
        }
    }

    private companion object {
        const val MAX_ATTEMPTS = 3
    }
}
