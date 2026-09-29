package ru.vpncheck.agent

import android.app.ForegroundServiceStartNotAllowedException
import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import okhttp3.Call
import org.json.JSONArray
import java.io.IOException
import java.util.concurrent.atomic.AtomicReference
import kotlin.random.Random

class LinkService : Service() {
    @Volatile private var running = false
    private var worker: Thread? = null
    private val call = AtomicReference<Call?>()
    @Volatile private var shortWaitUntil = 0L
    @Volatile private var shortWait = WIFI_WAIT_S
    @Volatile private var askedAt = 0L
    @Volatile private var askedWait = 0
    @Volatile private var askedNet: Network? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!startForegroundSafe()) {
            stopSelf()
            return START_NOT_STICKY
        }
        val prefs = Prefs(applicationContext)
        if (!prefs.consented || prefs.paused) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!running) {
            running = true
            worker = Thread { loop() }.apply { isDaemon = true; start() }
        }
        return START_STICKY
    }

    private fun loop() {
        val prefs = Prefs(applicationContext)
        var backoff = MIN_BACKOFF_MS
        while (running) {
            if (!prefs.consented || prefs.paused) {
                running = false
                stopSelf()
                return
            }
            try {
                val pause = pollOnce(prefs)
                backoff = MIN_BACKOFF_MS
                if (pause > 0) Thread.sleep(pause)
            } catch (_: InterruptedException) {
                continue
            } catch (e: Exception) {
                if (e is IOException && e !is Api.HttpError && running && sameNetwork()) stepDown()
                if (e !is IOException || e is Api.HttpError) ErrorLog.recordLimited(applicationContext, "link", e)
                val pause = (backoff * Random.nextDouble(1 - JITTER, 1 + JITTER)).toLong()
                try { Thread.sleep(pause) } catch (_: InterruptedException) { continue }
                backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
            }
        }
    }

    private fun pollOnce(prefs: Prefs): Long {
        val after = prefs.linkAfter
        val wait = waitSec()
        val askedAt = System.currentTimeMillis()
        this.askedAt = askedAt
        askedWait = wait
        askedNet = activeNet()
        val answer = Api.poll(prefs.agentId, after, wait, call)
        if (!running) return 0
        val now = System.currentTimeMillis()
        if (now - prefs.linkOkAt !in 0 until LINK_OK_WRITE_MS) prefs.linkOkAt = now
        val waitedMs = now - askedAt
        val commands = answer.optJSONArray("commands") ?: JSONArray()
        val serverTime = answer.optLong("server_time", 0)
        val ceiling = if (serverTime > 0) serverTime * 1000 + MAX_AHEAD_MS else Long.MAX_VALUE
        if (after > ceiling) {
            prefs.linkAfter = 0
            return 0
        }
        if (after == 0L) {
            check(serverTime > 0) { "poll: no server_time" }
            val start = if (waitedMs < QUICK_ANSWER_MS) {
                var latest = answer.optLong("seq", 0)
                for (i in 0 until commands.length()) latest = maxOf(latest, commands.getJSONObject(i).optLong("seq"))
                maxOf(latest.coerceAtMost(ceiling), (serverTime - 2) * 1000)
            } else {
                serverTime * 1000 - waitedMs - 2000
            }
            prefs.linkAfter = start.coerceAtLeast(1)
            return 0
        }
        val rejected = runCommands(prefs, commands, serverTime, ceiling)
        Scheduler.updateInterval(applicationContext, prefs, answer.optInt("interval_min", prefs.intervalMin))
        return when {
            rejected -> MAX_BACKOFF_MS
            commands.length() > 0 -> 300L
            else -> 0L
        }
    }

    private fun runCommands(prefs: Prefs, commands: JSONArray, serverTime: Long, ceiling: Long): Boolean {
        var rejected = false
        for (i in 0 until commands.length()) {
            val command = commands.getJSONObject(i)
            val seq = command.optLong("seq")
            if (seq > ceiling) {
                rejected = true
                continue
            }
            prefs.linkAfter = maxOf(prefs.linkAfter, seq)
            val ts = command.optDouble("ts", 0.0)
            if (serverTime > 0 && ts > 0 && serverTime - ts > MAX_AGE_S) continue
            try {
                Commands.dispatch(applicationContext, command.text("action"), command.text("text"), seq)
            } catch (e: Exception) {
                ErrorLog.record(applicationContext, "link-command", e)
            }
        }
        return rejected
    }

    private fun stepDown() {
        val held = System.currentTimeMillis() - askedAt
        val lower = WAIT_STEPS.firstOrNull { it < askedWait } ?: return
        if (held < lower * 1000L) return
        shortWait = lower
        shortWaitUntil = System.currentTimeMillis() + SHORT_WAIT_MS
    }

    private fun activeNet(): Network? = try {
        getSystemService(ConnectivityManager::class.java)?.activeNetwork
    } catch (_: Exception) { null }

    private fun sameNetwork(): Boolean {
        val asked = askedNet ?: return false
        return asked == activeNet()
    }

    private fun waitSec(): Int {
        val base = if (NetInfo.activeIsWifi(applicationContext)) WIFI_WAIT_S else MOBILE_WAIT_S
        return if (System.currentTimeMillis() < shortWaitUntil) minOf(base, shortWait) else base
    }

    override fun onDestroy() {
        running = false
        worker?.interrupt()
        call.getAndSet(null)?.cancel()
        super.onDestroy()
    }

    private fun startForegroundSafe(): Boolean {
        val notification = Notification.Builder(this, Notifications.CHANNEL_LINK)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle(getString(R.string.link_title))
            .setContentText(getString(R.string.link_text))
            .setContentIntent(Notifications.openApp(this, Notifications.LINK))
            .setOngoing(true)
            .build()
        return try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(Notifications.LINK, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(Notifications.LINK, notification)
            }
            true
        } catch (e: Exception) {
            ErrorLog.record(this, "link-foreground", e)
            false
        }
    }

    companion object {
        private const val MIN_BACKOFF_MS = 3000L
        private const val MAX_BACKOFF_MS = 60000L
        private const val JITTER = 0.3
        private const val MAX_AGE_S = 15 * 60
        private const val ERROR_EVERY_MS = 6 * 3600_000L
        private const val QUICK_ANSWER_MS = 5000L
        private const val MAX_AHEAD_MS = 24 * 3600_000L
        private const val LINK_OK_WRITE_MS = 60_000L
        private const val WIFI_WAIT_S = 240
        private const val MOBILE_WAIT_S = 110
        private const val SHORT_WAIT_S = 50
        private const val SHORT_WAIT_MS = 6 * 3600_000L
        private val WAIT_STEPS = listOf(WIFI_WAIT_S, MOBILE_WAIT_S, SHORT_WAIT_S)
        const val LINK_FRESH_MS = 15 * 60_000L

        fun start(context: Context) {
            val prefs = Prefs(context)
            if (!prefs.consented || prefs.paused || !Api.paired()) return
            try {
                context.startForegroundService(Intent(context, LinkService::class.java))
            } catch (e: Exception) {
                if (Build.VERSION.SDK_INT >= 31 && e is ForegroundServiceStartNotAllowedException) return
                val now = System.currentTimeMillis()
                if (now - prefs.linkErrorAt !in 0 until ERROR_EVERY_MS) {
                    prefs.linkErrorAt = now
                    ErrorLog.record(context, "link-start", e)
                }
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, LinkService::class.java))
        }
    }
}
