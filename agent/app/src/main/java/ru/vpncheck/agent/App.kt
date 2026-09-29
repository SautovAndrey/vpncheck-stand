package ru.vpncheck.agent

import android.app.Application
import androidx.work.Configuration
import java.io.File

class App : Application(), Configuration.Provider {
    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        ErrorLog.install(this)
        File(filesDir, "core").deleteRecursively()
        File(cacheDir, "xray").deleteRecursively()
        Pairing.load(this)
        val prefs = Prefs(this)
        prefs.running = false
        if (prefs.consented) {
            Scheduler.ensure(this)
            ErrorLog.flush(this)
            fetchPushToken()
            LinkService.start(this)
        }
    }

    private fun fetchPushToken() {
        try {
            com.google.firebase.messaging.FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
                val prefs = Prefs(this)
                if (token != null && (token != prefs.pushToken || !prefs.pushTokenSent)) {
                    prefs.pushToken = token
                    Thread { PushService.sendToken(this, prefs) }.start()
                }
            }
        } catch (ignored: Exception) {
        }
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setMinimumLoggingLevel(android.util.Log.INFO).build()
}
