package ru.vpncheck.agent

import android.content.Context
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.json.JSONObject

class PushService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        val prefs = Prefs(this)
        prefs.pushToken = token
        prefs.pushTokenSent = false
        val app = applicationContext
        Thread { sendToken(app, prefs) }.start()
    }

    override fun onMessageReceived(message: RemoteMessage) {
        LinkService.start(this)
        Commands.dispatch(this, message.data["action"].orEmpty(), message.data["text"].orEmpty())
    }

    companion object {
        fun sendToken(context: Context, prefs: Prefs) {
            if (!prefs.consented || prefs.pushToken.isEmpty()) return
            try {
                Api.postToken(JSONObject().put("agent_id", prefs.agentId).put("push_token", prefs.pushToken)
                    .put("app_version", BuildConfig.VERSION_NAME))
                prefs.pushTokenSent = true
            } catch (e: Exception) {
                ErrorLog.recordLimited(context, "push-token", e)
            }
        }
    }
}
