package ru.vpncheck.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationManagerCompat

object Notifications {
    const val CHANNEL_LINK = "link"
    const val CHANNEL_MESSAGES = "messages"
    private const val OLD_CHANNEL = "agent"
    const val UPDATE = 1001
    const val LOCATE = 1002
    const val MESSAGE = 1003
    const val LINK = 1010

    fun createChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.deleteNotificationChannel(OLD_CHANNEL)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_LINK, context.getString(R.string.channel_link), NotificationManager.IMPORTANCE_MIN)
        )
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_MESSAGES, context.getString(R.string.channel_messages), NotificationManager.IMPORTANCE_DEFAULT)
        )
    }

    fun openApp(context: Context, requestCode: Int): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(context, requestCode, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }

    fun show(context: Context, id: Int, icon: Int, title: String, text: String, contentIntent: PendingIntent) {
        val notification = Notification.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(id, notification)
        } catch (ignored: SecurityException) {
        }
    }
}
