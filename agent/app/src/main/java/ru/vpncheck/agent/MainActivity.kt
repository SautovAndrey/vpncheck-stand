package ru.vpncheck.agent

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONObject
import java.io.File
import java.lang.ref.WeakReference

class MainActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private var netCache: JSONObject? = null
    private var batteryCache = true
    private var cacheAt = 0L
    private val handler = Handler(Looper.getMainLooper())
    private val refresh = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val root = findViewById<View>(R.id.root)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        prefs = Prefs(this)
        offerPairing(intent)
        findViewById<TextView>(R.id.agentId).text = getString(R.string.agent_id, prefs.agentId.take(8))
        findViewById<TextView>(R.id.version).text = versionLine()

        findViewById<Button>(R.id.consentButton).setOnClickListener {
            prefs.consented = true
            prefs.paused = false
            val wanted = mutableListOf(Manifest.permission.ACCESS_COARSE_LOCATION)
            if (Build.VERSION.SDK_INT >= 33) wanted.add(Manifest.permission.POST_NOTIFICATIONS)
            requestPermissions(wanted.toTypedArray(), REQUEST_CONSENT)
            Scheduler.ensure(this)
            LinkService.start(this)
            render()
        }
        findViewById<Button>(R.id.installButton).setOnClickListener {
            val pending = prefs.pendingApk
            if (pending.isNotEmpty() && File(pending).exists()) {
                try {
                    startActivity(Updater(this).installIntent(File(pending)))
                } catch (e: Exception) {
                    ErrorLog.record(this, "install", e)
                }
            }
            render()
        }
        findViewById<Button>(R.id.checkButton).setOnClickListener {
            if (Scheduler.runNowFromUser(this)) {
                prefs.lastSummary = getString(R.string.summary_running)
                render()
            } else {
                Toast.makeText(this, R.string.check_already_running, Toast.LENGTH_SHORT).show()
                render()
            }
        }
        findViewById<Button>(R.id.batteryButton).setOnClickListener { openBatterySettings() }
        findViewById<Button>(R.id.locateButton).setOnClickListener {
            if (Locator.grantedFine(this)) {
                inBackground { app -> LocateTask.run(app, force = true) }
            } else {
                requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), REQUEST_PRECISE)
            }
        }
        findViewById<Button>(R.id.stopButton).setOnClickListener {
            if (prefs.paused) {
                prefs.paused = false
                Scheduler.ensure(this)
                LinkService.start(this)
            } else {
                prefs.paused = true
                Scheduler.cancel(this)
                LinkService.stop(this)
            }
            render()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        offerPairing(intent)
    }

    private fun offerPairing(intent: Intent?) {
        val target = Pairing.parse(intent?.data) ?: return
        intent?.data = null
        val baseNote = getString(when {
            target.key.isNotEmpty() -> R.string.pair_key
            prefs.manifestKey.isNotEmpty() -> R.string.pair_no_key_keep
            else -> R.string.pair_no_key
        })
        val keyNote = if (!Pairing.changesKey(this, target)) baseNote
            else getString(R.string.pair_key_changed) + "\n\n" + baseNote
        val tlsNote = getString(when (Pairing.tlsChange(this, target)) {
            Pairing.TlsChange.NEW -> R.string.pair_tls_new
            Pairing.TlsChange.KEPT -> R.string.pair_tls_kept
            Pairing.TlsChange.DROPPED -> R.string.pair_tls_dropped
            Pairing.TlsChange.NONE -> R.string.pair_tls_none
        })
        AlertDialog.Builder(this)
            .setTitle(R.string.pair_title)
            .setMessage(getString(R.string.pair_message, target.server, keyNote + "\n\n" + tlsNote))
            .setPositiveButton(R.string.pair_connect) { _, _ ->
                Pairing.apply(this, target)
                findViewById<TextView>(R.id.version).text = versionLine()
                if (prefs.consented) {
                    LinkService.stop(this)
                    LinkService.start(this)
                    Scheduler.runNowFromUser(this)
                }
                Toast.makeText(this, getString(R.string.pair_done, target.server), Toast.LENGTH_LONG).show()
            }
            .setNegativeButton(R.string.pair_cancel, null)
            .show()
    }

    private fun versionLine() =
        getString(R.string.version_line, BuildConfig.VERSION_NAME, XrayRunner(this).coreVersion(), Api.root())

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_PRECISE && Locator.grantedFine(this)) inBackground { app -> LocateTask.run(app, force = true) }
        inBackground { app -> Locator.refresh(app) }
        if (prefs.consented && prefs.lastCheck == 0L) Scheduler.runNow(this)
    }

    override fun onResume() {
        super.onResume()
        cacheAt = 0L
        if (prefs.consented && !prefs.paused) LinkService.start(this)
        handler.post(refresh)
        if (prefs.consented && Locator.granted(this) && System.currentTimeMillis() - prefs.locTs > 6 * 3600_000L) {
            inBackground { app -> Locator.refresh(app) }
        }
        if (prefs.consented && !Locator.granted(this) && !prefs.locationAsked) {
            prefs.locationAsked = true
            requestPermissions(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION), REQUEST_LOCATION)
        }
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refresh)
    }

    private fun inBackground(task: (Context) -> Unit) {
        val app = applicationContext
        val screen = WeakReference(this)
        Thread {
            task(app)
            screen.get()?.let { activity -> activity.runOnUiThread { if (!activity.isDestroyed) activity.render() } }
        }.start()
    }

    private fun batteryUnrestricted(): Boolean = try {
        getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)
    } catch (_: Exception) {
        true
    }

    private fun openBatterySettings() {
        val packageUri = Uri.parse("package:$packageName")
        try {
            @SuppressLint("BatteryLife")
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, packageUri)
            startActivity(intent)
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri))
            } catch (ignored: Exception) {
            }
        }
    }

    private fun render() {
        val consented = prefs.consented
        findViewById<View>(R.id.consentBox).visibility = if (consented) View.GONE else View.VISIBLE
        findViewById<View>(R.id.statusBox).visibility = if (consented) View.VISIBLE else View.GONE
        if (!consented) return

        val now = System.currentTimeMillis()
        if (netCache == null || now - cacheAt !in 0 until CACHE_MS) {
            netCache = NetInfo.describe(this)
            batteryCache = batteryUnrestricted()
            cacheAt = now
        }
        val net = netCache ?: JSONObject()
        if (prefs.pendingApk.isNotEmpty() && (prefs.pendingApkCode <= BuildConfig.VERSION_CODE || !File(prefs.pendingApk).exists())) {
            File(prefs.pendingApk).delete()
            prefs.pendingApk = ""
        }
        findViewById<TextView>(R.id.network).text = networkLine(net)
        findViewById<TextView>(R.id.version).text = versionLine()

        val status = findViewById<TextView>(R.id.status)
        status.text = when {
            prefs.paused -> getString(R.string.status_paused)
            prefs.running -> getString(R.string.status_running)
            else -> getString(R.string.status_idle_last, CheckWorker.formatTime(prefs.lastCheck))
        }
        val summary = prefs.lastSummary
        val waiting = !prefs.running && net.text("type") == "none" && summary == getString(R.string.summary_running)
        findViewById<TextView>(R.id.lastResult).text = when {
            !Api.paired() -> getString(R.string.summary_not_paired)
            waiting -> getString(R.string.summary_wait_network)
            else -> summary
        }
        findViewById<TextView>(R.id.details).text = listOf(prefs.lastDetails, prefs.serverMessage)
            .filter { it.isNotEmpty() }.joinToString("\n\n")
        renderButtons()
    }

    private fun networkLine(net: JSONObject): String {
        val typeName = NetInfo.label(this, net.text("type"))
        val operator = if (net.text("type") == "cellular") net.text("operator") else ""
        val place = prefs.locShown.ifEmpty { Locator.joinPlace(prefs.locCity to prefs.locRegion) }
        val where = when {
            place.isNotEmpty() -> getString(R.string.where_phone, place)
            prefs.lastRegion.isNotEmpty() && Locator.granted(this) && !Locator.enabled(this) ->
                getString(R.string.where_ip_geo_off, prefs.lastRegion)
            prefs.lastRegion.isNotEmpty() -> getString(R.string.where_ip, prefs.lastRegion)
            else -> ""
        }
        return listOf(typeName, operator).filter { it.isNotEmpty() }.joinToString(" · ") +
            (if (where.isNotEmpty()) "\n" + where else "")
    }

    private fun renderButtons() {
        val locate = findViewById<Button>(R.id.locateButton)
        locate.visibility = if (prefs.locateRequested || Locator.grantedFine(this)) View.VISIBLE else View.GONE
        locate.text = getString(if (prefs.locateRequested) R.string.locate_requested else R.string.locate)
        val restricted = !batteryCache
        findViewById<View>(R.id.batteryHint).visibility = if (restricted) View.VISIBLE else View.GONE
        findViewById<View>(R.id.batteryButton).visibility = if (restricted) View.VISIBLE else View.GONE
        val install = findViewById<Button>(R.id.installButton)
        val pending = prefs.pendingApk
        install.visibility = if (pending.isNotEmpty() && File(pending).exists()) View.VISIBLE else View.GONE
        install.text = getString(R.string.install_update, prefs.pendingApkVersion)
        val check = findViewById<Button>(R.id.checkButton)
        check.isEnabled = !prefs.running && !prefs.paused && Api.paired()
        findViewById<Button>(R.id.stopButton).text = getString(if (prefs.paused) R.string.resume else R.string.stop)
    }

    private companion object {
        const val REQUEST_CONSENT = 1
        const val REQUEST_LOCATION = 2
        const val REQUEST_PRECISE = 3
        const val CACHE_MS = 15_000L
    }
}
