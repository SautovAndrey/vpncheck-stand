package ru.vpncheck.agent

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

class Updater(private val context: Context) {

    fun fetchAndApply() {
        val config = Api.config(context)
        apply(config.optJSONObject("manifest"), background = false)?.let(Prefs(context)::addDetailLine)
    }

    fun learnTls(manifest: JSONObject?) {
        synchronized(LOCK) { adoptTls(Prefs(context), manifest) }
    }

    fun recoverTls(): Boolean {
        val manifest = try {
            Api.manifestOverHttp()
        } catch (_: Exception) {
            null
        } ?: return false
        val prefs = Prefs(context)
        val change = synchronized(LOCK) { adoptTls(prefs, manifest) } ?: return false
        prefs.addDetailLine(context.getString(if (change.tls == null) R.string.tls_disabled else R.string.tls_recovered))
        return true
    }

    fun apply(manifest: JSONObject?, background: Boolean = true): String? {
        if (manifest == null) return null
        if (!Verify.manifestSigned(manifest)) return context.getString(R.string.upd_unsigned)
        val app = synchronized(LOCK) {
            val prefs = Prefs(context)
            val issued = manifest.optLong("issued", 0)
            if (issued < prefs.lastManifestIssued) return context.getString(R.string.upd_stale)
            prefs.lastManifestIssued = issued
            adoptTls(prefs, manifest)
            manifest.optJSONObject("app")
        } ?: return null
        return updateApp(app, background)
    }

    private fun adoptTls(prefs: Prefs, manifest: JSONObject?): PinnedTls.Change? {
        val change = PinnedTls.fromManifest(prefs.serverUrl, prefs.tlsIssued, prefs.lastManifestIssued, manifest)
            ?: return null
        prefs.tlsIssued = change.issued
        val current = prefs.tls
        if (current?.port == change.tls?.port && current?.pin == change.tls?.pin) return null
        prefs.tls = change.tls
        Api.useTls(change.tls)
        return change
    }

    private fun updateApp(app: JSONObject, background: Boolean): String? {
        val code = app.optInt("version_code", 0)
        val name = app.optString("version_name", "")
        val url = app.optString("url")
        val sha = app.optString("sha256").lowercase()
        if (code <= BuildConfig.VERSION_CODE || url.isEmpty() || sha.isEmpty()) return null
        val prefs = Prefs(context)
        if (prefs.rejectedApk == "$code|$sha") return null
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        val apk = File(dir, "agent-$code.apk")
        val fresh = !apk.exists() || cachedSha(apk) != sha
        if (fresh) {
            if (background) {
                Scheduler.fetchUpdate(context)
                return context.getString(R.string.upd_wait_wifi, name)
            }
            download(url, apk, sha, name)?.let { return it }
        }
        if (fresh || prefs.pendingApk != apk.absolutePath || prefs.pendingApkCode != code) {
            apkProblem(apk, code)?.let { problem ->
                apk.delete()
                prefs.rejectedApk = "$code|$sha"
                val line = context.getString(R.string.upd_app_rejected, name, problem)
                ErrorLog.record(context, "update", null, text = line)
                return line
            }
        }
        synchronized(LOCK) {
            prefs.pendingApk = apk.absolutePath
            prefs.pendingApkVersion = name
            prefs.pendingApkCode = code
        }
        Notifications.show(
            context, Notifications.UPDATE, android.R.drawable.stat_sys_download_done,
            context.getString(R.string.upd_notif_title, name), context.getString(R.string.upd_notif_text),
            PendingIntent.getActivity(
                context, Notifications.UPDATE, installIntent(apk),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        return context.getString(R.string.upd_app_available, name)
    }

    private fun download(url: String, apk: File, sha: String, name: String): String? {
        if (!DOWNLOADING.compareAndSet(false, true)) return context.getString(R.string.upd_downloading, name)
        val part = File(apk.parentFile, apk.name + ".part")
        try {
            Api.download(url, part)
            if (Verify.sha256(part) != sha) return context.getString(R.string.upd_app_checksum, name)
            if (!part.renameTo(apk)) return context.getString(R.string.upd_app_error, name, "rename")
            return null
        } catch (e: Exception) {
            return context.getString(R.string.upd_app_error, name, e.message ?: e.javaClass.simpleName)
        } finally {
            part.delete()
            DOWNLOADING.set(false)
        }
    }

    private fun apkProblem(apk: File, code: Int): String? {
        val manager = context.packageManager
        val archive = packageInfo { archiveInfo(manager, apk) } ?: return context.getString(R.string.upd_bad_apk)
        if (archive.packageName != context.packageName) return context.getString(R.string.upd_bad_package, archive.packageName)
        val archiveCode = PackageInfoCompat.getLongVersionCode(archive)
        if (archiveCode != code.toLong() || archiveCode <= BuildConfig.VERSION_CODE) {
            return context.getString(R.string.upd_bad_version, archiveCode, code)
        }
        val installed = packageInfo { installedInfo(manager) }?.let(::signers).orEmpty()
        val incoming = signers(archive)
        if (installed.isEmpty() || !incoming.containsAll(installed)) return context.getString(R.string.upd_bad_signature)
        return null
    }

    private fun packageInfo(block: () -> PackageInfo?): PackageInfo? = try {
        block()
    } catch (_: Exception) {
        null
    }

    @Suppress("DEPRECATION")
    private fun archiveInfo(manager: PackageManager, apk: File): PackageInfo? =
        if (Build.VERSION.SDK_INT >= 28) manager.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
        else manager.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNATURES)

    @Suppress("DEPRECATION")
    private fun installedInfo(manager: PackageManager): PackageInfo =
        if (Build.VERSION.SDK_INT >= 28) manager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        else manager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)

    @Suppress("DEPRECATION")
    private fun signers(info: PackageInfo): Set<String> {
        val list = if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo?.let { if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory }
        } else {
            info.signatures
        }
        return list.orEmpty().filterNotNull().map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
    }

    private fun cachedSha(apk: File): String {
        val prefs = Prefs(context)
        val stamp = "${apk.absolutePath}|${apk.length()}|${apk.lastModified()}"
        val cached = prefs.apkShaCache
        if (cached.substringBeforeLast('|') == stamp) return cached.substringAfterLast('|')
        val sha = Verify.sha256(apk)
        prefs.apkShaCache = "$stamp|$sha"
        return sha
    }

    fun installIntent(apk: File): Intent {
        val uri = FileProvider.getUriForFile(context, "${BuildConfig.APPLICATION_ID}.files", apk)
        return Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    private companion object {
        val LOCK = Any()
        val DOWNLOADING = AtomicBoolean(false)
    }
}
