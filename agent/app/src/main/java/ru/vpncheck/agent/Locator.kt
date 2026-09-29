package ru.vpncheck.agent

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.Geocoder
import android.location.Location
import android.location.LocationManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority
import com.google.android.gms.tasks.CancellationTokenSource
import com.google.android.gms.tasks.Tasks
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.roundToInt

object Locator {
    fun grantedFine(context: Context) =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun precise(context: Context): Location? {
        if (!grantedFine(context) || !enabled(context)) return null
        return try {
            fusedCurrent(context, Priority.PRIORITY_HIGH_ACCURACY, 60)
        } catch (_: Exception) {
            null
        }
    }

    fun placeOf(context: Context, lat: Double, lon: Double, locale: Locale = Locale("ru")): Pair<String, String> = try {
        @Suppress("DEPRECATION")
        val p = Geocoder(context, locale).getFromLocation(lat, lon, 1)?.firstOrNull()
        Pair((p?.locality ?: p?.subAdminArea).orEmpty(), p?.adminArea.orEmpty())
    } catch (_: Exception) {
        Pair("", "")
    }

    fun shownPlace(context: Context, lat: Double, lon: Double, serverPlace: Pair<String, String>): Pair<String, String> {
        val locale = Locale.getDefault()
        if (locale.language == "ru") return serverPlace
        val local = placeOf(context, lat, lon, locale)
        return if (local.first.isNotEmpty() || local.second.isNotEmpty()) local else serverPlace
    }

    fun joinPlace(place: Pair<String, String>): String =
        listOf(place.first, place.second).filter { it.isNotEmpty() }.joinToString(", ")

    fun granted(context: Context) =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun enabled(context: Context): Boolean = try {
        val manager = context.getSystemService(LocationManager::class.java)
        if (Build.VERSION.SDK_INT >= 28) manager.isLocationEnabled
        else manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER) || manager.isProviderEnabled(LocationManager.GPS_PROVIDER)
    } catch (_: Exception) {
        false
    }

    fun refresh(context: Context) {
        if (!granted(context) || !enabled(context)) return
        val prefs = Prefs(context)
        val location = fused(context) ?: lastKnown(context) ?: current(context) ?: return
        val round = prefs.locRound.toDouble().coerceIn(1.0, 5000.0)
        val lat = (location.latitude * round).roundToInt() / round
        val lon = (location.longitude * round).roundToInt() / round
        prefs.locLat = lat.toFloat()
        prefs.locLon = lon.toFloat()
        prefs.locTs = System.currentTimeMillis()
        prefs.locAccuracy = if (location.hasAccuracy()) location.accuracy else 0f
        val place = placeOf(context, lat, lon)
        val (city, region) = place
        if (city.isNotEmpty() || region.isNotEmpty()) {
            prefs.locCity = city
            prefs.locRegion = region
            prefs.locShown = joinPlace(shownPlace(context, lat, lon, place))
        }
    }

    @SuppressLint("MissingPermission")
    private fun fused(context: Context): Location? {
        return try {
            fusedCurrent(context, Priority.PRIORITY_BALANCED_POWER_ACCURACY, 25)
                ?: Tasks.await(LocationServices.getFusedLocationProviderClient(context).lastLocation, 5, TimeUnit.SECONDS)
        } catch (_: SecurityException) {
            null
        } catch (_: Exception) {
            null
        }
    }

    @SuppressLint("MissingPermission")
    private fun fusedCurrent(context: Context, priority: Int, timeoutSec: Long): Location? {
        val client = LocationServices.getFusedLocationProviderClient(context)
        val task = client.getCurrentLocation(priority, CancellationTokenSource().token)
        return Tasks.await(task, timeoutSec, TimeUnit.SECONDS)
    }

    @SuppressLint("MissingPermission")
    private fun current(context: Context): Location? {
        if (Build.VERSION.SDK_INT < 30) return null
        val manager = context.getSystemService(LocationManager::class.java)
        val provider = when {
            Build.VERSION.SDK_INT >= 31 && manager.isProviderEnabled(LocationManager.FUSED_PROVIDER) -> LocationManager.FUSED_PROVIDER
            manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER) -> LocationManager.NETWORK_PROVIDER
            else -> return null
        }
        val latch = CountDownLatch(1)
        var result: Location? = null
        try {
            manager.getCurrentLocation(provider, null, context.mainExecutor) { location ->
                result = location
                latch.countDown()
            }
            latch.await(20, TimeUnit.SECONDS)
        } catch (_: SecurityException) {
            return null
        } catch (_: Exception) {
            return null
        }
        return result
    }

    private fun lastKnown(context: Context): Location? {
        val manager = context.getSystemService(LocationManager::class.java)
        val providers = mutableListOf(LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)
        if (Build.VERSION.SDK_INT >= 31) providers.add(0, LocationManager.FUSED_PROVIDER)
        var best: Location? = null
        for (provider in providers) {
            val location = try {
                manager.getLastKnownLocation(provider)
            } catch (_: SecurityException) {
                null
            } catch (_: Exception) {
                null
            } ?: continue
            if (best == null || location.time > best.time) best = location
        }
        return best
    }
}
