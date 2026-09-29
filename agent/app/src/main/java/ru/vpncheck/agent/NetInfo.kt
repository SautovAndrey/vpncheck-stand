package ru.vpncheck.agent

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.TelephonyNetworkSpecifier
import android.os.Build
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import org.json.JSONObject
import java.net.Inet4Address
import java.net.NetworkInterface

object NetInfo {
    fun usableNetworkCount(context: Context): Int {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val physical = listOf(
            NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR, NetworkCapabilities.TRANSPORT_ETHERNET
        )
        return cm.allNetworks.count { net ->
            val caps = cm.getNetworkCapabilities(net) ?: return@count false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                physical.any { caps.hasTransport(it) }
        }
    }

    fun activeIsWifi(context: Context): Boolean = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
    } catch (_: Exception) { false }

    fun vpnActive(context: Context): Boolean = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    } catch (_: Exception) { false }

    fun source(context: Context, net: Network): XrayRunner.Via? {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val lp = cm.getLinkProperties(net) ?: return null
        val device = lp.interfaceName
        val own = lp.linkAddresses.map { it.address to device }
        val clat = try {
            device?.let { NetworkInterface.getByName("v4-$it") }?.let { stacked ->
                stacked.inetAddresses.toList().map { it to stacked.name }
            }.orEmpty()
        } catch (_: Exception) { emptyList() }
        val (address, name) = (own + clat).firstOrNull { (it, _) ->
            it is Inet4Address && !it.isLoopbackAddress && !it.isLinkLocalAddress
        } ?: return null
        return address.hostAddress?.let { XrayRunner.Via(it, name) }
    }

    fun label(context: Context, type: String): String = when (type) {
        "wifi" -> "Wi-Fi"
        "cellular" -> context.getString(R.string.net_mobile)
        "ethernet" -> "Ethernet"
        "none" -> context.getString(R.string.net_none)
        else -> type
    }

    fun describe(context: Context, net: Network? = null): JSONObject {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val target = net ?: cm.activeNetwork
        val caps = target?.let { cm.getNetworkCapabilities(it) }
        val tm = telephonyFor(context, caps)
        val type = when {
            caps == null -> "none"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
        val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val operator = try { tm.networkOperatorName.orEmpty() } catch (_: Exception) { "" }
        val simOperator = try { tm.simOperatorName.orEmpty() } catch (_: Exception) { "" }
        val mccMnc = try { tm.networkOperator.orEmpty() } catch (_: Exception) { "" }
        return JSONObject().apply {
            put("type", type)
            put("vpn", vpn)
            put("operator", if (type == "cellular") operator.ifEmpty { simOperator } else operator)
            put("sim_operator", simOperator)
            put("mcc_mnc", mccMnc)
            put("radio", "")
        }
    }

    private fun telephonyFor(context: Context, caps: NetworkCapabilities?): TelephonyManager {
        val tm = context.getSystemService(TelephonyManager::class.java)
        val fromNetwork = if (Build.VERSION.SDK_INT >= 30) {
            (caps?.networkSpecifier as? TelephonyNetworkSpecifier)?.subscriptionId
        } else {
            null
        }
        val subId = fromNetwork?.takeIf { it != SubscriptionManager.INVALID_SUBSCRIPTION_ID }
            ?: SubscriptionManager.getDefaultDataSubscriptionId()
        if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) return tm
        return try { tm.createForSubscriptionId(subId) } catch (_: Exception) { tm }
    }
}
