package ru.vpncheck.agent

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class NetGather private constructor(
    private val cm: ConnectivityManager,
    private val callbacks: List<ConnectivityManager.NetworkCallback>,
    val networks: List<Network>,
    private val lost: MutableSet<Network>
) {
    fun isLost(net: Network): Boolean = synchronized(lost) { net in lost }

    fun release() {
        for (cb in callbacks) try { cm.unregisterNetworkCallback(cb) } catch (ignored: Exception) {}
    }

    companion object {
        fun request(context: Context, timeoutMs: Long): NetGather {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val transports = listOf(NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR)
                .filter { it != NetworkCapabilities.TRANSPORT_WIFI || wifiPossible(context, cm) }
            val found = mutableListOf<Pair<Int, Network>>()
            val lost = mutableSetOf<Network>()
            val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
            val latch = CountDownLatch(transports.size)
            for (transport in transports) {
                val request = NetworkRequest.Builder()
                    .addTransportType(transport)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
                val callback = object : ConnectivityManager.NetworkCallback() {
                    private var counted = false

                    @Synchronized
                    private fun countOnce() {
                        if (!counted) {
                            counted = true
                            latch.countDown()
                        }
                    }

                    override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                        synchronized(lost) { lost.remove(network) }
                        synchronized(found) { if (found.none { it.second == network }) found.add(transport to network) }
                        if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) countOnce()
                    }

                    override fun onLost(network: Network) {
                        synchronized(lost) { lost.add(network) }
                    }

                    override fun onUnavailable() = countOnce()
                }
                try {
                    cm.requestNetwork(request, callback, timeoutMs.toInt())
                    callbacks.add(callback)
                } catch (_: Exception) {
                    latch.countDown()
                }
            }
            try { latch.await(timeoutMs + 2000, TimeUnit.MILLISECONDS) } catch (ignored: InterruptedException) {}
            val ordered = synchronized(found) {
                found.sortedByDescending { it.first == NetworkCapabilities.TRANSPORT_WIFI }.map { it.second }
            }.filterNot { net -> synchronized(lost) { net in lost } }
            return NetGather(cm, callbacks, ordered, lost)
        }

        private fun wifiPossible(context: Context, cm: ConnectivityManager): Boolean {
            val present = try {
                cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
            } catch (_: Exception) { false }
            if (present) return true
            return try {
                context.applicationContext.getSystemService(WifiManager::class.java)?.isWifiEnabled != false
            } catch (_: Exception) { true }
        }
    }
}
