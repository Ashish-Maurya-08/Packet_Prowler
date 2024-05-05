package com.packet.prowler.services

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.packet.prowler.worker.ToDeviceQueueWorker
import com.packet.prowler.worker.ToNetworkQueueWorker
import com.packet.prowler.worker.TcpWorker
import com.packet.prowler.worker.UdpReceiveWorker
import com.packet.prowler.worker.UdpSendWorker
import com.packet.prowler.worker.UdpSocketCleanWorker
import com.packet.prowler.worker.categorize

var isRunning by mutableStateOf(false)
var cManager : ConnectivityManager? = null
var pkgManager : PackageManager? = null

class ProwlerService : VpnService() {

    private lateinit var vpnInterface: ParcelFileDescriptor

    @RequiresApi(Build.VERSION_CODES.Q)
    override fun onCreate() {
        UdpSendWorker.start(this)
        UdpReceiveWorker.start(this)
        UdpSocketCleanWorker.start()
        TcpWorker.start(this)
        categorize.start()

        cManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        pkgManager = packageManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d("vpn", "onStartCommand")
        if (intent != null) {
            if (intent.action == ACTION_STOP_VPN && isRunning) {
                Log.d("vpn", "Stopping VPN")
                stopVpn()
                return START_NOT_STICKY
            }
        }
        startVpn()
        return START_STICKY_COMPATIBILITY
    }



    override fun onDestroy() {
        UdpSendWorker.stop()
        UdpReceiveWorker.stop()
        UdpSocketCleanWorker.stop()
        TcpWorker.stop()
        categorize.stop()
        stopVpn()

        super.onDestroy()
    }


    private fun startVpn() {

        vpnInterface = configureVpn()
        val fileDescriptor = vpnInterface.fileDescriptor
        ToNetworkQueueWorker.start(fileDescriptor)
        ToDeviceQueueWorker.start(fileDescriptor)
        isRunning = true

        Log.d("vpn", "Thread started ")

    }

    private fun configureVpn(): ParcelFileDescriptor {
        val builder = Builder()
        builder.setSession("vpn")
        builder.addAddress(IP_ADDRESS, 24)
        builder.addRoute("0.0.0.0", 0)
        builder.setMtu(1500)

        return builder.establish() ?: throw IllegalStateException("Cannot establish VPN")
    }

    private fun stopVpn() {
        ToNetworkQueueWorker.stop()
        ToDeviceQueueWorker.stop()
        vpnInterface.close()
        isRunning = false

        System.gc()
    }

    override fun onRevoke() {
        isRunning = false
        stopVpn()
        super.onRevoke()
    }

    companion object {
        const val ACTION_STOP_VPN = "ACTION_STOP_VPN"
        const val IP_ADDRESS = "10.0.0.8"
    }

}
