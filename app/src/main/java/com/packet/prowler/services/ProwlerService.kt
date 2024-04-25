package com.packet.prowler.services

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.packet.prowler.utils.ToDeviceQueueWorker
import com.packet.prowler.utils.ToNetworkQueueWorker
import com.packet.prowler.worker.TcpWorker
import com.packet.prowler.worker.UdpReceiveWorker
import com.packet.prowler.worker.UdpSendWorker
import com.packet.prowler.worker.UdpSocketCleanWorker
import kotlinx.coroutines.Job

var isRunning by mutableStateOf(false)

class ProwlerService : VpnService() {

    private lateinit var vpnInterface: ParcelFileDescriptor




    override fun onCreate() {
        UdpSendWorker.start(this)
        UdpReceiveWorker.start(this)
        UdpSocketCleanWorker.start()
        TcpWorker.start(this)
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
        builder.addAddress("10.0.0.2", 24)
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
    }




}
