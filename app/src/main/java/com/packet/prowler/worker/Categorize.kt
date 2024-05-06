package com.packet.prowler.worker

import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import com.packet.prowler.utils.Packet
import com.packet.prowler.utils.packetGroup
import com.packet.prowler.worker.categorize.TAG
import java.lang.Thread.sleep
import java.util.concurrent.ArrayBlockingQueue

val allPackets  = ArrayBlockingQueue<Packet>(1024)
val categorizedPackets = ArrayList<packetGroup>()

object categorize : Runnable {

    private const val TAG = "categorize"
    private lateinit var thread: Thread

    fun start() {
        if (this::thread.isInitialized && thread.isAlive) throw IllegalStateException("")
        thread = Thread(this).apply {
            name = TAG
            start()
        }
    }

    fun stop() {
        if (this::thread.isInitialized) {
            thread.interrupt()
        }
    }

    override fun run() {
        while (!thread.isInterrupted) {
            val packet = allPackets.take() ?: continue

            if (packet.uid == null || packet.uid!! < 0) { continue }

            val group = categorizedPackets.find { it.uid == packet.uid }
            if (group == null) {
                createNewGroup(packet)
                continue
            }
            else {
                var foundFlag = false
                for (newPacket in categorizedPackets){
                    if (newPacket.uid != packet.uid){
                        continue
                    }

                    if (packet.isSent) {
                        val remoteIP = packet.ip4Header?.destinationAddress
                        val remotePort =
                            packet.tcpHeader?.destinationPort ?: packet.udpHeader?.destinationPort

                        if (newPacket.remoteIP == packet.ip4Header?.destinationAddress && newPacket.remotePort == (packet.tcpHeader?.destinationPort
                                ?: packet.udpHeader?.destinationPort)
                        ) {
                            newPacket.sent.add(packet)
                            foundFlag = true
                            break
                        } else {
                            Log.d(
                                "vpn", "${newPacket.remoteIP} $remoteIP ${newPacket.remotePort} $remotePort"
                            )
                            continue
                        }
                    } else {

                        val remoteIP = packet.ip4Header?.sourceAddress
                        val remotePort =
                            packet.tcpHeader?.sourcePort ?: packet.udpHeader?.sourcePort

                        if (newPacket.remoteIP == packet.ip4Header?.sourceAddress && newPacket.remotePort == (packet.tcpHeader?.sourcePort
                                ?: packet.udpHeader?.sourcePort)
                        ) {
                            newPacket.received.add(packet)
                            foundFlag = true
                            break
                        } else {
                            Log.d(
                                "vpn", "${newPacket.remoteIP} $remoteIP ${newPacket.remotePort} $remotePort"
                            )
                            continue
                        }
                    }
                }
                if (!foundFlag){
                    createNewGroup(packet)
                    continue
                }

            }
        }
    }
}

private fun createNewGroup(packet: Packet){

    if (packet.uid!! < 0){
        return
    }

    val remoteIP = if (packet.isSent){
        packet.ip4Header?.destinationAddress!!
    } else {
        packet.ip4Header?.sourceAddress!!
    }
    val remotePort = if (packet.isSent){
        if (packet.isTCP){
            packet.tcpHeader?.destinationPort!!
        } else {
            packet.udpHeader?.destinationPort!!
        }
    } else {
        if (packet.isTCP){
            packet.tcpHeader?.sourcePort!!
        } else {
            packet.udpHeader?.sourcePort!!
        }
    }
    val newGroup = packetGroup(
        packet.uid,
        remoteIP,
        remotePort,
        ArrayList(),
        ArrayList()
    )
    if (packet.isSent){
        newGroup.sent.add(packet)
    } else {
        newGroup.received.add(packet)
    }
    categorizedPackets.add(newGroup)
    Log.d("vpn", "${categorizedPackets.size}")
}