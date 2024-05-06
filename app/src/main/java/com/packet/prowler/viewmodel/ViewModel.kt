package com.packet.prowler.viewmodel

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.setValue
import com.packet.prowler.utils.Packet
import com.packet.prowler.utils.packetGroup
import com.packet.prowler.worker.ManagedDatagramChannel
import com.packet.prowler.worker.UdpTunnel
import java.nio.channels.Selector
import java.util.concurrent.ArrayBlockingQueue


enum class Screens(){
    Home,
    ListPage,
    DataPage
}


var totalSize by mutableLongStateOf(0L)

val allPackets  = ArrayBlockingQueue<Packet>(1024)

val categorizedPackets = ArrayList<packetGroup>()

val tcpNioSelector: Selector = Selector.open()


val udpTunnelQueue = ArrayBlockingQueue<UdpTunnel>(1024)
val udpNioSelector: Selector = Selector.open()
val udpSocketMap = HashMap<String, ManagedDatagramChannel>()