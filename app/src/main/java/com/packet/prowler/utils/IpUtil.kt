package com.packet.prowler.utils

import java.net.InetSocketAddress


object IpUtil {
    fun buildUdpPacket(source: InetSocketAddress, dest: InetSocketAddress, ipId: Int): Packet {
        val packet: Packet = Packet()
        packet.isTCP = false
        packet.isUDP = true
        val ip4Header: Packet.IP4Header = Packet.IP4Header()
        ip4Header.version = 4
        ip4Header.IHL = 5
        ip4Header.destinationAddress = dest.address
        ip4Header.headerChecksum = 0
        ip4Header.headerLength = 20

        //int ipId=0;
        val ipFlag = 0x40
        val ipOff = 0

        ip4Header.identificationAndFlagsAndFragmentOffset = ipId shl 16 or (ipFlag shl 8) or ipOff

        ip4Header.optionsAndPadding = 0
        ip4Header.protocol = Packet.IP4Header.TransportProtocol.UDP
        ip4Header.protocolNum = 17
        ip4Header.sourceAddress = source.address
        ip4Header.totalLength = 60
        ip4Header.typeOfService = 0
        ip4Header.TTL = 64

        val udpHeader: Packet.UDPHeader = Packet.UDPHeader()
        udpHeader.sourcePort = source.port
        udpHeader.destinationPort = dest.port
        udpHeader.length = 0


        packet.ip4Header = ip4Header
        packet.udpHeader = udpHeader
        return packet
    }

    fun buildTcpPacket(
        source: InetSocketAddress,
        dest: InetSocketAddress,
        flag: Byte,
        ack: Long,
        seq: Long,
        ipId: Int
    ): Packet {
        val packet: Packet = Packet()
        packet.isTCP = true
        packet.isUDP = false
        val ip4Header: Packet.IP4Header = Packet.IP4Header()
        ip4Header.version = 4
        ip4Header.IHL = 5
        ip4Header.destinationAddress = dest.address
        ip4Header.headerChecksum = 0
        ip4Header.headerLength = 20

        //int ipId=0;
        val ipFlag = 0x40
        val ipOff = 0

        ip4Header.identificationAndFlagsAndFragmentOffset = ipId shl 16 or (ipFlag shl 8) or ipOff

        ip4Header.optionsAndPadding = 0
        ip4Header.protocol = Packet.IP4Header.TransportProtocol.TCP
        ip4Header.protocolNum = 6
        ip4Header.sourceAddress = source.address
        ip4Header.totalLength = 60
        ip4Header.typeOfService = 0
        ip4Header.TTL = 64

        val tcpHeader: Packet.TCPHeader = Packet.TCPHeader()
        tcpHeader.acknowledgementNumber = ack
        tcpHeader.checksum = 0
        tcpHeader.dataOffsetAndReserved = -96
        tcpHeader.destinationPort = dest.port
        tcpHeader.flags = flag
        tcpHeader.headerLength = 40
        tcpHeader.optionsAndPadding = null
        tcpHeader.sequenceNumber = seq
        tcpHeader.sourcePort = source.port
        tcpHeader.urgentPointer = 0
        tcpHeader.window = 65535


        packet.ip4Header = ip4Header
        packet.tcpHeader = tcpHeader
        return packet
    }
}