package com.packet.prowler.utils

import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong


/**
 * Representation of an IP Packet
 */
// TODO: Reduce public mutability
class Packet() {
    var ip4Header: IP4Header? = null
    var tcpHeader: TCPHeader? = null
    var udpHeader: UDPHeader? = null
    var backingBuffer: ByteBuffer? = null

    var isTCP: Boolean = false
    var isUDP: Boolean = false

    init {
        globalPackId.addAndGet(1)
    }

    constructor(buffer: ByteBuffer) : this() {
        this.ip4Header = IP4Header(buffer)
        if (ip4Header!!.protocol == IP4Header.TransportProtocol.TCP) {
            this.tcpHeader = TCPHeader(buffer)
            this.isTCP = true
        } else if (ip4Header!!.protocol == IP4Header.TransportProtocol.UDP) {
            this.udpHeader = UDPHeader(buffer)
            this.isUDP = true
        }
        this.backingBuffer = buffer
    }

    fun release() {
        ip4Header = null
        tcpHeader = null
        udpHeader = null
        backingBuffer = null
    }

    override fun toString(): String {
        val sb = StringBuilder("Packet{")
        sb.append("ip4Header=").append(ip4Header)
        if (isTCP) sb.append(", tcpHeader=").append(tcpHeader)
        else if (isUDP) sb.append(", udpHeader=").append(udpHeader)
        sb.append(", payloadSize=").append(backingBuffer!!.limit() - backingBuffer!!.position())
        sb.append('}')
        return sb.toString()
    }


    fun updateTCPBuffer(
        buffer: ByteBuffer,
        flags: Byte,
        sequenceNum: Long,
        ackNum: Long,
        payloadSize: Int
    ) {
        buffer.position(0)
        fillHeader(buffer)
        backingBuffer = buffer

        tcpHeader!!.flags = flags
        backingBuffer!!.put(IP4_HEADER_SIZE + 13, flags)

        tcpHeader!!.sequenceNumber = sequenceNum
        backingBuffer!!.putInt(IP4_HEADER_SIZE + 4, sequenceNum.toInt())

        tcpHeader!!.acknowledgementNumber = ackNum
        backingBuffer!!.putInt(IP4_HEADER_SIZE + 8, ackNum.toInt())

        // Reset header size, since we don't need options
        val dataOffset = (TCP_HEADER_SIZE shl 2).toByte()
        tcpHeader!!.dataOffsetAndReserved = dataOffset
        backingBuffer!!.put(IP4_HEADER_SIZE + 12, dataOffset)

        updateTCPChecksum(payloadSize)

        val ip4TotalLength = IP4_HEADER_SIZE + TCP_HEADER_SIZE + payloadSize
        backingBuffer!!.putShort(2, ip4TotalLength.toShort())
        ip4Header!!.totalLength = ip4TotalLength

        updateIP4Checksum()
    }

    fun updateUDPBuffer(buffer: ByteBuffer, payloadSize: Int) {
        buffer.position(0)
        fillHeader(buffer)
        backingBuffer = buffer

        val udpTotalLength = UDP_HEADER_SIZE + payloadSize
        backingBuffer!!.putShort(IP4_HEADER_SIZE + 4, udpTotalLength.toShort())
        udpHeader!!.length = udpTotalLength

        // Disable UDP checksum validation
        backingBuffer!!.putShort(IP4_HEADER_SIZE + 6, 0.toShort())
        udpHeader!!.checksum = 0

        val ip4TotalLength = IP4_HEADER_SIZE + udpTotalLength
        backingBuffer!!.putShort(2, ip4TotalLength.toShort())
        ip4Header!!.totalLength = ip4TotalLength

        updateIP4Checksum()
    }

    private fun updateIP4Checksum() {
        val buffer = backingBuffer!!.duplicate()
        buffer.position(0)

        // Clear previous checksum
        buffer.putShort(10, 0.toShort())

        var ipLength = ip4Header!!.headerLength
        var sum = 0
        while (ipLength > 0) {
            sum += BitUtils.getUnsignedShort(buffer.getShort())
            ipLength -= 2
        }
        while (sum shr 16 > 0) sum = (sum and 0xFFFF) + (sum shr 16)

        sum = sum.inv()
        ip4Header!!.headerChecksum = sum
        backingBuffer!!.putShort(10, sum.toShort())
    }

    private fun updateTCPChecksum(payloadSize: Int) {
        var sum = 0
        var tcpLength = TCP_HEADER_SIZE + payloadSize

        // Calculate pseudo-header checksum
        var buffer = ByteBuffer.wrap(ip4Header!!.sourceAddress!!.address)
        sum =
            BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort())

        buffer = ByteBuffer.wrap(ip4Header!!.destinationAddress!!.address)
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort())

        sum += IP4Header.TransportProtocol.TCP.number + tcpLength

        buffer = backingBuffer!!.duplicate()
        // Clear previous checksum
        buffer.putShort(IP4_HEADER_SIZE + 16, 0.toShort())

        // Calculate TCP segment checksum
        buffer.position(IP4_HEADER_SIZE)
        while (tcpLength > 1) {
            sum += BitUtils.getUnsignedShort(buffer.getShort())
            tcpLength -= 2
        }
        if (tcpLength > 0) sum += BitUtils.getUnsignedByte(buffer.get()).toInt() shl 8

        while (sum shr 16 > 0) sum = (sum and 0xFFFF) + (sum shr 16)

        sum = sum.inv()
        tcpHeader!!.checksum = sum
        backingBuffer!!.putShort(IP4_HEADER_SIZE + 16, sum.toShort())
    }

    private fun fillHeader(buffer: ByteBuffer) {
        ip4Header!!.fillHeader(buffer)
        if (isUDP) udpHeader!!.fillHeader(buffer)
        else if (isTCP) tcpHeader!!.fillHeader(buffer)
    }

    class IP4Header {
        var version: Byte = 0
        var IHL: Byte = 0
        var headerLength: Int = 0
        var typeOfService: Short = 0
        var totalLength: Int = 0

        var identificationAndFlagsAndFragmentOffset: Int = 0

        var TTL: Short = 0
        var protocolNum: Short = 0
        var protocol: TransportProtocol? = null
        var headerChecksum: Int = 0

        var sourceAddress: InetAddress? = null
        var destinationAddress: InetAddress? = null

        var optionsAndPadding: Int = 0

        enum class TransportProtocol(val number: Int) {
            TCP(6),
            UDP(17),
            Other(0xFF);

            companion object {
                fun numberToEnum(protocolNumber: Int): TransportProtocol {
                    return if (protocolNumber == 6) TCP
                    else if (protocolNumber == 17) UDP
                    else Other
                }
            }
        }

        constructor()

        internal constructor(buffer: ByteBuffer) {
            val versionAndIHL = buffer.get()
            this.version = (versionAndIHL.toInt() shr 4).toByte()
            this.IHL = (versionAndIHL.toInt() and 0x0F).toByte()
            this.headerLength = IHL.toInt() shl 2

            this.typeOfService = BitUtils.getUnsignedByte(buffer.get())
            this.totalLength = BitUtils.getUnsignedShort(buffer.getShort())

            this.identificationAndFlagsAndFragmentOffset = buffer.getInt()

            this.TTL = BitUtils.getUnsignedByte(buffer.get())
            this.protocolNum = BitUtils.getUnsignedByte(buffer.get())
            this.protocol = TransportProtocol.numberToEnum(protocolNum.toInt())
            this.headerChecksum = BitUtils.getUnsignedShort(buffer.getShort())

            val addressBytes = ByteArray(4)
            buffer[addressBytes, 0, 4]
            this.sourceAddress = InetAddress.getByAddress(addressBytes)

            buffer[addressBytes, 0, 4]
            this.destinationAddress = InetAddress.getByAddress(addressBytes)

            //this.optionsAndPadding = buffer.getInt();
        }

        fun fillHeader(buffer: ByteBuffer) {
            buffer.put((version.toInt() shl 4 or IHL.toInt()).toByte())
            buffer.put(typeOfService.toByte())
            buffer.putShort(totalLength.toShort())

            buffer.putInt(this.identificationAndFlagsAndFragmentOffset)

            buffer.put(TTL.toByte())
            buffer.put(protocol!!.number.toByte())
            buffer.putShort(headerChecksum.toShort())

            buffer.put(sourceAddress!!.address)
            buffer.put(destinationAddress!!.address)
        }

        override fun toString(): String {
            val sb = StringBuilder("IP4Header{")
            sb.append("version=").append(version.toInt())
            sb.append(", IHL=").append(IHL.toInt())
            sb.append(", typeOfService=").append(typeOfService.toInt())
            sb.append(", totalLength=").append(totalLength)
            sb.append(", identificationAndFlagsAndFragmentOffset=")
                .append(identificationAndFlagsAndFragmentOffset)
            sb.append(", TTL=").append(TTL.toInt())
            sb.append(", protocol=").append(protocolNum.toInt()).append(":").append(protocol)
            sb.append(", headerChecksum=").append(headerChecksum)
            sb.append(", sourceAddress=").append(sourceAddress!!.hostAddress)
            sb.append(", destinationAddress=").append(destinationAddress!!.hostAddress)
            sb.append('}')
            return sb.toString()
        }
    }

    class TCPHeader {
        var sourcePort: Int = 0
        var destinationPort: Int = 0

        var sequenceNumber: Long = 0
        var acknowledgementNumber: Long = 0

        var dataOffsetAndReserved: Byte = 0
        var headerLength: Int = 0
        var flags: Byte = 0
        var window: Int = 0

        var checksum: Int = 0
        var urgentPointer: Int = 0

        var optionsAndPadding: ByteArray? = null

        constructor(buffer: ByteBuffer) {
            this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort())
            this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort())

            this.sequenceNumber = BitUtils.getUnsignedInt(buffer.getInt())
            this.acknowledgementNumber = BitUtils.getUnsignedInt(buffer.getInt())

            this.dataOffsetAndReserved = buffer.get()
            this.headerLength = (dataOffsetAndReserved.toInt() and 0xF0) shr 2
            this.flags = buffer.get()
            this.window = BitUtils.getUnsignedShort(buffer.getShort())

            this.checksum = BitUtils.getUnsignedShort(buffer.getShort())
            this.urgentPointer = BitUtils.getUnsignedShort(buffer.getShort())

            val optionsLength = this.headerLength - TCP_HEADER_SIZE
            if (optionsLength > 0) {
                optionsAndPadding = ByteArray(optionsLength)
                buffer[optionsAndPadding, 0, optionsLength]
            }
        }

        constructor()

        val isFIN: Boolean
            get() = (flags.toInt() and FIN) == FIN

        val isSYN: Boolean
            get() = (flags.toInt() and SYN) == SYN


        val isRST: Boolean
            get() = (flags.toInt() and RST) == RST

        val isPSH: Boolean
            get() = (flags.toInt() and PSH) == PSH

        val isACK: Boolean
            get() = (flags.toInt() and ACK) == ACK

        val isURG: Boolean
            get() = (flags.toInt() and URG) == URG

        fun fillHeader(buffer: ByteBuffer) {
            buffer.putShort(sourcePort.toShort())
            buffer.putShort(destinationPort.toShort())

            buffer.putInt(sequenceNumber.toInt())
            buffer.putInt(acknowledgementNumber.toInt())

            buffer.put(dataOffsetAndReserved)
            buffer.put(flags)
            buffer.putShort(window.toShort())

            buffer.putShort(checksum.toShort())
            buffer.putShort(urgentPointer.toShort())
        }

        fun printSimple(): String {
            val sb = StringBuilder("")
            if (isFIN) sb.append("FIN ")
            if (isSYN) sb.append("SYN ")
            if (isRST) sb.append("RST ")
            if (isPSH) sb.append("PSH ")
            if (isACK) sb.append("ACK ")
            if (isURG) sb.append("URG ")
            sb.append("seq $sequenceNumber ")
            sb.append("ack $acknowledgementNumber ")
            return sb.toString()
        }

        override fun toString(): String {
            val sb = StringBuilder("TCPHeader{")
            sb.append("sourcePort=").append(sourcePort)
            sb.append(", destinationPort=").append(destinationPort)
            sb.append(", sequenceNumber=").append(sequenceNumber)
            sb.append(", acknowledgementNumber=").append(acknowledgementNumber)
            sb.append(", headerLength=").append(headerLength)
            sb.append(", window=").append(window)
            sb.append(", checksum=").append(checksum)
            sb.append(", flags=")
            if (isFIN) sb.append(" FIN")
            if (isSYN) sb.append(" SYN")
            if (isRST) sb.append(" RST")
            if (isPSH) sb.append(" PSH")
            if (isACK) sb.append(" ACK")
            if (isURG) sb.append(" URG")
            sb.append('}')
            return sb.toString()
        }

        companion object {
            const val FIN: Int = 0x01
            const val SYN: Int = 0x02
            const val RST: Int = 0x04
            const val PSH: Int = 0x08
            const val ACK: Int = 0x10
            const val URG: Int = 0x20

            fun flagToString(flags: Byte): String {
                val sb = StringBuilder("")
                if ((flags.toInt() and FIN) == FIN) sb.append("FIN ")
                if ((flags.toInt() and SYN) == SYN) sb.append("SYN ")
                if ((flags.toInt() and RST) == RST) sb.append("RST ")
                if ((flags.toInt() and PSH) == PSH) sb.append("PSH ")
                if ((flags.toInt() and ACK) == ACK) sb.append("ACK ")
                if ((flags.toInt() and URG) == URG) sb.append("URG ")
                return sb.toString()
            }
        }
    }

    class UDPHeader {
        var sourcePort: Int = 0
        var destinationPort: Int = 0

        var length: Int = 0
        var checksum: Int = 0


        constructor()

        constructor(buffer: ByteBuffer) {
            this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort())
            this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort())

            this.length = BitUtils.getUnsignedShort(buffer.getShort())
            this.checksum = BitUtils.getUnsignedShort(buffer.getShort())
        }

        fun fillHeader(buffer: ByteBuffer) {
            buffer.putShort(sourcePort.toShort())
            buffer.putShort(destinationPort.toShort())

            buffer.putShort(length.toShort())
            buffer.putShort(checksum.toShort())
        }

        override fun toString(): String {
            val sb = StringBuilder("UDPHeader{")
            sb.append("sourcePort=").append(sourcePort)
            sb.append(", destinationPort=").append(destinationPort)
            sb.append(", length=").append(length)
            sb.append(", checksum=").append(checksum)
            sb.append('}')
            return sb.toString()
        }
    }

    private object BitUtils {
        fun getUnsignedByte(value: Byte): Short {
            return (value.toInt() and 0xFF).toShort()
        }

        fun getUnsignedShort(value: Short): Int {
            return value.toInt() and 0xFFFF
        }

        fun getUnsignedInt(value: Int): Long {
            return value.toLong() and 0xFFFFFFFFL
        }
    }

    companion object {
        const val IP4_HEADER_SIZE: Int = 20
        const val TCP_HEADER_SIZE: Int = 20
        const val UDP_HEADER_SIZE: Int = 8


        val globalPackId: AtomicLong = AtomicLong()
    }
}
