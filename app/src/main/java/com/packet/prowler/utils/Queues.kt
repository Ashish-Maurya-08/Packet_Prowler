package com.packet.prowler.utils

import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.ClosedByInterruptException
import java.nio.channels.FileChannel
import java.util.concurrent.ArrayBlockingQueue


val deviceToNetworkUDPQueue = ArrayBlockingQueue<Packet>(1024)
val deviceToNetworkTCPQueue = ArrayBlockingQueue<Packet>(1024)
val networkToDeviceQueue = ArrayBlockingQueue<ByteBuffer>(1024)


object ToNetworkQueueWorker : Runnable {
    private const val TAG = "ToNetworkQueueWorker"

    /**
     * own thread
     */
    private lateinit var thread: Thread

    /**
     * read data channel from device
     */
    private lateinit var vpnInput: FileChannel

    /**
     * overall read data byte count
     */
    var totalInputCount = 0L


    fun start(vpnFileDescriptor: FileDescriptor) {
        if (this::thread.isInitialized && thread.isAlive) throw IllegalStateException("")
        vpnInput = FileInputStream(vpnFileDescriptor).channel
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
        val readBuffer = ByteBuffer.allocate(16384)
        while (!thread.isInterrupted) {
            var readCount = 0
            try {
                readCount = vpnInput.read(readBuffer)
            } catch (e: IOException) {
                e.printStackTrace()
                continue
            }
            if (readCount > 0) {
                readBuffer.flip()
                val byteArray = ByteArray(readCount)
                readBuffer.get(byteArray)

                val byteBuffer = ByteBuffer.wrap(byteArray)
                totalInputCount += readCount

                val packet = Packet(byteBuffer)
                if (packet.isUDP) {
                    deviceToNetworkUDPQueue.offer(packet)
                } else if (packet.isTCP) {
                    deviceToNetworkTCPQueue.offer(packet)
                } else {
                    Log.d(TAG, "${packet.ip4Header!!.protocolNum}")
                }
            } else if (readCount < 0) {
                break
            }
            readBuffer.clear()
        }
        Log.i(TAG, "ToNetworkQueueWorker")
    }

    fun checkWebUrl(packet: Packet) {
        val pktBuffer = packet.backingBuffer
        if (pktBuffer != null) {
            pktBuffer.mark()
        val tmpBytes = byteArrayOf()
        pktBuffer.get(tmpBytes)
        pktBuffer.reset()
        }
    }
}

/**
 * processing network communication device packet processing thread
 */
object ToDeviceQueueWorker : Runnable {
    private const val TAG = "ToDeviceQueueWorker"

    /**
     * own thread
     */
    private lateinit var thread: Thread

    /**
     * overall write data byte count
     */
    var totalOutputCount = 0L


    /**
     * write from network data channel
     */
    private lateinit var vpnOutput: FileChannel

    fun start(vpnFileDescriptor: FileDescriptor) {
        if (this::thread.isInitialized && thread.isAlive) throw IllegalStateException("")
        vpnOutput = FileOutputStream(vpnFileDescriptor).channel
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
        try {
            while (!thread.isInterrupted) {
                val byteBuffer = networkToDeviceQueue.take()
                byteBuffer.flip()
                while (byteBuffer.hasRemaining()) {
                    val count = vpnOutput.write(byteBuffer)
                    if (count > 0) {
                        totalOutputCount += count
                    }
                }
            }
        } catch (_: InterruptedException) {

        } catch (_: ClosedByInterruptException) {

        }

    }
}
