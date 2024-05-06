package com.packet.prowler.worker

import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import com.packet.prowler.utils.Packet
import com.packet.prowler.viewmodel.allPackets
import com.packet.prowler.viewmodel.totalSize
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
    private lateinit var thread: Thread
    private lateinit var vpnInput: FileChannel
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

    @RequiresApi(Build.VERSION_CODES.Q)
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

                addPacket(readBuffer)


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

}



object ToDeviceQueueWorker : Runnable {

    private const val TAG = "ToDeviceQueueWorker"
    private lateinit var thread: Thread
    var totalOutputCount = 0L


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

    @RequiresApi(Build.VERSION_CODES.Q)
    override fun run() {
        try {
            while (!thread.isInterrupted) {
                val byteBuffer = networkToDeviceQueue.take()
                byteBuffer.flip()

                addPacket(byteBuffer)

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


@RequiresApi(Build.VERSION_CODES.Q)
fun addPacket(byteBuffer: ByteBuffer){
    val buffer = byteBuffer.duplicate()
    val packet = Packet(buffer)
    if (packet.isUDP || packet.isTCP){
        totalSize += byteBuffer.remaining()
        Log.d("TotalSize", totalSize.toString())
        allPackets.offer(packet)
    }
}

