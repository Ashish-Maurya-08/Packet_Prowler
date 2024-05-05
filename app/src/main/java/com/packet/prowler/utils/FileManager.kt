package com.packet.prowler.utils

import android.util.Log
import java.io.File

class FileManager {
    val processHost = mutableMapOf<Int, Int>()
    private val filePaths = arrayOf(
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
        "/proc/net/raw",
        "/proc/net/raw6"
    )

    fun readNetworkInfo() {
        for (filePath in filePaths) {
            val file = File(filePath)
            if (file.exists()) {
                Log.d("FileManager", "File exists: $filePath")
                file.forEachLine { line ->
                    Log.d("FileManager", "Line: $line")
                    val netInfo = parseData(line)
                    netInfo?.let { saveToMap(it) }
                }
            }
        }
    }

    private fun parseData(data: String): NetInfo? {
        val splitData = data.split("\\s+".toRegex())
        if (splitData.size < 9) {
            return null
        }

        val localPort = splitData[2].split(":")[1].toIntOrNull(16) ?: return null
        val remotePort = splitData[3].split(":")[1].toIntOrNull(16) ?: return null
        val uid = splitData[7].toIntOrNull(10) ?: return null

        return NetInfo(localPort, remotePort, uid)
    }

    private fun saveToMap(netInfo: NetInfo) {
        processHost[netInfo.localPort] = netInfo.uid
    }

    data class NetInfo(val localPort: Int, val remotePort: Int, val uid: Int)
}
