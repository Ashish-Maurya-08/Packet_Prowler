package com.packet.prowler.utils

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import com.packet.prowler.services.pkgManager
import java.net.InetAddress



data class packetGroup(
    val uid: Int?,
    val remoteIP: InetAddress,
    val remotePort: Int,
    val sent: ArrayList<Packet>,
    val received: ArrayList<Packet>
)
{
    @SuppressLint("QueryPermissionsNeeded")
    val pkgs = pkgManager?.getInstalledPackages(PackageManager.GET_META_DATA)!!
    private var pkgName : String? = null
    var appName : String? = null
    var appIcon : Drawable? = null

    init {
        findPackage()
    }

    private fun findPackage(){
        pkgs.forEach {
            if(it.applicationInfo.uid == uid){
                pkgName = it.packageName
                appName = it.applicationInfo.loadLabel(pkgManager!!).toString()
                appIcon = it.applicationInfo.loadIcon(pkgManager!!)
            }
        }
        if (uid == 0){
            pkgName = "root"
            appName = "Android"
        }
    }

}