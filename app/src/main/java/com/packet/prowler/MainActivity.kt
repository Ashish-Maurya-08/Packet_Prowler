package com.packet.prowler

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.BottomAppBar
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.google.accompanist.drawablepainter.DrawablePainter
import com.packet.prowler.services.ProwlerService
import com.packet.prowler.services.ProwlerService.Companion.ACTION_STOP_VPN
import com.packet.prowler.services.isRunning
import com.packet.prowler.ui.theme.AppTheme
import com.packet.prowler.utils.packetGroup
import com.packet.prowler.utils.ports
import com.packet.prowler.viewmodel.Screens
import com.packet.prowler.viewmodel.categorizedPackets
import com.packet.prowler.viewmodel.totalSize
import java.net.InetAddress


class MainActivity : ComponentActivity() {
    @RequiresApi(Build.VERSION_CODES.Q)
    @SuppressLint("UnrememberedMutableState")
    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)


        enableEdgeToEdge()
        setContent {
            AppTheme {

                val homeTab = remember { mutableStateOf(true) }
                val buttonColors = ButtonColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    disabledContainerColor = MaterialTheme.colorScheme.primary,
                    disabledContentColor = MaterialTheme.colorScheme.onPrimary
                )
                val selectedButtonColor = ButtonColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    disabledContainerColor = MaterialTheme.colorScheme.primary,
                    disabledContentColor = MaterialTheme.colorScheme.onPrimary
                )

                val navController = rememberNavController()

                Scaffold(

                    topBar = {
                        TopAppBar(
                            title = { Text(stringResource(R.string.app_topBar), fontWeight = FontWeight(600)) },
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                titleContentColor = MaterialTheme.colorScheme.onSecondaryContainer
                            )
                        )
                    },

                    bottomBar = {
                        BottomAppBar(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                        ){
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceAround
                            ) {
                                Button(
                                    onClick = {
                                        if (currentScreen(navController) != Screens.Home.name){
                                            navController.navigate(Screens.Home.name)
                                            homeTab.value=true
                                        } else {/*pass*/}
                                    },
                                    colors = if (homeTab.value) selectedButtonColor else buttonColors,
                                ) {
                                    Icon( painter = painterResource(R.drawable.vpn_key), contentDescription ="Connection")
                                }
                                Button(
                                    onClick = {
                                        if (currentScreen(navController) != Screens.ListPage.name){
                                            navController.navigate(Screens.ListPage.name)
                                            homeTab.value=false
                                        } else{ /*pass*/ }
                                    },
                                    colors = if (!homeTab.value) selectedButtonColor else buttonColors,
                                ) {
                                    Icon(painter = painterResource(R.drawable.data_24), contentDescription ="Data")
                                }
                            }

                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )
                {
                    innerPadding ->
                    NavHost(
                        navController = navController,
                        startDestination = Screens.Home.name,
                        modifier = Modifier.padding(innerPadding)
                    ) {
                        composable(route = Screens.Home.name ) {
                            HomeScreen()
                        }
                        composable(route = Screens.ListPage.name) {
                            EmptyScreen()
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
    }
}


fun currentScreen(navController: NavHostController): String {
    return navController.currentDestination?.route?:Screens.Home.name
}



@RequiresApi(Build.VERSION_CODES.Q)
@Composable
fun HomeScreen() {

    val context = LocalContext.current
    val startVPNService = rememberStartVpnService(context)
    Box(
        modifier = Modifier
            .fillMaxSize()
            .wrapContentWidth()
            .wrapContentHeight()
    )
    {
        Button(
            shape = CircleShape,
            border = BorderStroke(2.dp, MaterialTheme.colorScheme.secondary),
            colors = ButtonColors(
                containerColor = Color.Transparent,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                disabledContainerColor = MaterialTheme.colorScheme.primary,
                disabledContentColor = MaterialTheme.colorScheme.onPrimary
            ),
            onClick = {
                if (!isRunning) {
                    startVPNService()
                }
                else {
                    stopVpnService(context)
                }

            },
            modifier = Modifier
                .padding(10.dp)
                .height(200.dp)
                .width(200.dp)
            ) {
            val size = convertBytes(totalSize)
            Text(

                text = if (!isRunning) "Start" else "$size",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

fun convertBytes(totalSize: Long): Any {
    return when {
        totalSize < 1024 -> "$totalSize B"
        totalSize < 1024 * 1024 -> "${totalSize / 1024} KB"
        totalSize < 1024 * 1024 * 1024 -> "${totalSize / (1024 * 1024)} MB"
        else -> "${totalSize / (1024 * 1024 * 1024)} GB"
    }
}


@Composable
fun rememberStartVpnService(context: Context): () -> Unit {
    val prepareVpnActivityResultLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Log.d("vpn", "permission granted")
            startVpnService(context)
        } else {
            // VPN permission denied, handle accordingly
        }
    }

    return remember(context) {
        {
            val intent = VpnService.prepare(context)
            if (intent != null) {
                // Prepare permission request
                prepareVpnActivityResultLauncher.launch(intent)
            } else {
                Log.d("vpn", "permission already granted")
                // Permission already granted or not required, start VPN service directly
                startVpnService(context)
            }
        }
    }
}



fun startVpnService(context: Context) {
    val serviceIntent = Intent(context, ProwlerService::class.java)
    context.startService(serviceIntent)
}


fun stopVpnService(context: Context) {
    val serviceIntent = Intent(context, ProwlerService::class.java)
    serviceIntent.action = ACTION_STOP_VPN
    context.startService(serviceIntent)
}



@RequiresApi(Build.VERSION_CODES.Q)
@Composable
fun EmptyScreen() {
    Box(
        modifier = Modifier
            .fillMaxSize()

    ){
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp)
//                .verticalScroll(rememberScrollState())
        ) {
            items(categorizedPackets.size) { index ->
                PacketItem(categorizedPackets[index])
                HorizontalDivider()
            }
        }
    }
}

@Composable
fun PacketItem(packet: packetGroup) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(90.dp)
    ) {
        Image(painter = packet.appIcon?.let { DrawablePainter(it) } ?: painterResource( R.drawable.ic_launcher_foreground),
            contentDescription = null ,
            alignment = Alignment.Center ,
            modifier = Modifier
                .height(60.dp)
                .width(60.dp)
                .padding(2.dp)
                .align(Alignment.CenterVertically)
        )

        Column (
            modifier = Modifier
                .fillMaxHeight()
                .padding(7.dp)
                .weight(1f),
            verticalArrangement = Arrangement.SpaceAround

        ){
            Text(text = "${packet.appName}",maxLines = 1)
            if (packet.remotePort in ports){
                Text(text = "${packet.remotePort} - ${ports[packet.remotePort]}", fontSize = 12.sp)
            } else {
                Text(text = "${packet.remotePort}", fontSize = 12.sp)
            }
            Text(text = "${packet.remoteIP.hostAddress ?: packet.remoteIP }", fontSize = 12.sp)
        }
        Column(
            modifier = Modifier
                .fillMaxHeight()
                .padding(0.dp, 0.dp, 7.dp, 0.dp),
            verticalArrangement = Arrangement.SpaceAround,
            horizontalAlignment = Alignment.End
        )
        {
            Text(text = "Sent: ${packet.sent.size}", fontSize = 12.sp)
            Text(text = "Received: ${packet.received.size}", fontSize = 12.sp)
        }
    }
    Spacer(modifier = Modifier.height(1.dp))
}


@RequiresApi(Build.VERSION_CODES.Q)
@Preview
@Composable
fun PreviewScreen() {
    val tempPacket = packetGroup(
        uid = 0,
        remoteIP = InetAddress.getByName("10.0.0.1"),
        remotePort = 80,
        sent = ArrayList(),
        received = ArrayList()
    )
    tempPacket.appName = "Test App"
    AppTheme {
        PacketItem(packet = tempPacket)
    }
}

