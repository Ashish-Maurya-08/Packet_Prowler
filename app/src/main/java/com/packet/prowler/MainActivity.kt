package com.packet.prowler

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.BottomAppBar
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.packet.prowler.services.ProwlerService
import com.packet.prowler.services.ProwlerService.Companion.ACTION_STOP_VPN
import com.packet.prowler.services.isRunning
import com.packet.prowler.ui.theme.AppTheme


enum class Screens(
){
    Home,
    ListPage,
    DataPage
}


class MainActivity : ComponentActivity() {
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
                        composable(route = Screens.Home.name, enterTransition = { EnterTransition.None } , exitTransition = {ExitTransition.None} ) {
                            HomeScreen()
                        }
                        composable(route = Screens.ListPage.name) {
                            EmptyScreen()
                        }
                        composable(route = Screens.DataPage.name) {
                            EmptyScreen()
                        }
                    }
                }
            }
        }
    }
}


fun currentScreen(navController: NavHostController): String {
    return navController.currentDestination?.route?:Screens.Home.name
}



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
            Text(
                text = if (!isRunning) "Start" else "Stop",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
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



@Composable
fun EmptyScreen() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .wrapContentWidth()
            .wrapContentHeight()
            .background(Color.White)
    )
}

