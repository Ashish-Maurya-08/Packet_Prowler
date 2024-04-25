package com.packet.prowler

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.BottomAppBar
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarColors
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import com.packet.prowler.ui.theme.AppTheme

class MainActivity : ComponentActivity() {
    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AppTheme {
                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text(text = "Prowler") },
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.primary,
                                titleContentColor = MaterialTheme.colorScheme.onPrimary
                            )
                        )
                    },
                    bottomBar = {
                        BottomAppBar(
                            containerColor = MaterialTheme.colorScheme.primary,
                            contentColor = MaterialTheme.colorScheme.onPrimary
                        ){
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceAround
                            ) {
                                Button(onClick = { /*TODO*/ }) {
                                    Icon( painter = painterResource(R.drawable.vpn_key), contentDescription ="Connection")
                                }
                                Button(onClick = { /*TODO*/ }) {
                                    Icon(painter = painterResource(R.drawable.data_24), contentDescription ="Data")
                                }
                            }
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                ) {
                    innerPadding ->
                    HomeScreen(
                        modifier = Modifier
                            .padding(innerPadding)
                            .fillMaxSize()
                    )
                }
            }
        }
    }
}

@Composable
fun HomeScreen(modifier: Modifier = Modifier) {

}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    AppTheme {
        HomeScreen()
    }
}