package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.ui.Modifier
import com.example.data.db.ScanDatabase
import com.example.data.repository.ScanRepository
import com.example.service.NmapExecutionService
import com.example.ui.NmapScannerScreen
import com.example.ui.NmapViewModel
import com.example.ui.NmapViewModelFactory
import com.example.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {
    private val database by lazy { ScanDatabase.getDatabase(this) }
    private val repository by lazy { ScanRepository(database.scanHistoryDao()) }
    private val executionService by lazy { NmapExecutionService() }

    private val viewModel: NmapViewModel by viewModels {
        NmapViewModelFactory(application, repository, executionService)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    NmapScannerScreen(
                        viewModel = viewModel,
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

