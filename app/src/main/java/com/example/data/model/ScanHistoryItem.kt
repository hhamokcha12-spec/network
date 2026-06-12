package com.example.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_history")
data class ScanHistoryItem(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val target: String,
    val timestamp: Long = System.currentTimeMillis(),
    val arguments: String,
    val rawOutput: String,
    val portsCount: Int,
    val portsJson: String, // Stored as JSON list of ScanPort
    val isSuccess: Boolean,
    val projectName: String = "Corporate Subnet Alpha",
    val environmentTag: String = "Enterprise Scope"
)
