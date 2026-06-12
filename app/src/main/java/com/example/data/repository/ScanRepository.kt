package com.example.data.repository

import com.example.data.db.ScanHistoryDao
import com.example.data.model.ScanHistoryItem
import kotlinx.coroutines.flow.Flow

class ScanRepository(private val scanHistoryDao: ScanHistoryDao) {
    val allHistory: Flow<List<ScanHistoryItem>> = scanHistoryDao.getAllHistory()

    suspend fun insertScan(item: ScanHistoryItem): Long {
        return scanHistoryDao.insertScan(item)
    }

    suspend fun deleteScanById(id: Int) {
        scanHistoryDao.deleteScanById(id)
    }

    suspend fun clearHistory() {
        scanHistoryDao.deleteAllHistory()
    }
}
