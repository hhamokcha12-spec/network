package com.example.data.db

import androidx.room.TypeConverter
import com.example.data.model.ScanPort
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory

class ScanTypeConverters {
    private val moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()
    
    private val portListType = Types.newParameterizedType(List::class.java, ScanPort::class.java)
    private val adapter = moshi.adapter<List<ScanPort>>(portListType)

    @TypeConverter
    fun fromJson(json: String?): List<ScanPort>? {
        if (json.isNullOrEmpty()) return emptyList()
        return try {
            adapter.fromJson(json)
        } catch (e: Exception) {
            emptyList()
        }
    }

    @TypeConverter
    fun toJson(ports: List<ScanPort>?): String {
        return adapter.toJson(ports ?: emptyList())
    }
}
