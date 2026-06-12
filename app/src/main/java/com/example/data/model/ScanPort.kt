package com.example.data.model

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class ScanPort(
    val portNumber: Int,
    val protocol: String,
    val state: String,
    val serviceName: String,
    val version: String
)
