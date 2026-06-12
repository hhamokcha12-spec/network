package com.example.data

import com.example.data.model.ScanPort

object NmapParser {
    // Regex to match lines like:
    // 22/tcp   open   ssh          OpenSSH 8.2p1 Ubuntu
    // 80/tcp   closed http
    // 443/https open  ssl/http-alt
    private val portLineRegex = Regex(
        "^([0-9]+)/(\\w+)\\s+(\\w+)\\s+([a-zA-Z0-9_./+-]+)(?:\\s+(.*))?$"
    )

    private val targetRegex = Regex(
        "Nmap scan report for (?:([^\\s()]+)\\s+)?(?:\\(([^)]+)\\))?"
    )

    private val latencyRegex = Regex(
        "Host is up \\(([^)]+)\\s+latency\\)"
    )

    /**
     * Parses a single line representing a port status.
     * Returns a ScanPort if matches the pattern, otherwise null.
     */
    fun parsePortLine(line: String): ScanPort? {
        val trimmed = line.trim()
        val matchResult = portLineRegex.matchEntire(trimmed) ?: return null
        
        val portNumber = matchResult.groupValues[1].toIntOrNull() ?: return null
        val protocol = matchResult.groupValues[2]
        val state = matchResult.groupValues[3]
        val serviceName = matchResult.groupValues[4]
        val version = matchResult.groupValues[5].trim()

        return ScanPort(
            portNumber = portNumber,
            protocol = protocol,
            state = state,
            serviceName = serviceName,
            version = version.ifEmpty { "Unknown" }
        )
    }

    /**
     * Extracts the IP or Hostname from the "Nmap scan report for..." line.
     */
    fun extractTarget(line: String): String? {
        val match = targetRegex.find(line) ?: return null
        val hostname = match.groups[1]?.value
        val ip = match.groups[2]?.value
        return ip ?: hostname
    }

    /**
     * Extracts latency from lines like "Host is up (0.0021s latency)."
     */
    fun extractLatency(line: String): String? {
        val match = latencyRegex.find(line) ?: return null
        return match.groups[1]?.value
    }
}
