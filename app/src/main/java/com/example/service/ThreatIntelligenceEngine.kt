package com.example.service

import androidx.compose.ui.graphics.Color

data class ThreatIntelReport(
    val portNumber: Int,
    val serviceName: String,
    val cveIds: List<String>,
    val cvssScore: Double,
    val severity: RiskSeverity,
    val exploitMaturity: String,
    val exploitationMethod: String,
    val attackPathSimulation: String,
    val defaultOSIndicator: String,
    val recommendedFirewallCmd: String
)

enum class RiskSeverity(val label: String, val colorHex: String) {
    CRITICAL("CRITICAL EXPOSURE", "#FFFFB4AB"),
    HIGH("HIGH RISK", "#FFFCB075"),
    MEDIUM("MEDIUM ADVISORY", "#FFFFCC00"),
    LOW("LOW / COMPLIANCE", "#FFB8F397"),
    INFO("INFORMATIONAL", "#FF4F709C")
}

object ThreatIntelligenceEngine {

    /**
     * Maps an open port or specific service to standard enterprise CVE databases
     * and compiles predictive attack-chain metrics.
     */
    fun analyzePortSecurity(port: Int, service: String): ThreatIntelReport {
        return when (port) {
            21 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "FTP (vsftpd/ProFTPD)",
                cveIds = listOf("CVE-2011-2523", "CVE-2015-3306"),
                cvssScore = 9.8,
                severity = RiskSeverity.CRITICAL,
                exploitMaturity = "PoC / Metasploit payload is actively weaponized.",
                exploitationMethod = "vsftpd backdoors allow unauthenticated remote command execution under root context.",
                attackPathSimulation = "Port Scan -> ProFTPD directory traversal exploit -> Shell access -> Root escalation.",
                defaultOSIndicator = "TTL: 64 (Linux Kernel 3.x - 5.x)",
                recommendedFirewallCmd = "sudo ufw deny proto tcp from any to any port 21"
            )
            22 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "SSH (OpenSSH)",
                cveIds = listOf("CVE-2023-38408", "CVE-2024-3094"),
                cvssScore = 7.8,
                severity = RiskSeverity.HIGH,
                exploitMaturity = "Complex PoC exists (XZ Utils backdoor targeted OpenSSH servers).",
                exploitationMethod = "Targeted brute force attacks on weak keys or buffer overflow of agent forwarders.",
                attackPathSimulation = "SSH brute force -> Keyboard-interactive compromise -> User space shell -> Cron persistent backdoor.",
                defaultOSIndicator = "TTL: 64 (Ubuntu / CentOS Enterprise Core)",
                recommendedFirewallCmd = "sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set"
            )
            23 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "Telnet Console",
                cveIds = listOf("CVE-1999-0137", "CVE-2020-10188"),
                cvssScore = 9.0,
                severity = RiskSeverity.CRITICAL,
                exploitMaturity = "Trivial script access. Widely abused by Mirai botnet engines.",
                exploitationMethod = "Transmits passwords in cleartext. Plain sniffing captures root login strings immediately.",
                attackPathSimulation = "Cleartext packet capture -> User session takeover -> Malicious binary execution -> System corruption.",
                defaultOSIndicator = "TTL: 255 (Legacy Switch / Cisco Administrative Panel)",
                recommendedFirewallCmd = "sudo ufw limit 23/tcp comment 'Strictly restrict Telnet console'"
            )
            25 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "SMTP (Sendmail/Postfix)",
                cveIds = listOf("CVE-2019-15846", "CVE-2023-51764"),
                cvssScore = 7.3,
                severity = RiskSeverity.MEDIUM,
                exploitMaturity = "Functional exploits exist for specific TLS certificates bypasses.",
                exploitationMethod = "SMTP smuggling or relay abuse allowing target network spoofing.",
                attackPathSimulation = "Open relay detection -> Phishing email masquerade -> End-user compromise.",
                defaultOSIndicator = "TTL: 64 (Linux Red Hat Cluster)",
                recommendedFirewallCmd = "sudo ufw deny 25/tcp"
            )
            53 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "DNS Resolver (dnsmasq/BIND)",
                cveIds = listOf("CVE-2020-25684", "CVE-2021-25217"),
                cvssScore = 7.5,
                severity = RiskSeverity.MEDIUM,
                exploitMaturity = "High volume DDoS reflection exploitation vectors available.",
                exploitationMethod = "Abuse open recursions to amplify junk DNS payloads 40x against remote endpoints.",
                attackPathSimulation = "Open Resolver Discovery -> DDoS Amplification involvement -> Threat blacklist enrollment.",
                defaultOSIndicator = "TTL: 255 (Core Domain Controller / Cisco WAN Gate)",
                recommendedFirewallCmd = "sudo iptables -A INPUT -p udp --dport 53 -j DROP"
            )
            80 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "HTTP Web (Nginx/Apache)",
                cveIds = listOf("CVE-2021-41773", "CVE-2023-44487"),
                cvssScore = 6.8,
                severity = RiskSeverity.MEDIUM,
                exploitMaturity = "Highly matured. HTTP/2 Rapid Reset scripts widely distributed.",
                exploitationMethod = "MitM dynamic traffic alteration, session token spoofing, or directory traversal headers.",
                attackPathSimulation = "HTTP Snooping -> Cleartext login interception -> Administrative console compromise.",
                defaultOSIndicator = "TTL: 64 (Debian Nginx Web Server Space)",
                recommendedFirewallCmd = "sudo ufw allow 80/tcp comment 'Permit standard dynamic web'"
            )
            143 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "IMAP Server",
                cveIds = listOf("CVE-2018-12345", "CVE-2021-3444"),
                cvssScore = 7.1,
                severity = RiskSeverity.HIGH,
                exploitMaturity = "Standard credential intercept vectors.",
                exploitationMethod = "Cleartext transfer over insecure channel leads to identity compromise.",
                attackPathSimulation = "Insecure IMAP polling -> Email credentials dump -> Domain Admin brute force.",
                defaultOSIndicator = "TTL: 64 (Mail Host Stack)",
                recommendedFirewallCmd = "sudo ufw deny 143/tcp"
            )
            161 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "SNMP Daemon",
                cveIds = listOf("CVE-2019-16053", "CVE-2022-24810"),
                cvssScore = 8.1,
                severity = RiskSeverity.HIGH,
                exploitMaturity = "Abused with public/common credentials ('public', 'private').",
                exploitationMethod = "Extract network schema mapping and configuration strings.",
                attackPathSimulation = "SNMP public scan -> Local device map leakage -> Network isolation bypass.",
                defaultOSIndicator = "TTL: 255 (Core Router Management Link)",
                recommendedFirewallCmd = "sudo iptables -A INPUT -p udp --dport 161 -m limit --limit 5/sec -j ACCEPT"
            )
            443 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "HTTPS SSL/TLS",
                cveIds = listOf("CVE-2014-0160", "CVE-2021-3449"),
                cvssScore = 5.0,
                severity = RiskSeverity.INFO,
                exploitMaturity = "Standard web server interface. Highly secure unless legacy TLS v1.0 remains active.",
                exploitationMethod = "SSL/TLS renegotiation denial of service or certificate chain tricks.",
                attackPathSimulation = "TLS Probe -> Certificate verification -> Connection validated.",
                defaultOSIndicator = "TTL: 64 (Enterprise Nginx Node)",
                recommendedFirewallCmd = "sudo ufw allow 443/tcp"
            )
            445 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "SMB File Share (Microsoft-DS)",
                cveIds = listOf("CVE-2017-0144", "CVE-2020-0796"),
                cvssScore = 10.0,
                severity = RiskSeverity.CRITICAL,
                exploitMaturity = "Aggressive global weaponization (EternalBlue, WannaCry source available).",
                exploitationMethod = "Buffer overflows inside SMBv1 protocols allow system level remote code execution without login.",
                attackPathSimulation = "SMB Probe -> EternalBlue payload injection -> System NT Authority execution -> Ransomware lock.",
                defaultOSIndicator = "TTL: 128 (Windows Server 2016/2019 Cluster)",
                recommendedFirewallCmd = "sudo iptables -A INPUT -p tcp --dport 445 -j DROP"
            )
            3306 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "MySQL Relational database",
                cveIds = listOf("CVE-2012-2122", "CVE-2021-22926"),
                cvssScore = 8.8,
                severity = RiskSeverity.HIGH,
                exploitMaturity = "Password bypass exploits and credential injection utilities.",
                exploitationMethod = "Exploiting protocol flaw to bypass database login password checks via repetitive logins.",
                attackPathSimulation = "MySQL socket connection -> Password bypass inject -> Remote database tables dump.",
                defaultOSIndicator = "TTL: 64 (Linux Server RDS cluster)",
                recommendedFirewallCmd = "sudo ufw deny 3306/tcp"
            )
            3389 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "RDP Remote Desktop",
                cveIds = listOf("CVE-2019-0708", "CVE-2022-21893"),
                cvssScore = 9.8,
                severity = RiskSeverity.CRITICAL,
                exploitMaturity = "BlueKeep Exploit active. High threat vectors present.",
                exploitationMethod = "Remote unauthenticated memory corruption inside virtual channel initialization.",
                attackPathSimulation = "RDP probe -> BlueKeep heap groom payload -> System privilege shell -> Domain persistence.",
                defaultOSIndicator = "TTL: 128 (Windows Desktop Workstation)",
                recommendedFirewallCmd = "sudo iptables -A INPUT -p tcp --dport 3389 -j DROP"
            )
            8080 -> ThreatIntelReport(
                portNumber = port,
                serviceName = "HTTP Alternate Web",
                cveIds = listOf("CVE-2021-44228", "CVE-2022-22965"),
                cvssScore = 8.5,
                severity = RiskSeverity.HIGH,
                exploitMaturity = "Log4j Remote Code Execution toolchains widely deployed.",
                exploitationMethod = "Insecure Java deserialization or HTTP header injections targeting alternate debug panels.",
                attackPathSimulation = "Alternate port probe -> Log4Shell JNDI exploit call -> Shell execution.",
                defaultOSIndicator = "TTL: 64 (Tomcat Web Stack Applet)",
                recommendedFirewallCmd = "sudo ufw deny 8080/tcp"
            )
            else -> ThreatIntelReport(
                portNumber = port,
                serviceName = "Unknown Diagnostic Socket",
                cveIds = listOf("CVE-GENERIC-NONE"),
                cvssScore = 4.0,
                severity = RiskSeverity.LOW,
                exploitMaturity = "Minor configuration validation recommended.",
                exploitationMethod = "Port is open, creating potential reconnaissance endpoint for internal network structure mapping.",
                attackPathSimulation = "Port Discovery -> Reconn reconnaissance -> Service cataloging.",
                defaultOSIndicator = "TTL: 64 (Standard TCP Loop Device)",
                recommendedFirewallCmd = "sudo ufw deny $port/tcp"
            )
        }
    }
}
