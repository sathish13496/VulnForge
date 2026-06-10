"""
Services Module

Checks for misconfigured network services by analyzing
Nmap scan results — open ports, insecure daemons, and
services running on default/dangerous configurations.
"""

from __future__ import annotations

from vulnforge.core.target import Finding, Severity, FindingStatus, Target
from vulnforge.modules.base_module import BaseModule


class ServicesModule(BaseModule):
    name = "Misconfigured Services"
    description = "Open ports, insecure daemons, default configs"
    module_id = "services"
    requires_auth = False

    # Services that should never be exposed to the network
    DANGEROUS_SERVICES = {
        "redis": {
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "title": "Redis Server Exposed Without Authentication",
            "desc": "Redis is accessible over the network. By default Redis has no "
                    "authentication, allowing anyone to read/write data and execute "
                    "commands (including writing SSH keys for server takeover).",
            "remediation": "Bind Redis to 127.0.0.1 in redis.conf, enable AUTH with "
                          "a strong password, and block the port in the firewall.",
        },
        "memcached": {
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "title": "Memcached Server Exposed to Network",
            "desc": "Memcached is accessible over the network without authentication. "
                    "Attackers can read cached data and use it for DDoS amplification attacks.",
            "remediation": "Bind Memcached to 127.0.0.1 with -l 127.0.0.1 flag. "
                          "Disable UDP with -U 0.",
        },
        "mongodb": {
            "severity": Severity.CRITICAL,
            "cvss": 9.1,
            "title": "MongoDB Exposed Without Authentication",
            "desc": "MongoDB is accessible over the network. Default installations "
                    "have no authentication, exposing all databases to anyone.",
            "remediation": "Enable authentication in mongod.conf, bind to 127.0.0.1, "
                          "and create admin users with strong passwords.",
        },
        "elasticsearch": {
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "title": "Elasticsearch Cluster Exposed to Network",
            "desc": "Elasticsearch is accessible without authentication, "
                    "exposing all indexed data to anyone on the network.",
            "remediation": "Enable X-Pack security, bind to localhost, "
                          "and use a reverse proxy with authentication.",
        },
        "mysql": {
            "severity": Severity.MEDIUM,
            "cvss": 6.5,
            "title": "MySQL Server Exposed to Network",
            "desc": "MySQL is accessible over the network. If using weak or "
                    "default credentials, this allows unauthorized database access.",
            "remediation": "Bind MySQL to 127.0.0.1 in my.cnf, use strong passwords, "
                          "and restrict user host access with GRANT statements.",
        },
        "postgresql": {
            "severity": Severity.MEDIUM,
            "cvss": 6.5,
            "title": "PostgreSQL Server Exposed to Network",
            "desc": "PostgreSQL is accessible over the network. Check pg_hba.conf "
                    "for proper authentication rules.",
            "remediation": "Configure pg_hba.conf to restrict connections. "
                          "Bind to 127.0.0.1 and use SSL for remote connections.",
        },
    }

    # Ports that indicate potentially dangerous services
    SUSPICIOUS_PORTS = {
        21: "FTP",
        23: "Telnet",
        69: "TFTP",
        111: "RPCbind",
        161: "SNMP",
        512: "rexec",
        513: "rlogin",
        514: "rsh",
        1099: "Java RMI",
        1433: "MSSQL",
        2049: "NFS",
        3389: "RDP",
        5900: "VNC",
        5901: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        9200: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
    }

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        self._emit("info", "Analyzing discovered services for misconfigurations...")

        # 1. Check for dangerous exposed services
        for service in target.services:
            svc_name = service.service_name.lower()

            # Check against known dangerous services
            for dangerous_name, info in self.DANGEROUS_SERVICES.items():
                if dangerous_name in svc_name or dangerous_name in service.product.lower():
                    findings.append(Finding(
                        title=info["title"],
                        description=f"{info['desc']} Found on port {service.port}.",
                        severity=info["severity"],
                        cvss_score=info["cvss"],
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"Port {service.port}: {service.display_name}",
                        remediation=info["remediation"],
                    ))
                    break

        # 2. Check for Telnet (should never be used)
        telnet_service = target.get_service_by_port(23)
        if telnet_service:
            findings.append(Finding(
                title="Telnet Service Running (Unencrypted Remote Access)",
                description=(
                    "Telnet transmits all data including passwords in plaintext. "
                    "This is a severe security risk as credentials can be sniffed."
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                module=self.module_id,
                status=FindingStatus.OPEN,
                evidence=f"Port 23: {telnet_service.display_name}",
                remediation="Disable Telnet immediately. Use SSH for remote access.",
            ))

        # 3. Check for FTP (insecure file transfer)
        ftp_service = target.get_service_by_port(21)
        if ftp_service:
            finding_title = "FTP Service Running"
            finding_desc = (
                "FTP transmits credentials and data in plaintext. "
            )
            # Check for anonymous FTP
            if "anonymous" in (ftp_service.extra_info or "").lower():
                finding_title = "FTP Anonymous Login Enabled"
                finding_desc += "Anonymous FTP login is enabled, allowing anyone to access files."
                severity = Severity.HIGH
                cvss = 7.5
            else:
                finding_desc += "Consider using SFTP or SCP instead."
                severity = Severity.MEDIUM
                cvss = 5.3

            findings.append(Finding(
                title=finding_title,
                description=finding_desc,
                severity=severity,
                cvss_score=cvss,
                module=self.module_id,
                status=FindingStatus.OPEN,
                evidence=f"Port 21: {ftp_service.display_name}",
                remediation="Disable FTP and use SFTP/SCP for file transfers. "
                           "If FTP is required, use FTPS (FTP over TLS).",
            ))

        # 4. Check for VNC (often has weak/no auth)
        for port in [5900, 5901, 5902]:
            vnc_service = target.get_service_by_port(port)
            if vnc_service:
                findings.append(Finding(
                    title=f"VNC Service Exposed on Port {port}",
                    description=(
                        "VNC provides remote desktop access. Many VNC implementations "
                        "have weak authentication or known vulnerabilities."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Port {port}: {vnc_service.display_name}",
                    remediation="Tunnel VNC through SSH. Use strong passwords and "
                               "restrict access via firewall rules.",
                ))
                break  # Report VNC once

        # 5. Check for RPCbind (NFS precursor)
        rpc_service = target.get_service_by_port(111)
        if rpc_service:
            findings.append(Finding(
                title="RPCbind Service Exposed",
                description=(
                    "RPCbind (portmapper) is accessible, which can expose information "
                    "about running RPC services including NFS."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.0,
                module=self.module_id,
                status=FindingStatus.REVIEW,
                evidence=f"Port 111: {rpc_service.display_name}",
                remediation="Block port 111 in the firewall if RPC services are not needed.",
            ))

        # 6. Count total suspicious ports
        suspicious_found = []
        for port, name in self.SUSPICIOUS_PORTS.items():
            if port in target.open_ports:
                suspicious_found.append(f"{port}/{name}")

        if len(suspicious_found) > 5:
            findings.append(Finding(
                title=f"Large Attack Surface — {len(suspicious_found)} Suspicious Ports Open",
                description=(
                    f"Multiple potentially dangerous ports are open: "
                    f"{', '.join(suspicious_found[:10])}. "
                    f"This significantly increases the attack surface."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.0,
                module=self.module_id,
                status=FindingStatus.REVIEW,
                evidence=f"Open suspicious ports: {suspicious_found}",
                remediation="Review all open ports and close unnecessary services. "
                           "Apply the principle of least privilege to network exposure.",
            ))

        return findings
