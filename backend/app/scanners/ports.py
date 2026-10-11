"""Module 5 - Network & Port Security.

Active TCP connect scan of high-risk ports. This module is gated behind
target ownership verification (see ``requires_verified_target``).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.models import Finding, Severity
from app.scanners.base import BaseScanner, ScanContext


@dataclass(frozen=True)
class PortSpec:
    port: int
    service: str
    severity: Severity


PORT_CATALOG: tuple[PortSpec, ...] = (
    PortSpec(21, "FTP", Severity.CRITICAL),
    PortSpec(22, "SSH", Severity.WARNING),
    PortSpec(23, "Telnet", Severity.CRITICAL),
    PortSpec(25, "SMTP", Severity.WARNING),
    PortSpec(53, "DNS", Severity.INFO),
    PortSpec(110, "POP3", Severity.WARNING),
    PortSpec(111, "RPCbind", Severity.CRITICAL),
    PortSpec(135, "MS RPC", Severity.CRITICAL),
    PortSpec(137, "NetBIOS-NS", Severity.CRITICAL),
    PortSpec(139, "NetBIOS-SSN", Severity.CRITICAL),
    PortSpec(143, "IMAP", Severity.WARNING),
    PortSpec(161, "SNMP", Severity.CRITICAL),
    PortSpec(389, "LDAP", Severity.CRITICAL),
    PortSpec(445, "SMB", Severity.CRITICAL),
    PortSpec(465, "SMTPS", Severity.WARNING),
    PortSpec(500, "IKE/ISAKMP", Severity.WARNING),
    PortSpec(514, "Syslog", Severity.WARNING),
    PortSpec(587, "Submission", Severity.WARNING),
    PortSpec(636, "LDAPS", Severity.CRITICAL),
    PortSpec(873, "Rsync", Severity.WARNING),
    PortSpec(990, "FTPS", Severity.WARNING),
    PortSpec(993, "IMAPS", Severity.WARNING),
    PortSpec(995, "POP3S", Severity.WARNING),
    PortSpec(1080, "SOCKS Proxy", Severity.CRITICAL),
    PortSpec(1099, "RMI Registry", Severity.CRITICAL),
    PortSpec(1433, "MSSQL", Severity.CRITICAL),
    PortSpec(1521, "Oracle DB", Severity.CRITICAL),
    PortSpec(1883, "MQTT", Severity.WARNING),
    PortSpec(2049, "NFS", Severity.CRITICAL),
    PortSpec(2082, "cPanel", Severity.CRITICAL),
    PortSpec(2083, "cPanel SSL", Severity.CRITICAL),
    PortSpec(2086, "WHM", Severity.CRITICAL),
    PortSpec(2087, "WHM SSL", Severity.CRITICAL),
    PortSpec(2121, "FTP Alt", Severity.WARNING),
    PortSpec(2181, "ZooKeeper", Severity.CRITICAL),
    PortSpec(2222, "DirectAdmin/SSH Alt", Severity.WARNING),
    PortSpec(2375, "Docker API", Severity.CRITICAL),
    PortSpec(2376, "Docker TLS", Severity.WARNING),
    PortSpec(2377, "Docker Swarm", Severity.CRITICAL),
    PortSpec(2379, "etcd Client", Severity.CRITICAL),
    PortSpec(2380, "etcd Peer", Severity.CRITICAL),
    PortSpec(3000, "Grafana/Dev", Severity.WARNING),
    PortSpec(3306, "MySQL", Severity.CRITICAL),
    PortSpec(3389, "RDP", Severity.CRITICAL),
    PortSpec(4369, "Erlang EPMD", Severity.CRITICAL),
    PortSpec(4440, "Rundeck", Severity.WARNING),
    PortSpec(4646, "Nomad", Severity.CRITICAL),
    PortSpec(5000, "Dev/Registry", Severity.WARNING),
    PortSpec(5001, "Dev Alt", Severity.WARNING),
    PortSpec(5432, "PostgreSQL", Severity.CRITICAL),
    PortSpec(5433, "PostgreSQL Alt", Severity.CRITICAL),
    PortSpec(5601, "Kibana", Severity.WARNING),
    PortSpec(5666, "NRPE", Severity.WARNING),
    PortSpec(5672, "RabbitMQ", Severity.WARNING),
    PortSpec(5900, "VNC", Severity.CRITICAL),
    PortSpec(5984, "CouchDB", Severity.CRITICAL),
    PortSpec(5985, "WinRM HTTP", Severity.CRITICAL),
    PortSpec(5986, "WinRM HTTPS", Severity.CRITICAL),
    PortSpec(6006, "TensorBoard", Severity.WARNING),
    PortSpec(6379, "Redis", Severity.CRITICAL),
    PortSpec(6443, "Kubernetes API", Severity.CRITICAL),
    PortSpec(6667, "IRC", Severity.INFO),
    PortSpec(7001, "WebLogic", Severity.CRITICAL),
    PortSpec(7002, "WebLogic SSL", Severity.CRITICAL),
    PortSpec(7077, "Spark Master", Severity.CRITICAL),
    PortSpec(7474, "Neo4j", Severity.CRITICAL),
    PortSpec(8000, "HTTP Alt", Severity.WARNING),
    PortSpec(8008, "HTTP Alt", Severity.WARNING),
    PortSpec(8009, "AJP", Severity.CRITICAL),
    PortSpec(8020, "HDFS NameNode", Severity.CRITICAL),
    PortSpec(8042, "Hadoop NodeMgr", Severity.WARNING),
    PortSpec(8080, "HTTP Alt", Severity.WARNING),
    PortSpec(8081, "HTTP Alt", Severity.WARNING),
    PortSpec(8086, "InfluxDB", Severity.WARNING),
    PortSpec(8088, "YARN / Superset", Severity.WARNING),
    PortSpec(8090, "HTTP Alt", Severity.WARNING),
    PortSpec(8140, "Puppet", Severity.WARNING),
    PortSpec(8161, "ActiveMQ", Severity.CRITICAL),
    PortSpec(8200, "Vault", Severity.CRITICAL),
    PortSpec(8443, "HTTPS Alt", Severity.WARNING),
    PortSpec(8500, "Consul", Severity.CRITICAL),
    PortSpec(8529, "ArangoDB", Severity.CRITICAL),
    PortSpec(8888, "Jupyter", Severity.CRITICAL),
    PortSpec(8929, "GitLab", Severity.WARNING),
    PortSpec(8983, "Solr", Severity.WARNING),
    PortSpec(9000, "Portainer/Sonar", Severity.WARNING),
    PortSpec(9090, "Prometheus", Severity.WARNING),
    PortSpec(9092, "Kafka", Severity.WARNING),
    PortSpec(9100, "Node Exporter", Severity.WARNING),
    PortSpec(9200, "Elasticsearch", Severity.CRITICAL),
    PortSpec(9300, "Elasticsearch Transport", Severity.CRITICAL),
    PortSpec(9418, "Git", Severity.WARNING),
    PortSpec(9443, "HTTPS Alt", Severity.WARNING),
    PortSpec(10000, "Webmin", Severity.CRITICAL),
    PortSpec(10250, "Kubelet", Severity.CRITICAL),
    PortSpec(10255, "Kubelet Read-only", Severity.CRITICAL),
    PortSpec(11211, "Memcached", Severity.CRITICAL),
    PortSpec(15672, "RabbitMQ Mgmt", Severity.WARNING),
    PortSpec(27017, "MongoDB", Severity.CRITICAL),
    PortSpec(27018, "MongoDB Shard", Severity.CRITICAL),
    PortSpec(28017, "MongoDB HTTP", Severity.CRITICAL),
    PortSpec(50000, "DB2 / Jenkins", Severity.WARNING),
    PortSpec(50070, "HDFS WebUI", Severity.WARNING),
)


class PortScanner(BaseScanner):
    id = "ports"
    module = "Network & Port Audit"
    title = "Network & Port Security"
    requires_verified_target = True

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        semaphore = asyncio.Semaphore(ctx.settings.max_concurrency)
        host = ctx.target.host

        async def probe(spec: PortSpec) -> tuple[PortSpec, bool]:
            async with semaphore:
                is_open = await self._is_open(host, spec.port, ctx.settings.port_timeout)
            return spec, is_open

        results = await asyncio.gather(*(probe(spec) for spec in PORT_CATALOG))

        open_ports = [(spec, is_open) for spec, is_open in results if is_open]
        findings: list[Finding] = []

        for spec, _ in open_ports:
            findings.append(
                self.result(
                    id=f"port_{spec.port}",
                    name=f"Exposed Port {spec.port} ({spec.service})",
                    severity=spec.severity,
                    status="Open to Public",
                    summary=(
                        f"Port {spec.port} ({spec.service}) is reachable from the "
                        "public internet."
                    ),
                    explanation=(
                        "Databases and admin services must never be exposed publicly. "
                        "Restrict them to private networks or a VPN/bastion host."
                    ),
                    fix_snippet=f"# UFW firewall\nsudo ufw deny {spec.port}/tcp",
                    meta={"port": spec.port, "service": spec.service},
                )
            )

        open_summary = ", ".join(
            f"{spec.port}/{spec.service}" for spec, _ in open_ports
        )
        findings.append(
            self.result(
                id="scan_summary",
                name="Network Port Scan Summary",
                severity=Severity.PASSED if not open_ports else Severity.INFO,
                status=f"{len(open_ports)} / {len(PORT_CATALOG)} open",
                summary=(
                    "No high-risk ports are exposed to the public internet."
                    if not open_ports
                    else f"Publicly reachable ports: {open_summary}"
                ),
                explanation=(
                    "Only a curated set of high-value ports is probed. A closed result "
                    "means the port did not accept a TCP connection from the scanner."
                ),
                fix_snippet="# Keep unnecessary ports firewalled; expose only 80/443.",
                meta={
                    "scanned": len(PORT_CATALOG),
                    "open": [spec.port for spec, _ in open_ports],
                },
            )
        )
        return findings

    @staticmethod
    async def _is_open(host: str, port: int, timeout: float) -> bool:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (TimeoutError, OSError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001, S110
            pass
        return True
