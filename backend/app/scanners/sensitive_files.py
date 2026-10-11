"""Module 4 - Sensitive Data Exposure & OWASP checks."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from dataclasses import dataclass

from app.models import Finding, Severity
from app.scanners.base import BaseScanner, ScanContext
from app.scoring.confidence import Evidence


@dataclass(frozen=True)
class SensitivePath:
    id: str
    path: str
    name: str
    severity: Severity
    explanation: str
    fix_snippet: str
    markers: tuple[str, ...] = ()
    allow_html: bool = False
    require_json: bool = False
    regex: str | None = None


SENSITIVE_PATHS: tuple[SensitivePath, ...] = (
    SensitivePath(
        id="dotenv",
        path="/.env",
        name="Exposed .env File",
        severity=Severity.CRITICAL,
        explanation=(
            "The .env file holds database passwords, API keys and signing secrets. "
            "Public access is a full credential compromise."
        ),
        fix_snippet="location ~ /\\.env { deny all; return 404; }",
        markers=("=", "SECRET", "KEY", "PASSWORD"),
        regex=r"(?m)^[A-Za-z0-9_]+\s*=",
    ),
    SensitivePath(
        id="dotenv_local",
        path="/.env.local",
        name="Exposed .env.local File",
        severity=Severity.CRITICAL,
        explanation="Environment overrides frequently contain live production secrets.",
        fix_snippet="location ~ /\\.env { deny all; return 404; }",
        markers=("=", "SECRET", "KEY", "PASSWORD"),
        regex=r"(?m)^[A-Za-z0-9_]+\s*=",
    ),
    SensitivePath(
        id="dotenv_prod",
        path="/.env.production",
        name="Exposed .env.production File",
        severity=Severity.CRITICAL,
        explanation="Production environment files contain the most sensitive credentials.",
        fix_snippet="location ~ /\\.env { deny all; return 404; }",
        markers=("=", "SECRET", "KEY", "PASSWORD"),
        regex=r"(?m)^[A-Za-z0-9_]+\s*=",
    ),
    SensitivePath(
        id="dotenv_backup",
        path="/.env.backup",
        name="Exposed .env.backup File",
        severity=Severity.CRITICAL,
        explanation="Forgotten backup copies of secrets bypass secret rotation.",
        fix_snippet="location ~ /\\.env { deny all; return 404; }",
        markers=("=", "SECRET", "KEY", "PASSWORD"),
        regex=r"(?m)^[A-Za-z0-9_]+\s*=",
    ),
    SensitivePath(
        id="git_config",
        path="/.git/config",
        name="Exposed .git Repository",
        severity=Severity.CRITICAL,
        explanation=(
            "A public .git directory lets attackers download the entire source "
            "history, including secrets removed from the working tree."
        ),
        fix_snippet="location ~ /\\.git { deny all; return 404; }",
        markers=("[core]", "repositoryformatversion"),
    ),
    SensitivePath(
        id="git_head",
        path="/.git/HEAD",
        name="Exposed .git Directory",
        severity=Severity.CRITICAL,
        explanation="A readable .git/HEAD confirms the whole repository is downloadable.",
        fix_snippet="location ~ /\\.git { deny all; return 404; }",
        markers=("ref:", "refs/heads"),
    ),
    SensitivePath(
        id="svn_entries",
        path="/.svn/entries",
        name="Exposed .svn Directory",
        severity=Severity.WARNING,
        explanation="Subversion metadata can reveal source code and internal paths.",
        fix_snippet="location ~ /\\.svn { deny all; return 404; }",
        markers=("dir", "svn"),
    ),
    SensitivePath(
        id="config_json",
        path="/config.json",
        name="Exposed config.json",
        severity=Severity.CRITICAL,
        explanation="Configuration files frequently contain credentials and internal endpoints.",
        fix_snippet="location = /config.json { deny all; }",
        markers=("{", "}"),
        require_json=True,
        regex=r"(?i)^\s*[\[{]",
    ),
    SensitivePath(
        id="config_yml",
        path="/config.yml",
        name="Exposed config.yml",
        severity=Severity.CRITICAL,
        explanation="YAML configuration often embeds database and API credentials.",
        fix_snippet="location ~ /\\.ya?ml$ { deny all; }",
        markers=(":", "password", "secret", "key"),
        regex=r"(?m)^[A-Za-z0-9_.-]+\s*:\s*\S",
    ),
    SensitivePath(
        id="web_config",
        path="/web.config",
        name="Exposed web.config",
        severity=Severity.CRITICAL,
        explanation="IIS configuration exposes connection strings and app settings.",
        fix_snippet="<configuration><system.webServer><security>...</security></system.webServer></configuration>",
        markers=("<configuration", "connectionString", "<appSettings"),
    ),
    SensitivePath(
        id="htaccess",
        path="/.htaccess",
        name="Exposed .htaccess",
        severity=Severity.WARNING,
        explanation="Apache config can reveal rewrite rules, auth paths and internal structure.",
        fix_snippet="location ~ /\\.ht { deny all; return 404; }",
        markers=("RewriteRule", "RewriteEngine", "AuthType"),
    ),
    SensitivePath(
        id="aws_credentials",
        path="/.aws/credentials",
        name="Exposed AWS Credentials",
        severity=Severity.CRITICAL,
        explanation="AWS access keys allow full account takeover of cloud resources.",
        fix_snippet="Never serve .aws directories; rotate the exposed keys immediately.",
        markers=("aws_access_key_id", "aws_secret_access_key"),
    ),
    SensitivePath(
        id="ssh_key",
        path="/id_rsa",
        name="Exposed SSH Private Key",
        severity=Severity.CRITICAL,
        explanation="A leaked private key grants shell access to every server trusting it.",
        fix_snippet="Never deploy private keys to web roots; rotate the compromised key.",
        markers=("BEGIN", "PRIVATE KEY", "OPENSSH"),
    ),
    SensitivePath(
        id="credentials_json",
        path="/credentials.json",
        name="Exposed credentials.json",
        severity=Severity.CRITICAL,
        explanation="Service-account files grant programmatic access to cloud APIs.",
        fix_snippet="Store service accounts outside the web root and rotate.",
        markers=("private_key", "client_email", "type"),
    ),
    SensitivePath(
        id="service_account",
        path="/service-account.json",
        name="Exposed Service Account Key",
        severity=Severity.CRITICAL,
        explanation="A service-account key enables privileged cloud API access.",
        fix_snippet="Store service accounts outside the web root and rotate.",
        markers=("private_key", "client_email", "project_id"),
    ),
    SensitivePath(
        id="terraform_state",
        path="/terraform.tfstate",
        name="Exposed Terraform State",
        severity=Severity.CRITICAL,
        explanation="Terraform state contains infrastructure secrets in plaintext.",
        fix_snippet="Store state in a secured remote backend, never in the web root.",
        markers=("terraform_version", "resources", "outputs"),
    ),
    SensitivePath(
        id="docker_compose",
        path="/docker-compose.yml",
        name="Exposed docker-compose.yml",
        severity=Severity.WARNING,
        explanation="Compose files reveal services, images and inline secrets.",
        fix_snippet="location ~ docker-compose { deny all; }",
        markers=("services:", "image:", "environment:"),
    ),
    SensitivePath(
        id="swagger",
        path="/swagger.json",
        name="Exposed API Schema (swagger.json)",
        severity=Severity.WARNING,
        explanation=(
            "A public API schema maps every endpoint, easing targeted API attacks."
        ),
        fix_snippet="# Require authentication or disable in production.",
        markers=("swagger", "openapi", "paths"),
        require_json=True,
    ),
    SensitivePath(
        id="openapi",
        path="/openapi.json",
        name="Exposed API Schema (openapi.json)",
        severity=Severity.WARNING,
        explanation="A public OpenAPI document exposes the full API surface.",
        fix_snippet="app = FastAPI(openapi_url=None)  # disable public schema",
        markers=("openapi", "paths"),
        require_json=True,
    ),
    SensitivePath(
        id="swagger_ui",
        path="/swagger-ui.html",
        name="Exposed Swagger UI",
        severity=Severity.WARNING,
        explanation="An interactive API console lets attackers probe endpoints with ease.",
        fix_snippet="# Disable or auth-gate Swagger UI in production.",
        markers=("SwaggerUIBundle", "swagger-ui-container", "swaggerui"),
        allow_html=True,
    ),
    SensitivePath(
        id="api_docs",
        path="/v2/api-docs",
        name="Exposed API Docs (Springfox)",
        severity=Severity.WARNING,
        explanation="Springfox api-docs leak the full endpoint and model schema.",
        fix_snippet="springdoc.api-docs.enabled=false",
        markers=("swagger", "paths", "definitions"),
        require_json=True,
    ),
    SensitivePath(
        id="actuator_env",
        path="/actuator/env",
        name="Exposed Spring Boot Actuator (env)",
        severity=Severity.CRITICAL,
        explanation="Actuator env endpoints expose environment variables and secrets.",
        fix_snippet="management.endpoints.web.exposure.include=health",
        markers=("propertySources", "activeProfiles", "systemProperties"),
        require_json=True,
    ),
    SensitivePath(
        id="actuator_health",
        path="/actuator/health",
        name="Exposed Spring Boot Actuator (health)",
        severity=Severity.INFO,
        explanation="Actuator health can disclose internal component status and versions.",
        fix_snippet="management.endpoints.web.exposure.include=health",
        markers=("status", "\"UP\"", "components"),
        require_json=True,
    ),
    SensitivePath(
        id="h2_console",
        path="/h2-console",
        name="Exposed H2 Database Console",
        severity=Severity.CRITICAL,
        explanation="The H2 web console can allow direct database access.",
        fix_snippet="spring.h2.console.enabled=false",
        markers=("H2 Console", "h2-console", "login.jsp"),
        allow_html=True,
    ),
    SensitivePath(
        id="jenkins_script",
        path="/script",
        name="Exposed Jenkins Script Console",
        severity=Severity.CRITICAL,
        explanation="The Jenkins script console gives remote code execution.",
        fix_snippet="Disable the script console and require authentication.",
        markers=("Script Console", "Jenkins", "Groovy"),
        allow_html=True,
    ),
    SensitivePath(
        id="elastic_cat",
        path="/_cat/indices",
        name="Exposed Elasticsearch Indices",
        severity=Severity.CRITICAL,
        explanation="An open Elasticsearch exposes and often allows modification of all data.",
        fix_snippet="Enable X-Pack security and bind Elasticsearch to localhost.",
        markers=("green", "yellow", "index", "health"),
        regex=r"\b(?:green|yellow|red)\s+(?:open|close)",
    ),
    SensitivePath(
        id="phpinfo",
        path="/phpinfo.php",
        name="Exposed phpinfo() Page",
        severity=Severity.WARNING,
        explanation="phpinfo() reveals PHP config, extensions, paths and environment.",
        fix_snippet="Remove phpinfo() scripts from production.",
        markers=("phpinfo", "PHP Version", "Configuration"),
        allow_html=True,
    ),
    SensitivePath(
        id="info_php",
        path="/info.php",
        name="Exposed info.php",
        severity=Severity.WARNING,
        explanation="Debug info pages disclose server configuration details.",
        fix_snippet="Remove diagnostic scripts from production.",
        markers=("phpinfo", "PHP Version", "Configuration"),
        allow_html=True,
    ),
    SensitivePath(
        id="dot_ds_store",
        path="/.DS_Store",
        name="Exposed .DS_Store",
        severity=Severity.INFO,
        explanation=".DS_Store leaks file and directory names from the developer's machine.",
        fix_snippet="location ~ \\.DS_Store { deny all; return 404; }",
        markers=("Bud1", "Mac OS X", ".DS_Store"),
    ),
    SensitivePath(
        id="backup_zip",
        path="/backup.zip",
        name="Exposed Backup Archive",
        severity=Severity.CRITICAL,
        explanation="Backup archives often contain full database dumps and source code.",
        fix_snippet="location ~* \\.(zip|tar|gz|sql|bak)$ { deny all; }",
    ),
    SensitivePath(
        id="backup_tar",
        path="/backup.tar.gz",
        name="Exposed Backup Archive (tar.gz)",
        severity=Severity.CRITICAL,
        explanation="Backup archives often contain full database dumps and source code.",
        fix_snippet="location ~* \\.(zip|tar|gz|sql|bak)$ { deny all; }",
    ),
    SensitivePath(
        id="db_sql",
        path="/db.sql",
        name="Exposed Database Dump",
        severity=Severity.CRITICAL,
        explanation="A downloadable SQL dump exposes all application data.",
        fix_snippet="location ~* \\.sql$ { deny all; }",
        markers=("INSERT INTO", "CREATE TABLE"),
    ),
    SensitivePath(
        id="dump_sql",
        path="/dump.sql",
        name="Exposed Database Dump (dump.sql)",
        severity=Severity.CRITICAL,
        explanation="A downloadable SQL dump exposes all application data.",
        fix_snippet="location ~* \\.sql$ { deny all; }",
        markers=("INSERT INTO", "CREATE TABLE"),
    ),
    SensitivePath(
        id="database_sql",
        path="/database.sql",
        name="Exposed Database Dump (database.sql)",
        severity=Severity.CRITICAL,
        explanation="A downloadable SQL dump exposes all application data.",
        fix_snippet="location ~* \\.sql$ { deny all; }",
        markers=("INSERT INTO", "CREATE TABLE"),
    ),
    SensitivePath(
        id="wp_config_bak",
        path="/wp-config.php.bak",
        name="Exposed WordPress Config Backup",
        severity=Severity.CRITICAL,
        explanation="A backup of wp-config.php exposes database credentials and salts.",
        fix_snippet="location ~* \\.(bak|old|orig|save|swp)$ { deny all; }",
        markers=("DB_PASSWORD", "DB_NAME", "AUTH_KEY"),
    ),
    SensitivePath(
        id="server_status",
        path="/server-status",
        name="Exposed Apache server-status",
        severity=Severity.WARNING,
        explanation="server-status leaks internal requests, client IPs and server load.",
        fix_snippet="<Location /server-status>\n    Require local\n</Location>",
        markers=("Apache Server Status",),
        allow_html=True,
    ),
    SensitivePath(
        id="server_info",
        path="/server-info",
        name="Exposed Apache server-info",
        severity=Severity.WARNING,
        explanation="server-info discloses Apache modules and configuration.",
        fix_snippet="<Location /server-info>\n    Require local\n</Location>",
        markers=("Apache Server Information",),
        allow_html=True,
    ),
)


class SensitiveFileScanner(BaseScanner):
    id = "sensitive_files"
    module = "Vulnerability & Asset Check"
    title = "Sensitive Data Exposure & OWASP Check"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        baseline_status, baseline_body = await self._baseline(ctx)
        semaphore = asyncio.Semaphore(ctx.settings.max_concurrency)

        async def check(spec: SensitivePath) -> Finding:
            async with semaphore:
                return await self._check_path(ctx, spec, baseline_status, baseline_body)

        findings = list(
            await asyncio.gather(*(check(spec) for spec in SENSITIVE_PATHS))
        )
        findings.append(await self._check_cookies(ctx))
        return findings

    async def _baseline(self, ctx: ScanContext) -> tuple[int | None, str | None]:
        random_path = f"/{secrets.token_hex(8)}"
        try:
            response = await ctx.client.get(f"{ctx.target.origin}{random_path}")
        except Exception:  # noqa: BLE001
            return None, None
        return response.status_code, self._normalize(response.text)

    async def _check_path(
        self,
        ctx: ScanContext,
        spec: SensitivePath,
        baseline_status: int | None,
        baseline_body: str | None,
    ) -> Finding:
        url = f"{ctx.target.origin}{spec.path}"
        try:
            response = await ctx.client.get(url)
        except Exception as exc:  # noqa: BLE001
            return self.result(
                id=spec.id,
                name=spec.name,
                severity=Severity.PASSED,
                status="Not reachable",
                summary="The path could not be retrieved.",
                explanation=spec.explanation,
                fix_snippet=spec.fix_snippet,
                evidence=Evidence.WEAK,
                meta={"error": str(exc)},
            )

        body = response.text[:20000]
        evidence = self._classify(
            response, body, spec, baseline_status, baseline_body
        )

        if evidence is not None:
            return self.result(
                id=spec.id,
                name=spec.name,
                severity=spec.severity,
                status="Publicly accessible (HTTP 200)",
                summary=f"{spec.path} is readable without authentication.",
                explanation=spec.explanation,
                fix_snippet=spec.fix_snippet,
                evidence=evidence,
                meta={"path": spec.path, "bytes": len(response.content)},
            )

        return self.result(
            id=spec.id,
            name=spec.name,
            severity=Severity.PASSED,
            status=f"Not accessible (HTTP {response.status_code})",
            summary=f"{spec.path} is not publicly exposed.",
            explanation=spec.explanation,
            fix_snippet=spec.fix_snippet,
            meta={"path": spec.path},
        )

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text[:4000]).strip().lower()

    @classmethod
    def _classify(
        cls,
        response,
        body: str,
        spec: SensitivePath,
        baseline_status: int | None,
        baseline_body: str | None,
    ) -> Evidence | None:
        if response.status_code != 200:
            return None

        content_type = response.headers.get("content-type", "").lower()
        is_html = "text/html" in content_type or "application/xhtml" in content_type
        body_lower = body.lower()

        # If the body mirrors the random-path baseline, it is a soft-404 echo.
        if baseline_body is not None and cls._normalize(body) == baseline_body:
            return None

        if spec.markers:
            # A real leak must contain at least one artifact-specific marker.
            if not any(marker.lower() in body_lower for marker in spec.markers):
                return None
            # Secret/config artifacts are never legitimately served as HTML.
            if is_html and not spec.allow_html:
                return None
            # Structural validation defeats generic markers on catch-all pages.
            if spec.require_json:
                try:
                    json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    return None
            if spec.regex and not re.search(spec.regex, body):
                return None
            return Evidence.STRONG

        # Markerless artifacts (e.g. backups): require a non-HTML 200 that the
        # site does not also return for a random path.
        if is_html or not response.content:
            return None
        if baseline_status is None:
            # Could not establish a baseline, so the result is ambiguous.
            return Evidence.MODERATE
        if baseline_status == 200:
            return None
        return Evidence.STRONG

    async def _check_cookies(self, ctx: ScanContext) -> Finding:
        try:
            response = await ctx.client.get(ctx.target.url)
        except Exception as exc:  # noqa: BLE001
            return self.result(
                id="cookie_flags",
                name="Cookie Security Flags",
                severity=Severity.INFO,
                status="Unavailable",
                summary="Could not inspect cookies.",
                explanation="Session cookies should carry Secure, HttpOnly and SameSite.",
                fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
                meta={"error": str(exc)},
            )

        cookies = response.headers.get_list("set-cookie")
        if not cookies:
            return self.result(
                id="cookie_flags",
                name="Cookie Security Flags",
                severity=Severity.PASSED,
                status="No cookies set",
                summary="No cookies were issued on the landing response.",
                explanation="Nothing to protect when no session cookie is set here.",
                fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
            )

        missing: dict[str, list[str]] = {}
        for raw in cookies:
            name = raw.split("=", 1)[0].strip()
            lowered = raw.lower()
            absent = []
            if "secure" not in lowered:
                absent.append("Secure")
            if "httponly" not in lowered:
                absent.append("HttpOnly")
            if "samesite" not in lowered:
                absent.append("SameSite")
            if absent:
                missing[name] = absent

        if missing:
            detail = "; ".join(f"{name}: missing {', '.join(flags)}" for name, flags in missing.items())
            return self.result(
                id="cookie_flags",
                name="Cookie Security Flags",
                severity=Severity.WARNING,
                status="Missing flags",
                summary=detail,
                explanation=(
                    "Without Secure/HttpOnly/SameSite, cookies are exposed to network "
                    "sniffing, XSS theft and CSRF."
                ),
                fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
                meta={"missing": missing},
            )

        return self.result(
            id="cookie_flags",
            name="Cookie Security Flags",
            severity=Severity.PASSED,
            status="All flags present",
            summary="All cookies set Secure, HttpOnly and SameSite.",
            explanation="Cookie theft and CSRF risk is minimized.",
            fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
        )
