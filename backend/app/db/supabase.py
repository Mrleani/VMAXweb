"""Supabase (PostgREST) repository implementation.

All requests use the service-role key, which bypasses RLS, so ownership is
enforced here by always scoping queries to the requesting ``user_id``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from app.db.repository import Plan, ScanListItem, ScanRepository
from app.models import Confidence, Finding, ScanResult, Severity, Target


class SupabaseRepository(ScanRepository):
    def __init__(
        self,
        url: str,
        service_key: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._base = f"{url.rstrip('/')}/rest/v1"
        self._key = service_key
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        }

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- writes ----------------------------------------------------------
    async def save_scan(
        self, user_id: str, result: ScanResult, *, trigger: str = "manual"
    ) -> str:
        target_id = await self._upsert_target(user_id, result.target)

        scan_payload = {
            "user_id": user_id,
            "target_id": target_id,
            "status": "completed",
            "score": result.score,
            "grade": result.grade,
            "grade_label": result.grade_label,
            "trigger": trigger,
            "engine_version": result.engine_version,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "duration_ms": result.duration_ms,
        }
        response = await self._client.post(
            f"{self._base}/scans",
            headers={**self._headers, "Prefer": "return=representation"},
            json=scan_payload,
        )
        response.raise_for_status()
        scan_id = response.json()[0]["id"]

        if result.findings:
            finding_rows = [
                {
                    "scan_id": scan_id,
                    "finding_key": finding.id,
                    "module": finding.module,
                    "name": finding.name,
                    "severity": finding.severity.value,
                    "status": finding.status,
                    "summary": finding.summary,
                    "explanation": finding.explanation,
                    "fix_snippet": finding.fix_snippet,
                    "confidence": finding.confidence.value,
                    "meta": finding.meta,
                }
                for finding in result.findings
            ]
            insert = await self._client.post(
                f"{self._base}/findings",
                headers={**self._headers, "Prefer": "return=minimal"},
                json=finding_rows,
            )
            insert.raise_for_status()

        return scan_id

    async def _upsert_target(self, user_id: str, target: Target) -> str:
        response = await self._client.post(
            f"{self._base}/targets",
            params={"on_conflict": "user_id,host"},
            headers={
                **self._headers,
                "Prefer": "resolution=merge-duplicates,return=representation",
            },
            json={"user_id": user_id, "url": target.url, "host": target.host},
        )
        response.raise_for_status()
        return response.json()[0]["id"]

    # -- reads -----------------------------------------------------------
    async def get_scan(self, scan_id: str, user_id: str | None = None) -> ScanResult | None:
        params = {"id": f"eq.{scan_id}", "select": "*"}
        if user_id is not None:
            params["user_id"] = f"eq.{user_id}"

        scan_resp = await self._client.get(
            f"{self._base}/scans", headers=self._headers, params=params
        )
        scan_resp.raise_for_status()
        rows = scan_resp.json()
        if not rows:
            return None
        scan = rows[0]

        target = await self._fetch_target(scan["target_id"])
        findings = await self._fetch_findings(scan_id)
        return self._to_result(scan, target, findings)

    async def _fetch_target(self, target_id: str) -> dict[str, Any]:
        response = await self._client.get(
            f"{self._base}/targets",
            headers=self._headers,
            params={"id": f"eq.{target_id}", "select": "*"},
        )
        response.raise_for_status()
        rows = response.json()
        return rows[0] if rows else {"url": "unknown", "host": "unknown"}

    async def _fetch_findings(self, scan_id: str) -> list[dict[str, Any]]:
        response = await self._client.get(
            f"{self._base}/findings",
            headers=self._headers,
            params={
                "scan_id": f"eq.{scan_id}",
                "select": "*",
                "order": "created_at.asc",
            },
        )
        response.raise_for_status()
        return response.json()

    async def list_scans(self, user_id: str, limit: int = 50) -> list[ScanListItem]:
        response = await self._client.get(
            f"{self._base}/scans",
            headers=self._headers,
            params={
                "user_id": f"eq.{user_id}",
                "select": "id,score,grade,grade_label,trigger,finished_at,targets(url,host)",
                "order": "finished_at.desc",
                "limit": str(limit),
            },
        )
        response.raise_for_status()

        items: list[ScanListItem] = []
        for row in response.json():
            target = row.get("targets") or {}
            items.append(
                ScanListItem(
                    id=row["id"],
                    url=target.get("url", ""),
                    host=target.get("host", ""),
                    score=row["score"],
                    grade=row.get("grade", ""),
                    grade_label=row.get("grade_label", ""),
                    trigger=row.get("trigger", "manual"),
                    finished_at=datetime.fromisoformat(row["finished_at"]),
                )
            )
        return items

    async def count_scans_since(self, user_id: str, since: datetime) -> int:
        response = await self._client.get(
            f"{self._base}/scans",
            headers={**self._headers, "Prefer": "count=exact", "Range": "0-0"},
            params={
                "user_id": f"eq.{user_id}",
                "finished_at": f"gte.{since.isoformat()}",
                "select": "id",
            },
        )
        response.raise_for_status()

        content_range = response.headers.get("content-range", "")
        if "/" in content_range:
            total = content_range.rsplit("/", 1)[-1]
            if total.isdigit():
                return int(total)
        return len(response.json())

    async def get_plan(self, user_id: str) -> Plan:
        response = await self._client.get(
            f"{self._base}/profiles",
            headers=self._headers,
            params={"id": f"eq.{user_id}", "select": "plan"},
        )
        response.raise_for_status()
        rows = response.json()
        return rows[0]["plan"] if rows else "free"

    # -- mapping ---------------------------------------------------------
    @staticmethod
    def _to_result(
        scan: dict[str, Any], target: dict[str, Any], findings: list[dict[str, Any]]
    ) -> ScanResult:
        target_model = Target(
            url=target.get("url", ""),
            scheme=target.get("url", "https://").split("://", 1)[0] or "https",
            host=target.get("host", ""),
            port=443 if target.get("url", "").startswith("https") else 80,
        )
        return ScanResult(
            target=target_model,
            score=scan.get("score", 0),
            grade=scan.get("grade", ""),
            grade_label=scan.get("grade_label", ""),
            findings=[SupabaseRepository._to_finding(row) for row in findings],
            started_at=datetime.fromisoformat(scan["started_at"]),
            finished_at=datetime.fromisoformat(scan["finished_at"]),
            duration_ms=scan.get("duration_ms", 0),
            engine_version=scan.get("engine_version", "unknown"),
        )

    @staticmethod
    def _to_finding(row: dict[str, Any]) -> Finding:
        return Finding(
            id=row.get("finding_key", row.get("id", "")),
            module=row.get("module", ""),
            name=row.get("name", ""),
            severity=Severity(row.get("severity", "info")),
            status=row.get("status", ""),
            summary=row.get("summary", ""),
            explanation=row.get("explanation", ""),
            fix_snippet=row.get("fix_snippet", ""),
            confidence=Confidence(row.get("confidence", "high")),
            meta=row.get("meta") or {},
        )
