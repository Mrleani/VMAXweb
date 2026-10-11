"""Pro-plan feature tests: entitlements, API keys, schedules, alerts, PDF."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.db.account_store import AccountStore, account_store
from app.main import app
from app.models import Finding, ScanResult, Severity, Target
from app.services.alerts import _meets_threshold, _slack_text
from app.services.pdf import ReportBranding, build_report

DEV_HEADERS = {}


@pytest.fixture(autouse=True)
def _clean_store():
    account_store._accounts.clear()
    account_store._api_key_index.clear()
    yield
    account_store._accounts.clear()
    account_store._api_key_index.clear()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _sample_result(severity: Severity = Severity.CRITICAL) -> ScanResult:
    now = ScanResult.utc_now()
    findings = [
        Finding(
            id="tls.protocol",
            module="TLS",
            name="Legacy protocol",
            severity=severity,
            status="Failing",
            summary="summary",
            explanation="explanation",
        )
    ]
    return ScanResult(
        target=Target(
            url="https://example.com",
            scheme="https",
            host="example.com",
            port=443,
            path="/",
        ),
        score=42,
        grade="F",
        grade_label="Critical",
        findings=findings,
        started_at=now,
        finished_at=now,
        duration_ms=10,
        engine_version="1.1.0",
    )


def test_free_account_has_no_pro_entitlements(client: TestClient):
    body = client.get("/api/v1/account").json()
    assert body["plan"] == "free"
    assert body["entitlements"]["api_access"] is False
    assert body["monthly_limit"] == 5


def test_api_keys_require_pro(client: TestClient):
    response = client.post("/api/v1/api-keys", json={"name": "ci"})
    assert response.status_code == 402


def test_activate_pro_unlocks_entitlements(client: TestClient):
    body = client.post("/api/v1/account/plan", json={"plan": "pro"}).json()
    assert body["plan"] == "pro"
    assert body["entitlements"]["unlimited_scans"] is True
    assert body["entitlements"]["priority_support"] is True
    assert body["monthly_limit"] is None


def test_api_key_lifecycle_and_auth(client: TestClient):
    client.post("/api/v1/account/plan", json={"plan": "pro"})

    created = client.post("/api/v1/api-keys", json={"name": "ci"}).json()
    secret = created["secret"]
    assert secret.startswith("vmax_")
    assert created["key"]["prefix"] == secret[:12]

    authed = client.get("/api/v1/account", headers={"X-API-Key": secret})
    assert authed.status_code == 200

    bearer = client.get(
        "/api/v1/account", headers={"Authorization": f"Bearer {secret}"}
    )
    assert bearer.status_code == 200

    key_id = created["key"]["id"]
    assert client.delete(f"/api/v1/api-keys/{key_id}").status_code == 204
    assert client.get("/api/v1/account", headers={"X-API-Key": secret}).status_code == 401


def test_invalid_api_key_is_rejected(client: TestClient):
    response = client.get("/api/v1/account", headers={"X-API-Key": "vmax_deadbeef"})
    assert response.status_code == 401


def test_account_update_generates_webhook_secret(client: TestClient):
    client.post("/api/v1/account/plan", json={"plan": "pro"})
    body = client.put(
        "/api/v1/account",
        json={
            "brand_name": "Acme Security",
            "webhook_url": "https://hooks.example.com/vmax",
            "slack_webhook_url": "https://hooks.slack.com/services/x",
            "alert_email": "sec@acme.test",
            "alert_min_severity": "warning",
        },
    ).json()
    assert body["brand_name"] == "Acme Security"
    assert body["webhook_secret_set"] is True
    assert body["alert_min_severity"] == "warning"


def test_account_update_rejects_bad_severity(client: TestClient):
    client.post("/api/v1/account/plan", json={"plan": "pro"})
    response = client.put("/api/v1/account", json={"alert_min_severity": "nope"})
    assert response.status_code == 400


def test_schedules_require_pro_and_roundtrip(client: TestClient):
    assert client.get("/api/v1/schedules").status_code == 402

    client.post("/api/v1/account/plan", json={"plan": "pro"})
    created = client.post(
        "/api/v1/schedules", json={"url": "https://example.com", "cadence": "weekly"}
    ).json()
    assert created["cadence"] == "weekly"
    assert created["enabled"] is True

    listed = client.get("/api/v1/schedules").json()
    assert len(listed) == 1

    assert client.delete(f"/api/v1/schedules/{created['id']}").status_code == 204
    assert client.get("/api/v1/schedules").json() == []


def test_webhook_signature_is_stable():
    secret = "topsecret"
    body = json.dumps({"event": "scan.completed"}, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert signature == hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_alert_threshold_logic():
    critical = _sample_result(Severity.CRITICAL)
    passed = _sample_result(Severity.PASSED)
    assert _meets_threshold(critical, "critical") is True
    assert _meets_threshold(critical, "info") is True
    assert _meets_threshold(passed, "critical") is False
    assert "example.com" in _slack_text(critical, "abc123", "https://vma-xweb.vercel.app")


def test_scheduler_advance_moves_next_run():
    store = AccountStore()
    schedule = store.add_schedule("u1", "https://example.com", "daily")
    first = schedule.next_run_at
    store.advance(schedule, datetime.now(UTC))
    assert schedule.last_run_at is not None
    assert schedule.next_run_at > first - timedelta(seconds=1)


def test_pdf_branding_embeds_brand_name():
    plain = build_report(_sample_result())
    assert plain.startswith(b"%PDF")
    branded = build_report(
        _sample_result(), ReportBranding(brand_name="Acme Security")
    )
    assert branded.startswith(b"%PDF")
    assert len(branded) > 0
