import threading
import time

import pytest
from fastapi.testclient import TestClient

import app as appmod
from app import app, init_db


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "t.db")
    appmod.SESSIONS.clear()
    appmod._RESOURCE_LOCKS.clear()
    init_db()
    yield


def _login(c, username="admin", password="123456"):
    r = c.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _ro(c):
    return _login(c, "viewer", "view123")


def _snapshot(c, h):
    return {
        "slices": c.get("/api/slices", headers=h).json()["items"],
        "releases": c.get("/api/releases", headers=h).json()["items"],
        "watermarks": c.get("/api/watermarks", headers=h).json()["items"],
    }


def _events(role=None):
    with appmod.db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM auth_events ORDER BY id").fetchall()]
    return [r for r in rows if role is None or r["role"] == role]


def test_pipeline_admin():
    c = TestClient(app)
    assert c.get("/api/health").json()["product"] == "日切放行"
    h = _login(c)
    assert len(c.get("/api/slices", headers=h).json()["items"]) >= 1

    bad = c.post("/api/slices/1/release", headers=h, json={"consumer": "x"})
    assert bad.status_code == 409

    ok = c.post("/api/slices", headers=h, json={
        "slice_no": "SL-T-1", "biz_date": "2026-11-04", "partition_key": "mid",
        "row_count": 10, "expected_count": 10})
    assert ok.status_code == 200
    sid = ok.json()["id"]

    rel = c.post(f"/api/slices/{sid}/release", headers=h, json={"consumer": "ads_x"})
    assert rel.status_code == 200
    rid = rel.json()["release_id"]
    assert any(w["source_slice"] == "SL-T-1" for w in c.get("/api/watermarks", headers=h).json()["items"])

    # 重切：已放行须先回拨
    assert c.post(f"/api/slices/{sid}/recut", headers=h, json={}).status_code == 409
    rb = c.post(f"/api/releases/{rid}/rollback", headers=h)
    assert rb.status_code == 200 and rb.json()["watermarks_reverted"] == 1
    assert not any(w["source_slice"] == "SL-T-1" for w in c.get("/api/watermarks", headers=h).json()["items"])
    # 回拨后水位与放行态回退
    assert c.get(f"/api/slices/{sid}", headers=h).json()["slice"]["release_status"] == "未放行"
    # 重切 + 再放行
    rc = c.post(f"/api/slices/{sid}/recut", headers=h, json={"row_count": 8, "expected_count": 10})
    assert rc.status_code == 200 and rc.json()["completeness"] == "部分完整"
    assert c.post(f"/api/slices/{sid}/release", headers=h, json={"consumer": "ads_x"}).status_code == 409


def test_readonly_all_writes_denied_zero_write():
    c = TestClient(app)
    admin = _login(c)
    ro = _ro(c)
    before = _snapshot(c, admin)

    calls = [
        ("post", "/api/slices", {"slice_no": "SL-RO", "biz_date": "2026-11-05",
                                 "partition_key": "east", "row_count": 5, "expected_count": 5}),
        ("post", "/api/slices/1/evaluate", None),
        ("post", "/api/slices/2/release", {"consumer": "ads_ro"}),
        ("post", "/api/slices/1/recut", {"row_count": 1000}),
        ("post", "/api/releases/1/rollback", None),
        ("post", "/api/slices/2/rollback", {"consumer": "ads_order"}),
    ]
    for method, url, body in calls:
        r = getattr(c, method)(url, headers=ro, json=body)
        assert r.status_code == 403, (url, r.status_code, r.text)
        assert "无权限" in r.json()["detail"]

    after = _snapshot(c, admin)
    assert before == after, "只读令牌不得造成任何业务写入"

    denied = [e for e in _events() if e["event_type"] == "鉴权口径偏了"]
    assert len(denied) >= len(calls)
    assert all(e["result"] == "拒绝" and e["role"] == "只读" for e in denied)

    perms = c.get("/api/auth/permissions", headers=ro).json()
    assert perms["policy_code"] == "甲"
    assert perms["reconciliation"]["consistent"] is True
    assert perms["reconciliation"]["denied_write_attempts"] >= len(calls)


def test_policy_ledger_and_surface():
    c = TestClient(app)
    h = _login(c)
    pol = c.get("/api/auth/policy").json()
    assert pol["policy_code"] == "甲"
    assert pol["locked_on"] == "2026-11-17"
    assert "非管理员" in pol["rule"]
    assert pol["ledger"]["verified"] is True
    assert len(pol["ledger"]["sha256"]) == 64
    assert len(pol["write_endpoints"]) == 6

    perms = c.get("/api/auth/permissions", headers=h).json()
    roles = {r["role"]: r for r in perms["roles"]}
    assert roles["只读"]["can_write"] is False and roles["只读"]["can_release"] is False
    assert roles["管理员"]["can_release"] is True
    assert perms["release_flow"]["by_role"].get("管理员", 0) == perms["release_flow"]["total_success"]
    assert perms["reconciliation"]["consistent"] is True

    detail = c.get("/api/slices/1", headers=h).json()
    assert "auth_note" in detail and detail["can_write"] is True
    ro_detail = c.get("/api/slices/1", headers=_ro(c)).json()
    assert ro_detail["can_write"] is False and "只读" in ro_detail["auth_note"]

    wm = c.get("/api/watermarks", headers=h).json()
    assert wm["can_write"] is True and wm["items"]


def test_two_roles_same_endpoint_serialized_and_contention_logged():
    c = TestClient(app)
    admin = _login(c)
    ro = _ro(c)
    created = c.post("/api/slices", headers=admin, json={
        "slice_no": "SL-RACE", "biz_date": "2026-11-06", "partition_key": "race",
        "row_count": 4, "expected_count": 4}).json()
    sid = created["id"]

    results = {}

    def call(name, headers):
        results[name] = c.post(f"/api/slices/{sid}/release", headers=headers,
                               json={"consumer": "ads_race"})

    # 主线程先占住同一资源锁，确保两个角色都在“争用”路径上排队
    lock = appmod._resource_lock(f"slice:{sid}")
    lock.acquire()
    t1 = threading.Thread(target=call, args=("admin", admin))
    t2 = threading.Thread(target=call, args=("viewer", ro))
    t1.start()
    time.sleep(0.15)
    t2.start()
    time.sleep(0.3)
    lock.release()
    t1.join(5)
    t2.join(5)
    assert not t1.is_alive() and not t2.is_alive()

    assert results["admin"].status_code == 200
    assert results["viewer"].status_code == 403

    events = _events()
    contended = [e for e in events if e["event_type"] == "鉴权争用"]
    assert {e["role"] for e in contended} == {"管理员", "只读"}
    assert all(e["result"] in ("通过", "拒绝") for e in contended)
    assert any(e["event_type"] == "鉴权口径偏了" and e["result"] == "拒绝" for e in events)

    # 串行结果：切片只被放行一次，水位只有一条
    with appmod.db() as conn:
        succ = conn.execute("SELECT COUNT(*) c FROM releases WHERE slice_id=? AND status='成功'",
                            (sid,)).fetchone()["c"]
        wm = conn.execute("SELECT COUNT(*) c FROM watermarks WHERE source_slice='SL-RACE'").fetchone()["c"]
    assert succ == 1 and wm == 1


def test_ledger_deviation_blocks_writes_and_is_logged(tmp_path, monkeypatch):
    ledger = tmp_path / "鉴权拦截册.md"
    ledger.write_text("# 被篡改的册\n只读角色可写审计申请单\n", encoding="utf-8")
    monkeypatch.setattr("app.LEDGER_PATH", ledger)

    c = TestClient(app)
    h = _login(c)
    before = _snapshot(c, h)
    r = c.post("/api/slices", headers=h, json={
        "slice_no": "SL-BAD", "biz_date": "2026-11-07", "partition_key": "x",
        "row_count": 1, "expected_count": 1})
    assert r.status_code == 503
    assert "鉴权口径偏了" in r.json()["detail"]
    assert before == _snapshot(c, h)

    ev = [e for e in _events() if e["event_type"] == "鉴权口径偏了"]
    assert any(e["result"] == "拒绝" and e["role"] == "管理员" for e in ev)
    pol = c.get("/api/auth/policy").json()
    assert pol["ledger"]["verified"] is False


def test_startup_refuses_when_ledger_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("app.LEDGER_PATH", tmp_path / "missing.md")
    with pytest.raises(RuntimeError, match="鉴权口径偏了"):
        appmod._start()


def test_rejected_write_attempts_leave_audit_without_business_write():
    c = TestClient(app)
    h = _login(c)
    before = _snapshot(c, h)
    # 已放行切片再放行
    assert c.post("/api/slices/2/release", headers=h, json={"consumer": "ads_order"}).status_code == 409
    # 已放行切片重切
    assert c.post("/api/slices/2/recut", headers=h, json={}).status_code == 409
    # 未完整放行（只写拒绝流水，不改放行态与水位）
    assert c.post("/api/slices/3/release", headers=h, json={"consumer": "ads_none"}).status_code == 409

    after = _snapshot(c, h)
    assert before["slices"] == after["slices"]
    assert before["watermarks"] == after["watermarks"]
    assert [r["status"] for r in after["releases"]] == ["拒绝", "成功"]

    rows = [e for e in _events() if e["event_type"] == "下游放行" and e["result"] == "拒绝"]
    assert len(rows) >= 2
    assert all(e["role"] == "管理员" for e in rows)
