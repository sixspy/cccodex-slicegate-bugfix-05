import hashlib, json, secrets, sqlite3, threading, time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
LEDGER_PATH = ROOT / "ops" / "鉴权拦截册.md"
SESSIONS: dict[str, str] = {}

PRODUCT = "日切放行"
SKELETON = "业务日分区切片登记后裁决完整度，完整才放行下游，并与消费水位对账"

# ---- 鉴权口径（与 ops/鉴权拦截册.md 钉死一致，当天锁定为“甲”） ----
POLICY_CODE = "甲"
POLICY_DATE = "2026-11-17"
POLICY_RULE = "非管理员角色写接口一律返回无权限且零写入"
POLICY_FORBIDDEN = "乙规则：只读角色可写审计申请单但不得改切片放行态与水位，管理员审批后才由服务端执行写入"
POLICY_MARKERS = [
    f"口径代码：{POLICY_CODE}",
    f"锁定日期：{POLICY_DATE}",
    POLICY_RULE,
    "禁止乙口径混用",
]

ADMIN_ROLE = "管理员"
READONLY_ROLE = "只读"

WRITE_ENDPOINTS = [
    {"method": "POST", "path": "/api/slices", "action": "切片登记", "resource": "slices:new"},
    {"method": "POST", "path": "/api/slices/{sid}/evaluate", "action": "完整度重裁", "resource": "slice:{sid}"},
    {"method": "POST", "path": "/api/slices/{sid}/release", "action": "下游放行", "resource": "slice:{sid}"},
    {"method": "POST", "path": "/api/slices/{sid}/recut", "action": "重切", "resource": "slice:{sid}"},
    {"method": "POST", "path": "/api/releases/{rid}/rollback", "action": "放行回拨（按流水）", "resource": "releases:rollback"},
    {"method": "POST", "path": "/api/slices/{sid}/rollback", "action": "放行回拨（按切片）", "resource": "slice:{sid}"},
]

ROLE_MATRIX = [
    {"role": ADMIN_ROLE, "can_read": True, "can_write": True, "can_release": True,
     "can_rollback": True, "can_recut": True, "can_register": True,
     "note": "全部写入口可在服务端执行，按资源串行并留鉴权痕"},
    {"role": READONLY_ROLE, "can_read": True, "can_write": False, "can_release": False,
     "can_rollback": False, "can_recut": False, "can_register": False,
     "note": "写入口服务端一律 403，零业务写入；不得改切片放行态与水位"},
]

# ---- 并发闸：同一写入口按资源串行；等待者记“鉴权争用” ----
_LOCKS_GUARD = threading.Lock()
_RESOURCE_LOCKS: dict[str, threading.Lock] = {}


def _resource_lock(key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _RESOURCE_LOCKS.setdefault(key, threading.Lock())


def connect() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def completeness_of(row_count: int, expected_count: int) -> str:
    if expected_count > 0 and row_count >= expected_count:
        return "完整"
    return "部分完整" if row_count > 0 else "待检"


def http_error(status: int, detail: str, audited: bool = False) -> HTTPException:
    """audited=True 表示该拒绝已在业务事务内落过审计事件，避免重复记录。"""
    exc = HTTPException(status, detail)
    exc._audited = audited
    return exc


def ensure_users(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), ADMIN_ROLE))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), READONLY_ROLE))


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _insert_event(conn: sqlite3.Connection, username: str, role: str, action: str,
                  resource: str, event_type: str, result: str,
                  detail: str = "", ref_id: int | None = None) -> None:
    conn.execute(
        """INSERT INTO auth_events(ts,username,role,action,resource,event_type,result,detail,ref_id)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (now(), username, role, action, resource, event_type, result, detail, ref_id),
    )


def log_event(username: str, role: str, action: str, resource: str, event_type: str,
              result: str, detail: str = "", ref_id: int | None = None) -> None:
    """审计事件独立落库，保证非管理员被拒时业务表零写入。"""
    with db() as conn:
        _insert_event(conn, username, role, action, resource, event_type, result, detail, ref_id)


def require_user(authorization: str | None) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    username = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not username:
        raise HTTPException(401, "登录已失效")
    with db() as conn:
        row = conn.execute("SELECT username, role FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        raise HTTPException(401, "登录已失效")
    return {"username": row["username"], "role": row["role"]}


@contextmanager
def write_guard(authorization: str | None, action: str, resource: str) -> Iterator[dict[str, str]]:
    """服务端写入口鉴权 + 按资源串行。非管理员在锁内裁决为 403 且不碰业务表。"""
    user = require_user(authorization)
    lock = _resource_lock(resource)
    contended = not lock.acquire(blocking=False)
    if contended:
        lock.acquire()
    try:
        if contended:
            log_event(user["username"], user["role"], action, resource, "鉴权争用",
                      "通过" if user["role"] == ADMIN_ROLE else "拒绝",
                      f"同一写入口并发调用，按角色裁决：{user['role']}（已串行）")
        if user["role"] != ADMIN_ROLE:
            log_event(user["username"], user["role"], action, resource, "鉴权口径偏了",
                      "拒绝", f"非管理员调用写接口 {action}，已拒绝且零业务写入")
            raise HTTPException(403, "无权限：写入口仅管理员，已零写入")
        policy_ok, policy_reason, _ = verify_policy()
        if not policy_ok:
            log_event(user["username"], user["role"], action, resource, "鉴权口径偏了",
                      "拒绝", f"鉴权拦截册偏离，写入口已停用：{policy_reason}")
            raise HTTPException(503, "鉴权口径偏了：写入口已停用并零写入")
        try:
            yield user
        except HTTPException as exc:
            if not getattr(exc, "_audited", False):
                log_event(user["username"], user["role"], action, resource, "写入口拒绝",
                          "拒绝", f"{action}失败：{exc.detail}")
            raise
    finally:
        lock.release()


class LoginIn(BaseModel):
    username: str
    password: str


app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


def init_db() -> None:
    with db() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS slices(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_no TEXT UNIQUE NOT NULL,
          biz_date TEXT NOT NULL,
          partition_key TEXT NOT NULL,
          row_count INTEGER NOT NULL,
          expected_count INTEGER NOT NULL,
          completeness TEXT NOT NULL,
          release_status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS releases(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_id INTEGER NOT NULL,
          consumer TEXT NOT NULL,
          status TEXT NOT NULL,
          note TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS watermarks(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          consumer TEXT NOT NULL,
          biz_date TEXT NOT NULL,
          watermark TEXT NOT NULL,
          source_slice TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          username TEXT NOT NULL,
          role TEXT NOT NULL,
          action TEXT NOT NULL,
          resource TEXT NOT NULL,
          event_type TEXT NOT NULL,
          result TEXT NOT NULL,
          detail TEXT NOT NULL,
          ref_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS slice_ops(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_id INTEGER NOT NULL,
          action TEXT NOT NULL,
          actor TEXT NOT NULL,
          role TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        # 兼容本地旧库：只加列/表，不重建、不清数据
        _ensure_column(conn, "releases", "actor", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "releases", "actor_role", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "releases", "rollback_of", "INTEGER")
        _ensure_column(conn, "releases", "watermark_id", "INTEGER")
        conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_auth_baseline
                        ON auth_events(event_type, ref_id) WHERE event_type='基线放行'""")

        if conn.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"] == 0:
            rows = [
                ("SL-2026-11-01-east", "2026-11-01", "east", 980, 1000, "部分完整", "未放行"),
                ("SL-2026-11-01-west", "2026-11-01", "west", 1000, 1000, "完整", "已放行"),
                ("SL-2026-11-02-east", "2026-11-02", "east", 0, 1000, "待检", "未放行"),
            ]
            for r in rows:
                conn.execute(
                    "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status) VALUES (?,?,?,?,?,?,?)",
                    r,
                )
            conn.execute("INSERT INTO releases(slice_id,consumer,status,note,created_at,actor,actor_role) VALUES (2,'ads_order','成功','完整切片放行','2026-11-01T18:00:00','system','管理员')")
            conn.execute("INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES ('ads_order','2026-11-01','2026-11-01T18:00:00','SL-2026-11-01-west')")

        # 历史成功流水补齐角色归属与基线审计，保证“权限清册 = 放行流水”
        conn.execute("UPDATE releases SET actor='system' WHERE actor='' OR actor IS NULL")
        conn.execute("UPDATE releases SET actor_role='管理员' WHERE actor_role='' OR actor_role IS NULL")
        for r in conn.execute("SELECT id, slice_id, consumer FROM releases WHERE status='成功'").fetchall():
            conn.execute(
                """INSERT OR IGNORE INTO auth_events(ts,username,role,action,resource,event_type,result,detail,ref_id)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (now(), "system", ADMIN_ROLE, "release", f"slice:{r['slice_id']}",
                 "基线放行", "成功", "历史成功放行基线，管理员权限", r["id"]),
            )


def verify_policy() -> tuple[bool, str, str]:
    """服务启动时校验鉴权拦截册；偏离则拒绝启动并记“鉴权口径偏了”。"""
    if not LEDGER_PATH.exists():
        return False, f"缺少鉴权拦截册 {LEDGER_PATH}", ""
    text = LEDGER_PATH.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    missing = [m for m in POLICY_MARKERS if m not in text]
    if missing:
        return False, "鉴权拦截册缺少锁定口径：" + "；".join(missing), digest
    return True, "鉴权拦截册与实现一致", digest


@app.on_event("startup")
def _start() -> None:
    init_db()
    ok, reason, _ = verify_policy()
    if not ok:
        log_event("system", "系统", "policy", "ops/鉴权拦截册.md", "鉴权口径偏了", "拒绝", reason)
        raise RuntimeError("鉴权口径偏了：" + reason)


@app.get("/api/health")
def health():
    with db() as c:
        n = c.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "slices": n,
            "db": str(DB_PATH), "policy_code": POLICY_CODE}


@app.post("/api/login")
def login(body: LoginIn):
    with db() as c:
        row = c.execute("SELECT username, role FROM users WHERE username=? AND password_sha=?",
                        (body.username, sha(body.password))).fetchone()
    if not row:
        raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16)
    SESSIONS[tok] = row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)):
    return require_user(authorization)


@app.get("/api/auth/policy")
def auth_policy():
    ok, reason, digest = verify_policy()
    return {
        "policy_code": POLICY_CODE,
        "locked_on": POLICY_DATE,
        "rule": POLICY_RULE,
        "forbidden": POLICY_FORBIDDEN,
        "enforcement": "服务端角色拦截 + 同一写入口按资源串行；拒绝与争用落 auth_events",
        "write_endpoints": WRITE_ENDPOINTS,
        "ledger": {"path": "ops/鉴权拦截册.md", "sha256": digest, "verified": ok, "reason": reason},
    }


@app.get("/api/auth/events")
def auth_events(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM auth_events ORDER BY id DESC LIMIT 200").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/auth/permissions")
def permissions(authorization: str | None = Header(default=None)):
    me_user = require_user(authorization)
    with db() as c:
        success = c.execute("SELECT * FROM releases WHERE status='成功' ORDER BY id").fetchall()
        flow, mismatches, by_role = [], [], {}
        for r in success:
            ev = c.execute(
                """SELECT id FROM auth_events
                   WHERE action='release' AND result='成功' AND role=? AND ref_id=?""",
                (ADMIN_ROLE, r["id"]),
            ).fetchone()
            role = r["actor_role"] or "未知"
            consistent = role == ADMIN_ROLE and ev is not None
            by_role[role] = by_role.get(role, 0) + 1
            item = {"release_id": r["id"], "slice_id": r["slice_id"], "consumer": r["consumer"],
                    "actor": r["actor"] or "未知", "role": role,
                    "audited": ev is not None, "consistent": consistent}
            flow.append(item)
            if not consistent:
                mismatches.append({
                    "release_id": r["id"],
                    "reason": "放行角色非管理员" if role != ADMIN_ROLE else "缺少管理员鉴权留痕",
                })
        denied = c.execute(
            "SELECT COUNT(*) c FROM auth_events WHERE event_type='鉴权口径偏了' AND result='拒绝'"
        ).fetchone()["c"]
        contention = c.execute(
            "SELECT COUNT(*) c FROM auth_events WHERE event_type='鉴权争用'"
        ).fetchone()["c"]
    ok, _, digest = verify_policy()
    return {
        "me": me_user,
        "policy_code": POLICY_CODE,
        "roles": ROLE_MATRIX,
        "write_endpoints": WRITE_ENDPOINTS,
        "release_flow": {"total_success": len(success), "by_role": by_role, "items": flow},
        "reconciliation": {
            "consistent": not mismatches,
            "mismatches": mismatches,
            "denied_write_attempts": denied,
            "contention_events": contention,
        },
        "ledger": {"path": "ops/鉴权拦截册.md", "sha256": digest, "verified": ok},
    }


@app.get("/api/auth/ledger")
def auth_ledger():
    ok, reason, digest = verify_policy()
    return {"path": "ops/鉴权拦截册.md", "sha256": digest, "verified": ok, "reason": reason}


@app.get("/api/slices")
def list_slices(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM slices ORDER BY id").fetchall()
    return {"items": [dict(r) for r in rows]}


class SliceIn(BaseModel):
    slice_no: str
    biz_date: str
    partition_key: str
    row_count: int
    expected_count: int


@app.post("/api/slices")
def add_slice(body: SliceIn, authorization: str | None = Header(default=None)):
    with write_guard(authorization, "register", "slices:new") as user:
        if body.expected_count <= 0:
            raise HTTPException(400, "期望条数须大于 0")
        comp = completeness_of(body.row_count, body.expected_count)
        with db() as c:
            try:
                cur = c.execute(
                    "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status) VALUES (?,?,?,?,?,?,?)",
                    (body.slice_no, body.biz_date, body.partition_key, body.row_count,
                     body.expected_count, comp, "未放行"),
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "切片号已存在")
            sid = cur.lastrowid
            c.execute("INSERT INTO slice_ops(slice_id,action,actor,role,detail,created_at) VALUES (?,?,?,?,?,?)",
                      (sid, "register", user["username"], user["role"], f"{body.row_count}/{body.expected_count}", now()))
            _insert_event(c, user["username"], user["role"], "register", "slices:new",
                          "切片登记", "成功", body.slice_no, sid)
        return {"id": sid, "completeness": comp}


@app.get("/api/slices/{sid}")
def slice_detail(sid: int, authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    with db() as c:
        row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
        if not row:
            raise HTTPException(404, "切片不存在")
        rels = c.execute("SELECT * FROM releases WHERE slice_id=? ORDER BY id DESC", (sid,)).fetchall()
        wms = c.execute("SELECT * FROM watermarks WHERE source_slice=? ORDER BY id DESC",
                        (row["slice_no"],)).fetchall()
        ops = c.execute("SELECT * FROM slice_ops WHERE slice_id=? ORDER BY id DESC", (sid,)).fetchall()
    can_write = user["role"] == ADMIN_ROLE
    if can_write:
        note = "当前账号为管理员：可执行重裁、重切、放行与回拨；每次写入按切片串行并留鉴权痕。"
    else:
        note = "当前账号为只读：本切片写入口服务端一律 403，零写入；放行态、水位与审计申请均不可改，须管理员操作。"
    return {"slice": dict(row), "releases": [dict(r) for r in rels],
            "watermarks": [dict(w) for w in wms], "ops": [dict(o) for o in ops],
            "auth_note": note, "can_write": can_write, "role_matrix": ROLE_MATRIX,
            "policy_code": POLICY_CODE}


@app.post("/api/slices/{sid}/evaluate")
def evaluate(sid: int, authorization: str | None = Header(default=None)):
    with write_guard(authorization, "evaluate", f"slice:{sid}") as user:
        with db() as c:
            row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
            if not row:
                raise HTTPException(404, "切片不存在")
            comp = completeness_of(row["row_count"], row["expected_count"])
            c.execute("UPDATE slices SET completeness=? WHERE id=?", (comp, sid))
            c.execute("INSERT INTO slice_ops(slice_id,action,actor,role,detail,created_at) VALUES (?,?,?,?,?,?)",
                      (sid, "evaluate", user["username"], user["role"], comp, now()))
            _insert_event(c, user["username"], user["role"], "evaluate", f"slice:{sid}",
                          "完整度重裁", "成功", f"{row['completeness']}→{comp}", sid)
    return {"id": sid, "completeness": comp}


class ReleaseIn(BaseModel):
    consumer: str


@app.post("/api/slices/{sid}/release")
def release(sid: int, body: ReleaseIn, authorization: str | None = Header(default=None)):
    with write_guard(authorization, "release", f"slice:{sid}") as user:
        with db() as c:
            row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
            if not row:
                raise HTTPException(404, "切片不存在")
            ts = now()
            if row["release_status"] == "已放行":
                _insert_event(c, user["username"], user["role"], "release", f"slice:{sid}",
                              "下游放行", "拒绝", "切片已放行，须先回拨", sid)
                c.commit()
                raise http_error(409, "切片已放行，如需重放请先回拨", audited=True)
            if row["completeness"] != "完整":
                c.execute(
                    "INSERT INTO releases(slice_id,consumer,status,note,created_at,actor,actor_role) VALUES (?,?,?,?,?,?,?)",
                    (sid, body.consumer, "拒绝", "完整度未达标", ts, user["username"], user["role"]),
                )
                _insert_event(c, user["username"], user["role"], "release", f"slice:{sid}",
                              "下游放行", "拒绝", "完整度未达标", sid)
                c.commit()
                raise http_error(409, "未完整禁止放行", audited=True)
            c.execute("UPDATE slices SET release_status='已放行' WHERE id=?", (sid,))
            cur = c.execute(
                "INSERT INTO releases(slice_id,consumer,status,note,created_at,actor,actor_role) VALUES (?,?,?,?,?,?,?)",
                (sid, body.consumer, "成功", "完整切片放行", ts, user["username"], user["role"]),
            )
            rid = cur.lastrowid
            wm = c.execute(
                "INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES (?,?,?,?)",
                (body.consumer, row["biz_date"], ts, row["slice_no"]),
            )
            c.execute("UPDATE releases SET watermark_id=? WHERE id=?", (wm.lastrowid, rid))
            _insert_event(c, user["username"], user["role"], "release", f"slice:{sid}",
                          "下游放行", "成功", f"流水#{rid} 消费方 {body.consumer}", rid)
    return {"ok": True, "release_id": rid}


class RecutIn(BaseModel):
    row_count: int | None = None
    expected_count: int | None = None


@app.post("/api/slices/{sid}/recut")
def recut(sid: int, body: RecutIn, authorization: str | None = Header(default=None)):
    with write_guard(authorization, "recut", f"slice:{sid}") as user:
        with db() as c:
            row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
            if not row:
                raise HTTPException(404, "切片不存在")
            if row["release_status"] == "已放行":
                _insert_event(c, user["username"], user["role"], "recut", f"slice:{sid}",
                              "重切", "拒绝", "已放行切片须先回拨", sid)
                c.commit()
                raise http_error(409, "已放行切片须先回拨再重切", audited=True)
            rc = row["row_count"] if body.row_count is None else body.row_count
            ec = row["expected_count"] if body.expected_count is None else body.expected_count
            if ec <= 0 or rc < 0:
                raise HTTPException(400, "重切条数不合法")
            comp = completeness_of(rc, ec)
            c.execute("UPDATE slices SET row_count=?, expected_count=?, completeness=? WHERE id=?",
                      (rc, ec, comp, sid))
            c.execute("INSERT INTO slice_ops(slice_id,action,actor,role,detail,created_at) VALUES (?,?,?,?,?,?)",
                      (sid, "recut", user["username"], user["role"],
                       f"{row['row_count']}/{row['expected_count']}→{rc}/{ec} {comp}", now()))
            _insert_event(c, user["username"], user["role"], "recut", f"slice:{sid}",
                          "重切", "成功", f"{rc}/{ec} {comp}", sid)
    return {"id": sid, "row_count": rc, "expected_count": ec, "completeness": comp}


def _apply_rollback(c: sqlite3.Connection, rel: sqlite3.Row, user: dict[str, str]) -> dict:
    if rel["status"] != "成功":
        _insert_event(c, user["username"], user["role"], "rollback", f"release:{rel['id']}",
                      "放行回拨", "拒绝", "仅成功流水可回拨", rel["id"])
        c.commit()
        raise http_error(409, "仅成功放行流水可回拨", audited=True)
    ts = now()
    c.execute("UPDATE releases SET status='已回拨' WHERE id=?", (rel["id"],))
    cur = c.execute(
        "INSERT INTO releases(slice_id,consumer,status,note,created_at,actor,actor_role,rollback_of) VALUES (?,?,?,?,?,?,?,?)",
        (rel["slice_id"], rel["consumer"], "回拨", f"回拨流水#{rel['id']}", ts,
         user["username"], user["role"], rel["id"]),
    )
    new_id = cur.lastrowid
    other = c.execute(
        "SELECT COUNT(*) c FROM releases WHERE slice_id=? AND status='成功'", (rel["slice_id"],)
    ).fetchone()["c"]
    c.execute("UPDATE slices SET release_status=? WHERE id=?",
              ("已放行" if other else "未放行", rel["slice_id"]))
    removed = 0
    if rel["watermark_id"]:
        curw = c.execute("DELETE FROM watermarks WHERE id=?", (rel["watermark_id"],))
        removed = curw.rowcount
    else:
        curw = c.execute(
            "DELETE FROM watermarks WHERE consumer=? AND source_slice=? AND watermark=?",
            (rel["consumer"], rel["slice_no"], rel["created_at"]),
        )
        removed = curw.rowcount
    c.execute("INSERT INTO slice_ops(slice_id,action,actor,role,detail,created_at) VALUES (?,?,?,?,?,?)",
              (rel["slice_id"], "rollback", user["username"], user["role"],
               f"回拨流水#{rel['id']}，水位回退 {removed} 行", ts))
    _insert_event(c, user["username"], user["role"], "rollback", f"release:{rel['id']}",
                  "放行回拨", "成功", f"新流水#{new_id} 水位回退{removed}行", rel["id"])
    return {"ok": True, "release_id": rel["id"], "rollback_release_id": new_id,
            "watermarks_reverted": removed}


@app.post("/api/releases/{rid}/rollback")
def rollback_by_release(rid: int, authorization: str | None = Header(default=None)):
    with write_guard(authorization, "rollback", "releases:rollback") as user:
        with db() as c:
            rel = c.execute(
                """SELECT r.*, s.slice_no FROM releases r JOIN slices s ON s.id=r.slice_id
                   WHERE r.id=?""", (rid,),
            ).fetchone()
            if not rel:
                raise HTTPException(404, "放行流水不存在")
            return _apply_rollback(c, rel, user)


class RollbackIn(BaseModel):
    consumer: str | None = None


@app.post("/api/slices/{sid}/rollback")
def rollback_by_slice(sid: int, body: RollbackIn | None = None,
                      authorization: str | None = Header(default=None)):
    with write_guard(authorization, "rollback", f"slice:{sid}") as user:
        with db() as c:
            if not c.execute("SELECT 1 FROM slices WHERE id=?", (sid,)).fetchone():
                raise HTTPException(404, "切片不存在")
            sql = """SELECT r.*, s.slice_no FROM releases r JOIN slices s ON s.id=r.slice_id
                     WHERE r.slice_id=? AND r.status='成功'"""
            args: list = [sid]
            if body and body.consumer:
                sql += " AND r.consumer=?"
                args.append(body.consumer)
            rel = c.execute(sql + " ORDER BY r.id DESC LIMIT 1", args).fetchone()
            if not rel:
                raise HTTPException(404, "无成功放行流水可回拨")
            return _apply_rollback(c, rel, user)


@app.get("/api/releases")
def list_releases(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with db() as c:
        rows = c.execute(
            """SELECT r.*, s.slice_no FROM releases r JOIN slices s ON s.id=r.slice_id ORDER BY r.id DESC"""
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/watermarks")
def list_wm(authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    with db() as c:
        rows = c.execute("SELECT * FROM watermarks ORDER BY id DESC").fetchall()
    return {"items": [dict(r) for r in rows], "can_write": user["role"] == ADMIN_ROLE,
            "note": "水位回拨仅管理员可执行；只读账号只读，服务端零写入。"}


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
