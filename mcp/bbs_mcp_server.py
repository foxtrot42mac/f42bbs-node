"""
F42BBS MCP Server — Charlie-style session protocol
- bbs_claim(otp)             → {session_id, point_addr, help}
- bbs_step(session_id, cmd)  → {result, session_id}  # sliding sid

OTP flow:
  server: f42bbs-admin genotp <addr>  → prints OTP
  client: bbs_claim(otp)              → session_id + point_addr
  client: bbs_step(sid, "status")     → result + new sid

Keys stored on node, not client. Client only holds current session_id.
"""
from __future__ import annotations
import os, sys, json, time, secrets, hashlib, hmac as _hmac
from flask import Flask, request, Response, jsonify
from dotenv import load_dotenv

load_dotenv()

DATA_DIR   = os.getenv("F42BBS_DATA_DIR", "/var/lib/f42bbs")
NODE_ADDR  = os.getenv("F42BBS_NODE_ID",  "1:42/1")
STEP_URL   = os.getenv("F42BBS_STEP_URL", "http://localhost:8001")
PORT       = int(os.getenv("BBS_MCP_PORT", "8006"))
MCP_PATH   = os.getenv("BBS_MCP_PATH",    "/bbs-mcp")

POINTS_FILE = os.path.join(DATA_DIR, "points.json")
OTP_FILE    = os.path.join(DATA_DIR, "otps.json")    # {otp_hash: {addr, exp}}
SESSION_FILE= os.path.join(DATA_DIR, "sessions.json") # {sid: {addr, exp}}

sys.path.insert(0, "/home/f42agent/f42bbs")

app = Flask(__name__)


# ── storage ───────────────────────────────────────────────────────────────────

def _load(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return {}

def _save(path, data):
    import stat, tempfile
    tmp = path + ".tmp"
    with open(tmp, "w") as f: json.dump(data, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

def _otp_hash(otp: str) -> str:
    return hashlib.sha256(otp.encode()).hexdigest()

def _new_sid() -> str:
    return secrets.token_hex(32)

def _now() -> int:
    return int(time.time())


# ── OTP ───────────────────────────────────────────────────────────────────────

def generate_otp(point_addr: str, ttl: int = 300) -> str:
    """Generate 4-word OTP for point_addr. Saves hash to otps.json."""
    import random
    words = [
        "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel",
        "india","juliet","kilo","lima","mike","november","oscar","papa",
        "quebec","romeo","sierra","tango","uniform","victor","whiskey",
        "xray","yankee","zulu","zero","one","two","three","four","five",
        "six","seven","eight","nine","north","south","east","west","red",
        "blue","green","black","white","sun","moon","star","cloud","river",
    ]
    otp = " ".join(random.choices(words, k=4))
    otps = _load(OTP_FILE)
    # Expire old OTPs for this addr
    otps = {h: v for h, v in otps.items()
            if v.get("addr") != point_addr and v.get("exp", 0) > _now()}
    otps[_otp_hash(otp)] = {"addr": point_addr, "exp": _now() + ttl}
    _save(OTP_FILE, otps)
    return otp

def claim_otp(otp: str) -> str | None:
    """Verify OTP, consume it, return point_addr or None."""
    otps = _load(OTP_FILE)
    h = _otp_hash(otp.strip())
    entry = otps.get(h)
    if not entry:
        return None
    if entry.get("exp", 0) < _now():
        del otps[h]
        _save(OTP_FILE, otps)
        return None
    addr = entry["addr"]
    del otps[h]
    _save(OTP_FILE, otps)
    return addr


# ── Session ───────────────────────────────────────────────────────────────────

SESSION_TTL = 3600  # 1 hour

def create_session(point_addr: str) -> str:
    sid = _new_sid()
    sessions = _load(SESSION_FILE)
    # Expire old sessions
    sessions = {s: v for s, v in sessions.items() if v.get("exp", 0) > _now()}
    sessions[sid] = {"addr": point_addr, "exp": _now() + SESSION_TTL}
    _save(SESSION_FILE, sessions)
    return sid

def consume_session(sid: str) -> tuple[str | None, str]:
    """Consume session_id, return (point_addr, new_sid) or (None, '')."""
    sessions = _load(SESSION_FILE)
    entry = sessions.get(sid)
    if not entry or entry.get("exp", 0) < _now():
        if sid in sessions:
            del sessions[sid]
            _save(SESSION_FILE, sessions)
        return None, ""
    addr = entry["addr"]
    del sessions[sid]
    # Create new sid
    new_sid = _new_sid()
    sessions = {s: v for s, v in sessions.items() if v.get("exp", 0) > _now()}
    sessions[new_sid] = {"addr": addr, "exp": _now() + SESSION_TTL}
    _save(SESSION_FILE, sessions)
    return addr, new_sid


# ── BBS command executor ──────────────────────────────────────────────────────

def step_cmd(cmd: str) -> str:
    import requests as _req
    r = _req.post(f"{STEP_URL}/step",
                  data=f",{cmd}".encode("utf-8"),
                  headers={"Content-Type": "text/plain; charset=utf-8"},
                  timeout=15)
    parts = r.text.strip().split("%", 2)
    return parts[2].strip() if len(parts) >= 3 else r.text.strip()

def execute(cmd: str, point_addr: str) -> str:
    parts = cmd.strip().split(None, 1)
    verb  = parts[0].lower() if parts else ""
    rest  = parts[1] if len(parts) > 1 else ""

    if verb == "help":
        return HELP_TEXT

    if verb == "genotp":
        # genotp [addr] — generate new OTP (admin command in session)
        addr = rest.strip() or point_addr
        points = _load(POINTS_FILE)
        if addr not in points:
            return f"error: point {addr} not found"
        otp = generate_otp(addr)
        return f"OTP for {addr}: {otp}\n(valid 5 min, single use)"

    if verb in ("publish", "pub"):
        return step_cmd(f"publish {rest}")

    if verb == "get":
        return step_cmd(f"get {rest}")

    if verb == "request":
        return step_cmd(f"request {rest}")

    if verb == "status":
        import requests as _req, sqlite3
        db_path = os.getenv("F42BBS_DB", "/home/f42agent/f42bbs/f42bbs.db")
        lines = [f"Node:  {NODE_ADDR}", f"Point: {point_addr}",
                 f"Time:  {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"]
        try:
            size = os.path.getsize(db_path)
            con  = sqlite3.connect(db_path)
            msgs  = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            peers = con.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
            con.close()
            lines.append(f"DB:    {size//1024}KB, {msgs} msgs, {peers} peers")
        except Exception as e:
            lines.append(f"DB:    error ({e})")
        return "\n".join(lines)

    if verb == "points":
        pts = _load(POINTS_FILE)
        if not pts:
            return "no points registered"
        return "\n".join(f"  {a}  label={v.get('label','?')}" for a, v in sorted(pts.items()))

    if verb == "nodes":
        try:
            import keystore
            keystore.KEYS_FILE    = "/home/f42agent/.f42bbs_keys"
            keystore.GENESIS_FILE = "/home/f42agent/.f42bbs_genesis"
            nl = keystore.get_nodelist(NODE_ADDR)
            if not nl:
                return "no nodes in nodelist"
            return "\n".join(f"  {e['addr']}  sponsor={e['sponsor_addr']}" for e in nl)
        except Exception as e:
            return f"error: {e}"

    if verb == "whoami":
        return f"point: {point_addr}\nnode:  {NODE_ADDR}"

    if verb in ("send_private", "sp"):
        # sp to=1:42/1.2 body=hello
        return step_cmd(f"send_private {rest}")

    if verb in ("read_private", "rp"):
        return step_cmd(f"read_private {rest}")

    return f"unknown command: {verb}\ntype 'help' for list"


HELP_TEXT = """F42BBS MCP commands:
  help                     — this text
  status                   — node status
  whoami                   — your point addr
  points                   — list registered points
  nodes                    — list federated nodes
  genotp [addr]            — generate new OTP (for addr or self)
  publish topic=T body=B   — publish to topic
  get topic=T              — get latest from topic
  request topic=T          — request/digest
  sp to=ADDR body=MSG      — send encrypted private message
  rp from=ADDR             — read private message from addr"""


# ── MCP protocol ──────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "bbs_claim",
        "description": (
            "Claim a session using a one-time passphrase (OTP).\n"
            "OTP is generated server-side via f42bbs-admin or genotp command.\n"
            "Returns session_id (sliding — consumed on each bbs_step call) and point_addr.\n"
            "If session_id is lost, generate a new OTP and claim again."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "otp": {"type": "string", "description": "4-word one-time passphrase"}
            },
            "required": ["otp"]
        }
    },
    {
        "name": "bbs_step",
        "description": (
            "Execute a BBS command in an authenticated session.\n"
            "Consumes current session_id and returns a new one (sliding chain).\n"
            "Lost session_id? Use f42bbs-admin genotp + bbs_claim to re-authenticate.\n"
            "Commands: help, status, whoami, points, nodes, genotp, "
            "publish, get, request, sp (send_private), rp (read_private)"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Current session_id from bbs_claim or previous bbs_step"},
                "cmd":        {"type": "string", "description": "Command to execute, e.g. 'status' or 'publish topic=foo body=bar'"}
            },
            "required": ["session_id", "cmd"]
        }
    }
]

def ok(id_, result):
    return jsonify({"jsonrpc":"2.0","id":id_,"result":result})

def err(id_, code, msg):
    return jsonify({"jsonrpc":"2.0","id":id_,"error":{"code":code,"message":msg}})


@app.route(MCP_PATH, methods=["GET","POST"])
def mcp():
    if request.method == "GET":
        return jsonify({"name":"f42bbs-mcp","version":"1.0","protocol":"2024-11-05"})

    body   = request.get_json(silent=True) or {}
    method = body.get("method","")
    params = body.get("params") or {}
    id_    = body.get("id")

    if method == "initialize":
        return ok(id_, {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name":"f42bbs-mcp","version":"1.0"},
            "capabilities": {"tools":{}}
        })

    if method in ("notifications/initialized",):
        return Response("", status=204)

    if method == "tools/list":
        return ok(id_, {"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name","")
        args = params.get("arguments") or {}

        if name == "bbs_claim":
            otp  = args.get("otp","").strip()
            addr = claim_otp(otp)
            if not addr:
                text = "error: invalid or expired OTP"
            else:
                sid  = create_session(addr)
                text = json.dumps({
                    "session_id":  sid,
                    "point_addr":  addr,
                    "node":        NODE_ADDR,
                    "help":        HELP_TEXT,
                    "note": "Save session_id. Each bbs_step returns a new one. Lost? genotp + claim."
                }, ensure_ascii=False)

        elif name == "bbs_step":
            sid  = args.get("session_id","").strip()
            cmd  = args.get("cmd","").strip()
            addr, new_sid = consume_session(sid)
            if not addr:
                text = "error: invalid or expired session_id — use f42bbs-admin genotp + bbs_claim"
            else:
                result = execute(cmd, addr)
                text = json.dumps({
                    "result":     result,
                    "session_id": new_sid,
                    "point_addr": addr,
                }, ensure_ascii=False)

        else:
            text = f"unknown tool: {name}"

        return ok(id_, {"content":[{"type":"text","text":text}]})

    return err(id_, -32601, f"unknown method: {method}")


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"[bbs-mcp] starting on port {PORT}, path={MCP_PATH}, node={NODE_ADDR}", flush=True)
    app.run(host="0.0.0.0", port=PORT, debug=False)
