"""
F42BBS Bot 1:42/1.0 — dual mode
  1. Direct mode (admin only): genotp, addpoint, listpoints, status, set, reload
  2. Conf mode (plugin gateway): python, fs, charlie, help
"""
from __future__ import annotations
import sys, os, json, time, importlib, traceback, sqlite3
sys.path.insert(0, "/home/f42agent/f42bbs")

from dotenv import load_dotenv
load_dotenv("/home/f42agent/f42bbs/.env")

import crypto, keystore, requests

BOT_ADDR   = "1:42/1.0"
NODE_ADDR  = os.getenv("F42BBS_NODE_ID", "1:42/1")
NODE_URL   = os.getenv("F42BBS_STEP_URL", "http://localhost:8001")
DB_PATH    = os.getenv("F42BBS_DB", "/home/f42agent/f42bbs/f42bbs.db")
DATA_DIR   = os.getenv("F42BBS_DATA_DIR", "/home/f42agent/f42bbs")
POINTS_FILE = os.path.join(DATA_DIR, "points.json")
OTP_FILE    = os.path.join(DATA_DIR, "otps.json")
CONFIG_FILE = os.path.join(DATA_DIR, "bot0_config.json")
PLUGIN_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
POLL_SEC    = 3

keystore.KEYS_FILE    = "/home/f42agent/.f42bbs_keys"
keystore.GENESIS_FILE = "/home/f42agent/.f42bbs_genesis"

keystore.init_keys(BOT_ADDR)
BOT_PRIV, BOT_PUB = keystore.get_x25519(BOT_ADDR)
print(f"[bot.0] {BOT_ADDR} starting, pub={BOT_PUB[:24]}...", flush=True)


# ── config (forward_to, etc.) ─────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        return json.load(open(CONFIG_FILE))
    except Exception:
        return {"forward_to": []}

def _save_config(cfg: dict):
    open(CONFIG_FILE, "w").write(json.dumps(cfg, indent=2))


# ── helpers ───────────────────────────────────────────────────────────────────

def _step(cmd: str) -> str:
    r = requests.post(f"{NODE_URL}/step",
        data=f",{cmd}".encode("utf-8"),
        headers={"Content-Type": "text/plain; charset=utf-8"}, timeout=15)
    parts = r.text.strip().split("%", 2)
    return parts[2].strip() if len(parts) >= 3 else r.text.strip()

def _publish_mykey():
    body = json.dumps({"addr": BOT_ADDR, "pubkey_x25519": BOT_PUB,
                       "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    _step(f"publish topic=net.keys.{BOT_ADDR} body={body}")
    print(f"[bot.0] published net.keys.{BOT_ADDR}", flush=True)

def _hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]

def _load_points() -> dict:
    try: return json.load(open(POINTS_FILE))
    except Exception: return {}

def _save_points(pts: dict):
    open(POINTS_FILE, "w").write(json.dumps(pts, indent=2))

def _is_admin(addr: str) -> bool:
    pts = _load_points()
    return pts.get(addr, {}).get("role") == "admin"

def _get_peer_pub(addr: str) -> str:
    try:
        r = requests.get(f"{NODE_URL}/raw/net.keys.{addr}", timeout=5)
        return json.loads(r.json()["body"])["pubkey_x25519"]
    except Exception:
        return ""

def _send_direct(to_addr: str, text: str):
    peer_pub = _get_peer_pub(to_addr)
    if not peer_pub:
        print(f"[bot.0] no pub for {to_addr}", flush=True)
        return
    ct      = crypto.encrypt(text, peer_pub, BOT_PRIV)
    topic   = crypto.direct_topic(BOT_ADDR, to_addr)
    payload = json.dumps({"from": BOT_ADDR, "to": to_addr,
                          "encrypted": True, "body": ct})
    _step(f"publish topic={topic} body={payload}")

def _conf_send(conf_id: str, conf_key: str, text: str):
    ct      = crypto.conf_encrypt(text, conf_key)
    payload = json.dumps({"from": BOT_ADDR, "conf_id": conf_id,
                          "encrypted": True, "body": ct})
    _step(f"publish topic={conf_id} body={payload}")

def _conf_forward(conf_id: str, conf_key: str, text: str):
    """Forward message to all admin points."""
    cfg  = _load_config()
    pts  = _load_points()
    fwd  = cfg.get("forward_to", [])
    # If no explicit forward_to — send to all admin points
    targets = fwd if fwd else [a for a, v in pts.items() if v.get("role") == "admin"]
    for addr in targets:
        if addr == BOT_ADDR: continue
        _send_direct(addr, f"[fwd from {conf_id}] {text}")


# ── OTP helpers ───────────────────────────────────────────────────────────────

def _genotp(point_addr: str, ttl: int = 3600) -> str:
    import random, hashlib
    words = [
        "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel",
        "india","juliet","kilo","lima","mike","november","oscar","papa",
        "quebec","romeo","sierra","tango","uniform","victor","whiskey",
        "xray","yankee","zulu","red","blue","green","black","white",
        "sun","moon","star","cloud","river","stone","fire","wind",
        "oak","pine","hawk","wolf","bear","fox","swift","calm",
    ]
    otp = " ".join(random.choices(words, k=4))
    try:
        otps = json.load(open(OTP_FILE))
    except Exception:
        otps = {}
    otps = {h: v for h, v in otps.items()
            if v.get("addr") != point_addr and v.get("exp", 0) > int(time.time())}
    h = hashlib.sha256(otp.encode()).hexdigest()
    otps[h] = {"addr": point_addr, "exp": int(time.time()) + ttl}
    open(OTP_FILE, "w").write(json.dumps(otps, indent=2))
    return otp


# ── plugin loader ─────────────────────────────────────────────────────────────

_plugins: dict = {}

def load_plugins():
    global _plugins
    _plugins = {}
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    sys.path.insert(0, PLUGIN_DIR)
    for fname in sorted(os.listdir(PLUGIN_DIR)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        name = fname[:-3]
        try:
            mod = importlib.import_module(name)
            importlib.reload(mod)
            _plugins[name] = mod
            cmds = list(getattr(mod, "COMMANDS", {}).keys())
            print(f"[bot.0] plugin {name}: {cmds}", flush=True)
        except Exception as e:
            print(f"[bot.0] plugin {name} error: {e}", flush=True)


# ── DIRECT MODE — admin commands ──────────────────────────────────────────────

def handle_direct(msg: str, from_addr: str):
    """Handle direct message from admin point."""
    parts = msg.strip().split(None, 2)
    cmd   = parts[0].lower() if parts else ""
    arg1  = parts[1] if len(parts) > 1 else ""
    arg2  = parts[2] if len(parts) > 2 else ""

    if cmd == "help":
        return (
            "Direct commands (admin only):\n"
            "  genotp <addr>              — generate OTP for point\n"
            "  addpoint <label> [admin]   — create new point\n"
            "  listpoints                 — list all points\n"
            "  listnodes                  — list federated nodes\n"
            "  status                     — node status\n"
            "  set forward_to=<addr>      — set mail forward target\n"
            "  set forward_to=clear       — clear forward list\n"
            "  reload                     — reload plugins\n"
            "  help                       — this text"
        )

    if cmd == "genotp":
        addr = arg1.strip()
        if not addr:
            return "usage: genotp <addr>"
        pts = _load_points()
        if addr not in pts:
            return f"error: point {addr} not found"
        otp = _genotp(addr)
        return f"OTP for {addr} (1h):\n  {otp}\nbbs_claim(otp='{otp}')"

    if cmd == "addpoint":
        label = arg1.strip() or "point"
        role  = "admin" if "admin" in arg2.lower() else "user"
        # Find next addr
        pts    = _load_points()
        prefix = NODE_ADDR + "."
        used   = [int(a[len(prefix):]) for a in pts
                  if a.startswith(prefix) and a[len(prefix):].isdigit()]
        n      = max(used, default=0) + 1
        addr   = f"{prefix}{n}"
        priv, pub = crypto.keypair_generate()
        pts[addr] = {"x25519_pub": pub, "x25519_priv": priv,
                     "label": label, "role": role,
                     "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _save_points(pts)
        # Publish pub
        body = json.dumps({"addr": addr, "pubkey_x25519": pub,
                           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        _step(f"publish topic=net.keys.{addr} body={body}")
        otp = _genotp(addr)
        return (
            f"Point created: {addr}\n"
            f"  label: {label}\n"
            f"  role:  {role}\n"
            f"  OTP:   {otp}\n"
            f"bbs_claim(otp='{otp}')"
        )

    if cmd == "listpoints":
        pts = _load_points()
        if not pts:
            return "no points registered"
        lines = ["Points:"]
        for addr, v in sorted(pts.items()):
            lines.append(f"  {addr}  {v.get('role','?'):6}  {v.get('label','?')}")
        return "\n".join(lines)

    if cmd == "listnodes":
        try:
            nl = keystore.get_nodelist(NODE_ADDR)
            if not nl:
                return "no nodes"
            return "\n".join(f"  {e['addr']}  sponsor={e['sponsor_addr']}" for e in nl)
        except Exception as e:
            return f"error: {e}"

    if cmd == "status":
        try:
            con  = sqlite3.connect(DB_PATH)
            msgs  = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            peers = con.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
            con.close()
            size = os.path.getsize(DB_PATH)
            return (
                f"Node:  {NODE_ADDR}\n"
                f"Bot:   {BOT_ADDR}\n"
                f"DB:    {size//1024}KB, {msgs} msgs, {peers} peers\n"
                f"Time:  {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
            )
        except Exception as e:
            return f"error: {e}"

    if cmd == "set":
        cfg = _load_config()
        if arg1.startswith("forward_to="):
            val = arg1[len("forward_to="):].strip()
            if val == "clear":
                cfg["forward_to"] = []
                _save_config(cfg)
                return "forward_to cleared"
            targets = [a.strip() for a in val.split(",") if a.strip()]
            cfg["forward_to"] = targets
            _save_config(cfg)
            return f"forward_to set to: {targets}"
        return f"unknown set: {arg1}"

    if cmd == "reload":
        load_plugins()
        return f"plugins reloaded: {list(_plugins.keys())}"

    return f"unknown command: {cmd}\ntype 'help' for list"


# ── CONF MODE — plugin gateway ────────────────────────────────────────────────

def handle_conf(msg: str, from_addr: str, conf_id: str, conf_key: str) -> str:
    # Plugin commands require "!" prefix to avoid noise in conf
    if not msg.strip().startswith("!"):
        return ""
    msg = msg.strip()[1:].strip()
    parts = msg.split(None, 2)
    if not parts:
        return ""
    plugin_name = parts[0].lower()
    verb        = parts[1].lower() if len(parts) > 1 else "help"
    args        = parts[2] if len(parts) > 2 else ""

    if plugin_name == "help":
        lines = ["Plugins: " + ", ".join(_plugins.keys()),
                 "Format:  <plugin> <verb> [args]",
                 "Example: python exec cmd=print('hello')"]
        for pname, mod in _plugins.items():
            lines.append(f"  {pname}: {getattr(mod,'HELP','')}")
        return "\n".join(lines)

    if plugin_name not in _plugins:
        return f"unknown plugin: {plugin_name}. Type 'help' for list."

    mod      = _plugins[plugin_name]
    commands = getattr(mod, "COMMANDS", {})
    if verb not in commands:
        return f"unknown verb: {verb}. {plugin_name} commands: {list(commands.keys())}"

    ctx = {"from_addr": from_addr, "conf_id": conf_id,
           "bot_addr": BOT_ADDR, "node_url": NODE_URL, "step": _step}
    try:
        return commands[verb](args, ctx)
    except Exception as e:
        return f"error in {plugin_name}.{verb}: {e}"


# ── seen tracking ─────────────────────────────────────────────────────────────

_seen_direct: dict[str, str] = {}
_seen_conf:   dict[str, str] = {}


# ── poll direct messages ──────────────────────────────────────────────────────

def poll_direct():
    """Check direct messages from admin points."""
    pts = _load_points()
    admin_addrs = [a for a, v in pts.items() if v.get("role") == "admin"]

    for from_addr in admin_addrs:
        topic = crypto.direct_topic(from_addr, BOT_ADDR)
        con   = sqlite3.connect(DB_PATH)
        cur   = con.execute(
            "SELECT raw FROM messages WHERE topic=? ORDER BY created_at DESC LIMIT 5",
            (topic,))
        rows  = cur.fetchall()
        con.close()

        for (raw_str,) in rows:
            try:
                env     = json.loads(raw_str)
                payload = json.loads(env.get("body", "{}"))
                if payload.get("conf_invite"): continue  # handled separately
                if payload.get("from") == BOT_ADDR: break  # own msg
                ct = payload.get("body", "")
                if not ct: continue
                sender_pub = _get_peer_pub(from_addr)
                if not sender_pub: continue
                pt = crypto.decrypt(ct, BOT_PRIV, sender_pub)
                h  = _hash(pt)
                if _seen_direct.get(from_addr) == h: break
                _seen_direct[from_addr] = h
                print(f"[bot.0] direct from {from_addr}: {pt[:60]}", flush=True)
                reply = handle_direct(pt, from_addr)
                _send_direct(from_addr, reply)
                break
            except Exception:
                continue


# ── poll conferences ──────────────────────────────────────────────────────────

def get_my_confs() -> list[tuple[str, str]]:
    ks = keystore._load()
    result = []
    for key, val in ks.items():
        if key == "confs" and isinstance(val, dict):
            for conf_id, conf_key in val.items():
                result.append((conf_id, conf_key))
    return result

def poll_conf(conf_id: str, conf_key: str):
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "SELECT raw FROM messages WHERE topic=? ORDER BY created_at DESC LIMIT 20",
        (conf_id,))
    rows = cur.fetchall()
    con.close()

    for (raw_str,) in rows:
        try:
            env     = json.loads(raw_str)
            payload = json.loads(env.get("body", "{}"))
            ct      = payload.get("body", "")
            if not ct: continue
            try:
                pt = crypto.conf_decrypt(ct, conf_key)
            except Exception:
                continue
            h = _hash(pt)
            if _seen_conf.get(conf_id) == h: break
            _seen_conf[conf_id] = h
            sender = payload.get("from", "")
            if sender == BOT_ADDR: break
            print(f"[bot.0] conf [{conf_id[:12]}] {sender}: {pt[:60]}", flush=True)
            reply = handle_conf(pt, sender, conf_id, conf_key)
            if reply:
                _conf_send(conf_id, conf_key, f"[bot.0] {reply}")
            break
        except Exception as e:
            print(f"[bot.0] conf error: {e}", flush=True)


# ── auto-accept (admin invites only) ─────────────────────────────────────────

def check_invites():
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "SELECT DISTINCT topic FROM messages WHERE topic LIKE 'direct-%'")
    topics = [r[0] for r in cur.fetchall()]
    con.close()

    for topic in topics:
        con = sqlite3.connect(DB_PATH)
        cur = con.execute(
            "SELECT raw FROM messages WHERE topic=? ORDER BY created_at DESC LIMIT 5",
            (topic,))
        rows = cur.fetchall()
        con.close()

        for (raw_str,) in rows:
            try:
                env     = json.loads(raw_str)
                payload = json.loads(env.get("body", "{}"))
                if not payload.get("conf_invite"): continue
                from_addr = payload.get("from", "")
                if not from_addr: continue

                # Admin only
                if not _is_admin(from_addr):
                    print(f"[bot.0] reject invite from {from_addr} — not admin", flush=True)
                    continue

                sender_pub = _get_peer_pub(from_addr)
                if not sender_pub: continue
                try:
                    pt     = crypto.decrypt(payload["body"], BOT_PRIV, sender_pub)
                    invite = json.loads(pt)
                except Exception:
                    continue
                if invite.get("type") != "conf_invite": continue

                conf_id  = invite["conf_id"]
                conf_key = invite["conf_key"]

                # Already accepted?
                ks    = keystore._load()
                confs = ks.get("confs", {})
                if conf_id in confs: continue

                keystore.save_conf_key(BOT_ADDR, conf_key)
                keystore.save_conf_key(NODE_ADDR, conf_key)
                print(f"[bot.0] accepted conf {conf_id} from {from_addr} (admin)", flush=True)
                _conf_send(conf_id, conf_key,
                           f"[bot.0] joined. Plugins: {list(_plugins.keys())}. "
                           f"Type 'help' for commands.")
                _seen_conf[conf_id] = ""
            except Exception:
                continue


# ── forward 1:42/1 mail → admin points ───────────────────────────────────────

_seen_node_mail: dict[str, str] = {}

def poll_node_mail():
    """Forward direct messages sent to node addr (1:42/1) to admin points."""
    cfg  = _load_config()
    pts  = _load_points()
    targets = cfg.get("forward_to") or \
              [a for a, v in pts.items() if v.get("role") == "admin"]
    if not targets:
        return

    # Check direct topics addressed to NODE_ADDR
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "SELECT DISTINCT topic FROM messages WHERE topic LIKE 'direct-%'")
    topics = [r[0] for r in cur.fetchall()]
    con.close()

    for topic in topics:
        con = sqlite3.connect(DB_PATH)
        cur = con.execute(
            "SELECT raw FROM messages WHERE topic=? ORDER BY created_at DESC LIMIT 3",
            (topic,))
        rows = cur.fetchall()
        con.close()

        for (raw_str,) in rows:
            try:
                env     = json.loads(raw_str)
                payload = json.loads(env.get("body", "{}"))
                to_addr = payload.get("to", "")
                if to_addr != NODE_ADDR: continue  # not for node addr
                from_addr = payload.get("from", "")
                if from_addr == BOT_ADDR: continue

                h = _hash(raw_str)
                if _seen_node_mail.get(topic) == h: break
                _seen_node_mail[topic] = h

                print(f"[bot.0] node mail from {from_addr} → forwarding to {targets}", flush=True)
                for target in targets:
                    _send_direct(target,
                                 f"[mail to {NODE_ADDR} from {from_addr}]\n{payload.get('body','')}")
                break
            except Exception:
                continue


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    _publish_mykey()
    load_plugins()
    print(f"[bot.0] ready — direct(admin) + conf(plugins) + forward({NODE_ADDR}→admins)",
          flush=True)

    while True:
        try:
            check_invites()
            poll_direct()
            poll_node_mail()
            for conf_id, conf_key in get_my_confs():
                poll_conf(conf_id, conf_key)
        except Exception as e:
            print(f"[bot.0] loop error: {e}", flush=True)
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
