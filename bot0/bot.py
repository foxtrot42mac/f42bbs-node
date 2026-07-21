"""
F42BBS Bot 1:42/1.0 — plugin gateway
Polls conferences it's member of, routes commands to plugins, replies.

Command format in conf:
  <plugin> <verb> <args>

Examples:
  python write file=/home/doo/test.py content=print("hello")
  python exec file=/home/doo/test.py
  charlie exec cmd=ls -la /home/doo
  fs read path=/home/doo/notes.txt
  fs list path=/home/doo
  help
"""
from __future__ import annotations
import sys, os, json, time, importlib, traceback, sqlite3, base64
sys.path.insert(0, "/home/f42agent/f42bbs")

from dotenv import load_dotenv
load_dotenv("/home/f42agent/f42bbs/.env")

import crypto, keystore, requests

BOT_ADDR   = "1:42/1.0"
NODE_ADDR  = os.getenv("F42BBS_NODE_ID", "1:42/1")
NODE_URL   = os.getenv("F42BBS_STEP_URL", "http://localhost:8001")
DB_PATH    = os.getenv("F42BBS_DB", "/home/f42agent/f42bbs/f42bbs.db")
POLL_SEC   = 3
PLUGIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")

keystore.KEYS_FILE    = "/home/f42agent/.f42bbs_keys"
keystore.GENESIS_FILE = "/home/f42agent/.f42bbs_genesis"

# Init bot keypair
keystore.init_keys(BOT_ADDR)
BOT_PRIV, BOT_PUB = keystore.get_x25519(BOT_ADDR)
print(f"[bot.0] {BOT_ADDR} starting, pub={BOT_PUB[:24]}...", flush=True)

# Publish bot pub key
def _publish_mykey():
    body = json.dumps({"addr": BOT_ADDR, "pubkey_x25519": BOT_PUB,
                       "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    requests.post(f"{NODE_URL}/step",
        data=f",publish topic=net.keys.{BOT_ADDR} body={body}".encode(),
        headers={"Content-Type": "text/plain"}, timeout=10)
    print(f"[bot.0] published net.keys.{BOT_ADDR}", flush=True)

_publish_mykey()


# ── helpers ───────────────────────────────────────────────────────────────────

def _step(cmd: str) -> str:
    r = requests.post(f"{NODE_URL}/step",
        data=f",{cmd}".encode("utf-8"),
        headers={"Content-Type": "text/plain; charset=utf-8"}, timeout=15)
    parts = r.text.strip().split("%", 2)
    return parts[2].strip() if len(parts) >= 3 else r.text.strip()


def _conf_send(conf_id: str, conf_key: str, text: str):
    ct      = crypto.conf_encrypt(text, conf_key)
    payload = json.dumps({"from": BOT_ADDR, "conf_id": conf_id,
                          "encrypted": True, "body": ct})
    _step(f"publish topic={conf_id} body={payload}")


def _hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]


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


def route(plugin_name: str, verb: str, args: str, ctx: dict) -> str:
    if plugin_name == "help":
        lines = ["F42BBS Bot 1:42/1.0 — available plugins:"]
        for pname, mod in _plugins.items():
            help_txt = getattr(mod, "HELP", "")
            lines.append(f"  {pname}: {help_txt}")
        lines.append("\nFormat: <plugin> <verb> <args>")
        lines.append("Example: python exec cmd=print('hello')")
        return "\n".join(lines)

    if plugin_name not in _plugins:
        return f"unknown plugin: {plugin_name}\ntype 'help' for list"

    mod = _plugins[plugin_name]
    commands = getattr(mod, "COMMANDS", {})
    if verb not in commands:
        avail = list(commands.keys())
        return f"unknown verb: {verb}\n{plugin_name} commands: {avail}"

    try:
        return commands[verb](args, ctx)
    except Exception as e:
        return f"error in {plugin_name}.{verb}: {e}\n{traceback.format_exc()[:300]}"


# ── conference poller ─────────────────────────────────────────────────────────

_seen: dict[str, str] = {}  # conf_id → last_msg_hash

def get_my_confs() -> list[tuple[str, str]]:
    """Return list of (conf_id, conf_key) bot is member of."""
    ks = keystore._load()
    result = []
    for key, val in ks.items():
        if key.startswith("conf_") or key == "confs":
            confs = val if isinstance(val, dict) else {}
            for conf_id, conf_key in confs.items():
                result.append((conf_id, conf_key))
    return result


def poll_conf(conf_id: str, conf_key: str):
    """Check conference for new messages, route commands."""
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
            if not ct:
                continue
            try:
                pt = crypto.conf_decrypt(ct, conf_key)
            except Exception:
                continue

            h = _hash(pt)
            if _seen.get(conf_id) == h:
                break  # already processed this and everything older
            _seen[conf_id] = h

            sender = payload.get("from", "")
            if sender == BOT_ADDR:
                break  # own message, stop

            print(f"[bot.0] [{conf_id}] from {sender}: {pt[:60]}", flush=True)

            # Parse command: "<plugin> <verb> [args]"
            parts = pt.strip().split(None, 2)
            if not parts:
                break
            plugin_name = parts[0].lower()
            verb        = parts[1].lower() if len(parts) > 1 else "help"
            args        = parts[2] if len(parts) > 2 else ""

            ctx = {
                "from_addr": sender,
                "conf_id":   conf_id,
                "bot_addr":  BOT_ADDR,
                "node_url":  NODE_URL,
                "step":      _step,
            }

            reply = route(plugin_name, verb, args, ctx)
            _conf_send(conf_id, conf_key, f"[bot.0] {reply}")
            break  # process one message per poll

        except Exception as e:
            print(f"[bot.0] poll error: {e}", flush=True)


# ── main ──────────────────────────────────────────────────────────────────────

def check_invites():
    """Auto-accept conference invites sent to bot."""
    import requests as _rq_ai
    try:
        r = _rq_ai.get(f"{NODE_URL}/raw/net.keys.{BOT_ADDR}", timeout=5)
        # Check all direct topics for conf_invites
        con = sqlite3.connect(DB_PATH)
        cur = con.execute(
            "SELECT DISTINCT topic FROM messages WHERE topic LIKE 'direct-%' ORDER BY created_at DESC"
        )
        topics = [row[0] for row in cur.fetchall()]
        con.close()
        for topic in topics:
            con = sqlite3.connect(DB_PATH)
            cur2 = con.execute(
                "SELECT raw FROM messages WHERE topic=? ORDER BY created_at DESC LIMIT 5",
                (topic,))
            rows = cur2.fetchall()
            con.close()
            for (raw_str,) in rows:
                try:
                    env = json.loads(raw_str)
                    payload = json.loads(env.get("body","{}"))
                    if not payload.get("conf_invite"): continue
                    from_addr = payload.get("from","")
                    if not from_addr: continue
                    ct = payload.get("body","")
                    # Get sender pub
                    r_pub = _rq_ai.get(f"{NODE_URL}/raw/net.keys.{from_addr}", timeout=5)
                    sender_pub = json.loads(r_pub.json()["body"])["pubkey_x25519"]
                    pt = crypto.decrypt(ct, BOT_PRIV, sender_pub)
                    invite = json.loads(pt)
                    if invite.get("type") != "conf_invite": continue
                    conf_id = invite["conf_id"]
                    # Check if already accepted
                    ks = keystore._load()
                    confs = ks.get("confs", {})
                    if conf_id in confs: continue
                    # Accept
                    keystore.save_conf_key(BOT_ADDR, invite["conf_key"])
                    keystore.save_conf_key(NODE_ADDR, invite["conf_key"])
                    print(f"[bot.0] auto-accepted conf {conf_id} from {from_addr}", flush=True)
                    # Send welcome
                    _conf_send(conf_id, invite["conf_key"],
                               f"[bot.0] joined. Plugins: {list(_plugins.keys())}. Type 'help' for commands.")
                except Exception:
                    continue
    except Exception as e:
        print(f"[bot.0] check_invites error: {e}", flush=True)


def main():
    load_plugins()
    print(f"[bot.0] ready, polling every {POLL_SEC}s", flush=True)
    while True:
        try:
            check_invites()
            for conf_id, conf_key in get_my_confs():
                poll_conf(conf_id, conf_key)
        except Exception as e:
            print(f"[bot.0] loop error: {e}", flush=True)
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
