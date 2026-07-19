"""
F42BBS Bot — 1:42/1.0
Local-only system point. Reads direct topic, routes commands to plugins, replies.
Never accessible from outside — inbound traffic to 1:42/1.0 is dropped.
"""
from __future__ import annotations
import sys, os, json, time, traceback, importlib, base64
sys.path.insert(0, "/home/f42agent/f42bbs")

from dotenv import load_dotenv
load_dotenv("/home/f42agent/f42bbs/.env")

import crypto, keystore, signing, requests

BOT_ADDR   = "1:42/1.0"
NODE_ADDR  = "1:42/1"
NODE_URL   = "http://localhost:8001"
POLL_SEC   = 3
PLUGIN_DIR = os.path.join(os.path.dirname(__file__), "plugins")

keystore.KEYS_FILE    = "/home/f42agent/.f42bbs_keys"
keystore.GENESIS_FILE = "/home/f42agent/.f42bbs_genesis"

# Init bot keypair
keystore.init_keys(BOT_ADDR)
BOT_PRIV, BOT_PUB = keystore.get_x25519(BOT_ADDR)

print(f"[bot] {BOT_ADDR} starting, pub={BOT_PUB[:24]}...", flush=True)


# ── step helpers ──────────────────────────────────────────────────────────────

def step(cmd: str, otp: str = "") -> tuple:
    data = (f"%{otp}% {cmd}" if otp else f",{cmd}").encode()
    r = requests.post(f"{NODE_URL}/step", data=data,
                      headers={"Content-Type": "text/plain; charset=utf-8"},
                      timeout=10)
    r.raise_for_status()
    parts = r.text.strip().split("%", 2)
    return (parts[1], parts[2].strip()) if len(parts) >= 3 else ("", r.text.strip())

def raw(topic: str) -> dict:
    r = requests.get(f"{NODE_URL}/raw/{topic}", timeout=10)
    return r.json() if r.status_code == 200 else {}


# ── crypto helpers ────────────────────────────────────────────────────────────

def get_peer_pub(addr: str) -> str:
    """Get x25519 pub for addr from net.keys.<addr>."""
    env = raw(f"net.keys.{addr}")
    if not env:
        return ""
    try:
        body = json.loads(env.get("body", "{}"))
        return body.get("pubkey_x25519", "")
    except Exception:
        return ""

def send_reply(to_addr: str, text: str, otp: str) -> str:
    peer_pub = get_peer_pub(to_addr)
    if not peer_pub:
        print(f"[bot] no pub for {to_addr}", flush=True)
        return otp
    ct = crypto.encrypt(text, peer_pub, BOT_PRIV)
    topic = crypto.direct_topic(BOT_ADDR, to_addr)
    payload = json.dumps({"from": BOT_ADDR, "to": to_addr, "encrypted": True, "body": ct})
    otp, _ = step(f"publish topic={topic} body={payload}", otp)
    return otp

def read_direct(from_addr: str) -> str | None:
    """Read and decrypt latest direct message from from_addr."""
    topic = crypto.direct_topic(BOT_ADDR, from_addr)
    env = raw(topic)
    if not env:
        return None
    try:
        payload = json.loads(env.get("body", "{}"))
        # Echo filter: skip own messages
        if payload.get("from") == BOT_ADDR:
            return None
        ct = payload.get("body", "")
        if not ct:
            return None
        sender_pub = get_peer_pub(from_addr)
        if not sender_pub:
            return None
        return crypto.decrypt(ct, BOT_PRIV, sender_pub)
    except Exception:
        return None


# ── plugin loader ─────────────────────────────────────────────────────────────

_plugins: dict = {}

def load_plugins():
    global _plugins
    _plugins = {}
    sys.path.insert(0, PLUGIN_DIR)
    for fname in sorted(os.listdir(PLUGIN_DIR)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        name = fname[:-3]
        try:
            mod = importlib.import_module(name)
            importlib.reload(mod)
            for cmd, handler in getattr(mod, "COMMANDS", {}).items():
                _plugins[cmd.lower()] = (handler, getattr(mod, "HELP", {}).get(cmd, ""))
            print(f"[bot] plugin {name}: {list(getattr(mod, 'COMMANDS', {}).keys())}", flush=True)
        except Exception as e:
            print(f"[bot] plugin {name} error: {e}", flush=True)

def route(cmd: str, args: list, from_addr: str, otp: str) -> tuple[str, str]:
    """Route command to plugin. Returns (reply_text, otp)."""
    key = cmd.lower()
    if key == "help":
        lines = ["F42BBS Bot commands:"]
        for c, (_, h) in sorted(_plugins.items()):
            lines.append(f"  {c} — {h}" if h else f"  {c}")
        return "\n".join(lines), otp
    if key in _plugins:
        handler, _ = _plugins[key]
        try:
            ctx = {"from_addr": from_addr, "otp": otp, "step": step,
                   "raw": raw, "bot_addr": BOT_ADDR, "node_addr": NODE_ADDR,
                   "keystore_file": keystore.KEYS_FILE}
            reply = handler(args, ctx)
            return str(reply), ctx.get("otp", otp)
        except Exception as e:
            return f"error: {e}\n{traceback.format_exc()[:200]}", otp
    return f"unknown command: {cmd}\ntype 'help' for list", otp


# ── seen message dedup ────────────────────────────────────────────────────────

_seen: dict[str, str] = {}  # addr → last_plaintext_hash

def _hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]


# ── main loop ─────────────────────────────────────────────────────────────────

def get_known_points() -> list:
    """Return list of registered point addrs from keystore."""
    data = keystore._load()
    return list(data.get("points", {}).values())

def main():
    load_plugins()
    print(f"[bot] ready, polling every {POLL_SEC}s", flush=True)

    otp = ""
    while True:
        try:
            for point_addr in get_known_points():
                if point_addr == BOT_ADDR:
                    continue
                msg = read_direct(point_addr)
                if msg is None:
                    continue
                h = _hash(msg)
                if _seen.get(point_addr) == h:
                    continue
                _seen[point_addr] = h
                print(f"[bot] msg from {point_addr}: {msg[:60]}", flush=True)

                parts = msg.strip().split(None, 1)
                cmd  = parts[0] if parts else ""
                args = parts[1].split() if len(parts) > 1 else []
                if not cmd:
                    continue

                reply, otp = route(cmd, args, point_addr, otp)
                otp = send_reply(point_addr, reply, otp)

        except Exception as e:
            print(f"[bot] loop error: {e}", flush=True)
            otp = ""

        time.sleep(POLL_SEC)

if __name__ == "__main__":
    main()
