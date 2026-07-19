"""Ops plugin — status, keys."""
import json, os, sys, datetime
sys.path.insert(0, "/home/f42agent/f42bbs")
import keystore

HELP = {
    "status": "status — node status (uptime, db size, peers)",
    "keys":   "keys — show node public keys",
    "ping":   "ping — check bot is alive",
}

def _status(args, ctx):
    import sqlite3
    ks_file = ctx["keystore_file"]
    db_path = os.getenv("F42BBS_DB", "/home/f42agent/f42bbs/f42bbs.db")
    lines = [f"Node: {ctx['node_addr']}",
             f"Bot:  {ctx['bot_addr']}",
             f"Time: {datetime.datetime.utcnow().isoformat()}Z"]
    try:
        size = os.path.getsize(db_path)
        con = sqlite3.connect(db_path)
        msgs = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        peers = con.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
        con.close()
        lines += [f"DB:   {size//1024}KB, {msgs} messages, {peers} peers"]
    except Exception as e:
        lines.append(f"DB:   error ({e})")
    return "\n".join(lines)

def _keys(args, ctx):
    ks = keystore._load()
    ed = ks.get("ed25519", {}).get("pub", "?")
    x  = ks.get("x25519",  {}).get("pub", "?")
    return f"Node {ctx['node_addr']}:\n  ed25519: {ed}\n  x25519:  {x}"

def _ping(args, ctx):
    return f"pong from {ctx['bot_addr']}"

COMMANDS = {
    "status": _status,
    "keys":   _keys,
    "ping":   _ping,
}
