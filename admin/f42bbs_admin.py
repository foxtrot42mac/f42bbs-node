#!/usr/bin/env python3
"""
f42bbs-admin — CLI for F42BBS node management
Usage:
  f42bbs-admin addpoint [--label NAME]   → create point, print addr + priv_key
  f42bbs-admin genotp <addr>             → generate OTP for point, print to stdout
  f42bbs-admin listpoints                → list registered points
  f42bbs-admin listnodes                 → list federated nodes
  f42bbs-admin status                    → node status
"""
from __future__ import annotations
import sys, os, json, argparse, time, secrets, hashlib, sqlite3

DATA_DIR    = os.getenv("F42BBS_DATA_DIR",  "/var/lib/f42bbs")
NODE_ADDR   = os.getenv("F42BBS_NODE_ID",   "1:42/1")
DB_PATH     = os.getenv("F42BBS_DB",        "/home/f42agent/f42bbs/f42bbs.db")
KEYS_FILE   = os.getenv("F42BBS_KEYS",      "/home/f42agent/.f42bbs_keys")
GENESIS_FILE= os.getenv("F42BBS_GENESIS",   "/home/f42agent/.f42bbs_genesis")
POINTS_FILE = os.path.join(DATA_DIR, "points.json")
OTP_FILE    = os.path.join(DATA_DIR, "otps.json")

sys.path.insert(0, "/home/f42agent/f42bbs")

def _load(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return {}

def _save(path, data):
    import stat
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f: json.dump(data, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

def _now(): return int(time.time())

def _otp_hash(otp): return hashlib.sha256(otp.encode()).hexdigest()


def cmd_addpoint(args):
    """Create new point on this node. Node holds keypair."""
    import keystore, crypto
    keystore.KEYS_FILE    = KEYS_FILE
    keystore.GENESIS_FILE = GENESIS_FILE

    # Find next addr
    points = _load(POINTS_FILE)
    prefix = NODE_ADDR + "."
    used   = [int(a[len(prefix):]) for a in points
               if a.startswith(prefix) and a[len(prefix):].isdigit()]
    n    = max(used, default=0) + 1
    addr = f"{prefix}{n}"

    # Generate keypair — stored on node
    priv, pub = crypto.keypair_generate()

    points[addr] = {
        "x25519_pub":  pub,
        "x25519_priv": priv,   # stored on node
        "label":       args.label or addr,
        "created_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _save(POINTS_FILE, points)

    # Publish pub to net.keys.<addr> via step
    try:
        import requests as _req
        step_url = os.getenv("F42BBS_STEP_URL", "http://localhost:8001")
        body = json.dumps({"addr": addr, "pubkey_x25519": pub,
                           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        r = _req.post(f"{step_url}/step",
                      data=f",publish topic=net.keys.{addr} body={body}".encode(),
                      headers={"Content-Type": "text/plain"}, timeout=10)
        pub_ok = "published" in r.text
    except Exception as e:
        pub_ok = False

    # Generate initial OTP
    otp = _genotp(addr)

    print(f"Point created: {addr}")
    print(f"  label:   {args.label or addr}")
    print(f"  pub:     {pub[:24]}...")
    print(f"  net.keys published: {pub_ok}")
    print()
    print(f"Initial OTP (valid 5 min):")
    print(f"  {otp}")
    print()
    print(f"Use in claude.ai: bbs_claim(otp='{otp}')")


def _genotp(addr: str, ttl: int = 300) -> str:
    import random
    words = [
        "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel",
        "india","juliet","kilo","lima","mike","november","oscar","papa",
        "quebec","romeo","sierra","tango","uniform","victor","whiskey",
        "xray","yankee","zulu","red","blue","green","black","white",
        "sun","moon","star","cloud","river","stone","fire","wind",
        "oak","pine","hawk","wolf","bear","fox","swift","calm",
    ]
    otp = " ".join(random.choices(words, k=4))
    otps = _load(OTP_FILE)
    otps = {h: v for h, v in otps.items()
            if v.get("addr") != addr and v.get("exp", 0) > _now()}
    otps[_otp_hash(otp)] = {"addr": addr, "exp": _now() + ttl}
    _save(OTP_FILE, otps)
    return otp


def cmd_genotp(args):
    points = _load(POINTS_FILE)
    if args.addr not in points:
        print(f"error: point {args.addr} not found", file=sys.stderr)
        print(f"registered points: {list(points.keys())}", file=sys.stderr)
        sys.exit(1)
    otp = _genotp(args.addr)
    print(f"OTP for {args.addr} (valid 5 min, single use):")
    print(f"  {otp}")
    print()
    print(f"Use: bbs_claim(otp='{otp}')")


def cmd_listpoints(args):
    points = _load(POINTS_FILE)
    if not points:
        print("no points registered")
        return
    print(f"{'addr':<20} {'label':<20} {'created'}")
    print("-" * 60)
    for addr, v in sorted(points.items()):
        print(f"{addr:<20} {v.get('label','?'):<20} {v.get('created_at','?')}")


def cmd_listnodes(args):
    try:
        import keystore
        keystore.KEYS_FILE    = KEYS_FILE
        keystore.GENESIS_FILE = GENESIS_FILE
        nl = keystore.get_nodelist(NODE_ADDR)
        if not nl:
            print("no nodes in nodelist")
            return
        print(f"{'addr':<15} {'ed25519':<24} sponsor")
        print("-" * 60)
        for e in nl:
            print(f"{e['addr']:<15} {e['ed25519_pub'][:22]:<24} {e['sponsor_addr']}")
    except Exception as ex:
        print(f"error: {ex}")


def cmd_status(args):
    print(f"Node:     {NODE_ADDR}")
    print(f"Data dir: {DATA_DIR}")
    print(f"Keys:     {KEYS_FILE}")
    try:
        size = os.path.getsize(DB_PATH)
        con  = sqlite3.connect(DB_PATH)
        msgs  = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        peers = con.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
        con.close()
        print(f"DB:       {DB_PATH} ({size//1024}KB, {msgs} msgs, {peers} peers)")
    except Exception as e:
        print(f"DB:       error ({e})")
    pts = _load(POINTS_FILE)
    print(f"Points:   {len(pts)}")
    otps = {h: v for h, v in _load(OTP_FILE).items() if v.get("exp",0) > _now()}
    print(f"Live OTPs: {len(otps)}")


def cmd_admit(args):
    """Admit a pending node into the nodelist (root signs the entry)."""
    pending = _load(os.path.join(DATA_DIR, "pending.json"))
    if not pending:
        print("no pending admission requests")
        return

    if not args.addr:
        print("Pending requests:")
        for addr, v in pending.items():
            print(f"  {addr}  label={v.get('label','?')}  peer={v.get('peer_url','?')}  ts={v.get('ts','?')}")
        return

    addr = args.addr
    if addr not in pending:
        print(f"error: {addr} not in pending")
        print(f"pending: {list(pending.keys())}")
        sys.exit(1)

    entry = pending[addr]

    sys.path.insert(0, "/opt/f42bbs/core")
    import keystore, signing
    keystore.KEYS_FILE    = KEYS_FILE
    keystore.GENESIS_FILE = GENESIS_FILE

    # Root signs the entry
    root_priv, root_pub = keystore.get_ed25519(NODE_ADDR)

    connectors = entry.get("connectors", [])
    if not connectors and entry.get("peer_url"):
        connectors = [entry["peer_url"]]
    signed_entry = signing.sign_nodelist_entry({
        "addr":         addr,
        "ed25519_pub":  entry["ed25519_pub"],
        "x25519_pub":   entry["x25519_pub"],
        "connectors":   connectors,
        "label":        entry.get("label", addr),
        "sponsor_addr": NODE_ADDR,
    }, root_priv)

    # Verify chain
    data = keystore._load()
    nodelist = data.get("nodelist", [])
    genesis  = keystore.load_genesis()
    test_nl  = [e for e in nodelist if e.get("addr") != addr] + [signed_entry]

    ok = signing.verify_nodelist_chain(signed_entry, test_nl, genesis)
    if not ok:
        print(f"error: chain verify failed for {addr}")
        sys.exit(1)

    # Save to nodelist
    data["nodelist"] = test_nl
    keystore._save(data)

    # Add as peer in DB
    try:
        import sqlite3
        db_path = os.getenv("F42BBS_DB", "/var/lib/f42bbs/db/f42bbs.db")
        con = sqlite3.connect(db_path)
        _conn = entry.get("connectors", []) or [entry.get("peer_url","")]
        for i, curl in enumerate(_conn):
            pid = addr if i == 0 else f"{addr}#c{i}"
            con.execute("INSERT OR REPLACE INTO peers (node_id, name, address, trust) VALUES (?,?,?,?)",
                        (pid, entry.get("label", addr), curl, "trusted"))
        con.commit()
        con.close()
        print(f"peer {addr} added to DB")
    except Exception as e:
        print(f"warning: DB peer add failed: {e}")

    # Remove from pending
    del pending[addr]
    pending_file = os.path.join(DATA_DIR, "pending.json")
    _save(pending_file, pending)

    # Publish nodelist gossip via step
    try:
        import requests as _rq
        step_url = os.getenv("F42BBS_STEP_URL", "http://localhost:8001")
        body_nl  = json.dumps(test_nl, ensure_ascii=False)
        r = _rq.post(f"{step_url}/step",
                     data=f",publish topic=net.nodelist body={body_nl}".encode(),
                     headers={"Content-Type": "text/plain"}, timeout=10)
        print(f"nodelist published to net.nodelist: {r.text[:40]}")
    except Exception as e:
        print(f"warning: gossip publish failed: {e}")

    print(f"\n✓ Admitted {addr} ({entry.get('label','?')})")
    print(f"  ed25519: {entry['ed25519_pub'][:24]}...")
    print(f"  sponsor: {NODE_ADDR}")
    print(f"  chain verify: {ok}")
    print(f"  nodelist size: {len(test_nl)}")


def main():
    parser = argparse.ArgumentParser(prog="f42bbs-admin")
    sub = parser.add_subparsers(dest="command")

    p_add = sub.add_parser("addpoint", help="Create new point")
    p_add.add_argument("--label", default="", help="Human label for point")

    p_adm = sub.add_parser("admit", help="Admit pending node into nodelist")
    p_adm.add_argument("addr", nargs="?", default="", help="Node address to admit (omit to list pending)")

    p_otp = sub.add_parser("genotp", help="Generate OTP for point")
    p_otp.add_argument("addr", help="Point address, e.g. 1:42/1.1")

    sub.add_parser("listpoints", help="List registered points")
    sub.add_parser("listnodes",  help="List federated nodes")
    sub.add_parser("status",     help="Node status")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    {
        "admit":      cmd_admit,
        "addpoint":   cmd_addpoint,
        "genotp":     cmd_genotp,
        "listpoints": cmd_listpoints,
        "listnodes":  cmd_listnodes,
        "status":     cmd_status,
    }[args.command](args)


if __name__ == "__main__":
    main()
