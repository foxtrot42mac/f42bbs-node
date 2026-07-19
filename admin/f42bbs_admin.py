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


def main():
    parser = argparse.ArgumentParser(prog="f42bbs-admin")
    sub = parser.add_subparsers(dest="command")

    p_add = sub.add_parser("addpoint", help="Create new point")
    p_add.add_argument("--label", default="", help="Human label for point")

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
        "addpoint":   cmd_addpoint,
        "genotp":     cmd_genotp,
        "listpoints": cmd_listpoints,
        "listnodes":  cmd_listnodes,
        "status":     cmd_status,
    }[args.command](args)


if __name__ == "__main__":
    main()
