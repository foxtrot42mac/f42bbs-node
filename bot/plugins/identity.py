"""Identity plugin — register/unregister points and nodes."""
import json, sys, os
sys.path.insert(0, "/home/f42agent/f42bbs")
import keystore, crypto, signing

HELP = {
    "register":   "register — register yourself as a point, get addr+priv_key",
    "unregister": "unregister <addr> — remove a point",
    "nodes":      "nodes — list federated nodes",
    "points":     "points — list registered points",
    "whoami":     "whoami — show your point addr",
}

def _register(args, ctx):
    from_addr = ctx["from_addr"]
    # Generate keypair for this point
    priv, pub = crypto.keypair_generate()
    # Register via admit_point logic in keystore
    ks = keystore._load()
    points = ks.setdefault("points", {})
    # Check if already registered
    existing = {v: k for k, v in points.items()}
    if from_addr in existing:
        return json.dumps({"addr": from_addr, "status": "already registered",
                           "note": "use your existing priv_key"}, ensure_ascii=False)
    # Assign addr: BOT_ADDR parent.N → but for points from outside use NODE_ADDR
    node = ctx["node_addr"]  # 1:42/1
    prefix = node + "."
    used = [int(a[len(prefix):]) for a in points.values()
            if a.startswith(prefix) and a[len(prefix):].isdigit()]
    n = max(used, default=0) + 1
    addr = f"{prefix}{n}"
    points[pub] = addr
    keystore._save(ks)
    # Publish pub to net.keys.<addr>
    try:
        otp = ctx.get("otp", "")
        body = json.dumps({"addr": addr, "pubkey_x25519": pub, "ts": __import__("datetime").datetime.utcnow().isoformat()+"Z"})
        otp, _ = ctx["step"](f"publish topic=net.keys.{addr} body={body}", otp)
        ctx["otp"] = otp
    except Exception as e:
        pass
    return json.dumps({"addr": addr, "priv_key": priv, "pubkey": pub,
                       "note": "Save priv_key. Use addr+priv_key in bbs_send_private/bbs_read_private."}, ensure_ascii=False)

def _unregister(args, ctx):
    if not args:
        return "usage: unregister <addr>"
    addr = args[0]
    ks = keystore._load()
    points = ks.get("points", {})
    to_del = [k for k, v in points.items() if v == addr]
    if not to_del:
        return f"point {addr} not found"
    for k in to_del:
        del points[k]
    keystore._save(ks)
    return f"unregistered {addr}"

def _nodes(args, ctx):
    ks = keystore._load()
    nodelist = ks.get("nodelist", [])
    if not nodelist:
        return "no nodes in nodelist"
    lines = ["Federated nodes:"]
    for e in nodelist:
        lines.append(f"  {e['addr']} ed25519={e['ed25519_pub'][:16]}... sponsor={e['sponsor_addr']}")
    return "\n".join(lines)

def _points(args, ctx):
    ks = keystore._load()
    points = ks.get("points", {})
    if not points:
        return "no registered points"
    lines = ["Registered points:"]
    for pub, addr in sorted(points.items(), key=lambda x: x[1]):
        lines.append(f"  {addr} pub={pub[:16]}...")
    return "\n".join(lines)

def _whoami(args, ctx):
    from_addr = ctx["from_addr"]
    return f"you are {from_addr}"

COMMANDS = {
    "register":   _register,
    "unregister": _unregister,
    "nodes":      _nodes,
    "points":     _points,
    "whoami":     _whoami,
}
