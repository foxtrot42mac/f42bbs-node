import os
import json
import secrets
import time
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, request, Response, jsonify
import requests

from db import DB
from envelope import Envelope, make_msg_id, sign

load_dotenv()

F42BBS_NODE_ID = os.getenv("F42BBS_NODE_ID")

# B3: ed25519 signing — init at startup
import sys as _sys_b3
_sys_b3.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import keystore as _keystore
    import signing as _signing
    _ED25519_PRIV, _ED25519_PUB = _keystore.get_ed25519(F42BBS_NODE_ID)
    _NODELIST = _keystore.get_nodelist(F42BBS_NODE_ID)
    _GENESIS  = _keystore.load_genesis()
    print(f"[B3] ed25519 signing ready, pub={_ED25519_PUB[:24]}...", flush=True)
    from transport.http import init_b4_trust
    init_b4_trust(_NODELIST, _GENESIS)
    print("[B4] trust anchors loaded", flush=True)
except Exception as _e_b3:
    _ED25519_PRIV = _ED25519_PUB = None
    _NODELIST = []; _GENESIS = {}
    print(f"[B3] signing init FAILED: {_e_b3}", flush=True)


def _b4_verify_inbound(envelope_dict: dict) -> tuple:
    """
    B4: Verify inbound envelope ed25519 signature via nodelist chain.
    Returns (ok: bool, reason: str).
    Rejects if:
      - no sig field
      - sig invalid (tampered)
      - origin not in nodelist OR chain doesn't reach genesis (unrooted)
    """
    if not _ED25519_PRIV:
        return True, "signing not init, skip"  # graceful degradation

    origin = envelope_dict.get("origin", "")
    sig    = envelope_dict.get("sig", "")

    if not sig:
        return False, f"no sig field from {origin}"

    # Find origin entry in nodelist
    origin_entry = next((e for e in _NODELIST if e.get("addr") == origin), None)
    if not origin_entry:
        return False, f"origin {origin} not in nodelist"

    # Verify chain to genesis (catches unrooted self-signed entries)
    if not _signing.verify_nodelist_chain(origin_entry, _NODELIST, _GENESIS):
        return False, f"origin {origin} chain does not reach genesis"

    # Verify envelope signature
    origin_pub = origin_entry.get("ed25519_pub", "")
    if not _signing.verify_envelope(envelope_dict, origin_pub):
        return False, f"invalid sig from {origin}"

    return True, "ok"
F42BBS_KEY = os.getenv("F42BBS_KEY")
F42BBS_DB = os.getenv("F42BBS_DB", "f42bbs.db")
STEP_PORT = int(os.getenv("STEP_PORT", "8766"))

db = DB(F42BBS_DB)

otp_chain = {}
OTP_TTL = 3600

with open("nodes.json", "r") as f:
    nodes_data = json.load(f)
    peer_urls = []
    for node in nodes_data["nodes"]:
        for transport in node["transports"]:
            if transport.startswith("https:"):
                peer_urls.append(transport[6:])

app = Flask(__name__)

# Register HTTP inbound blueprint
from transport.http import http_transport, init_http_transport, HttpTransport
from daemon import Daemon
app.register_blueprint(http_transport)


def generate_otp() -> str:
    return secrets.token_hex(8)


def validate_otp(otp_str: str) -> bool:
    if otp_str not in otp_chain:
        return False
    created_at = otp_chain[otp_str]
    if time.time() - created_at > OTP_TTL:
        del otp_chain[otp_str]
        return False
    return True


def execute_command(command: str) -> str:
    parts = command.strip().split()
    if not parts:
        return "error: empty command"
    
    cmd = parts[0]
    
    if cmd == "ping":
        return "ok"
    
    elif cmd == "publish":
        topic = None
        body = None
        # body= takes everything to end of line (may contain spaces)
        raw = " ".join(parts[1:])
        import re as _re
        m_topic = _re.search(r'topic=(\S+)', raw)
        m_body = _re.search(r'body=(.+?)(?:\s+topic=|$)', raw)
        if not m_body:
            m_body = _re.search(r'body=(.+)', raw)
        if m_topic:
            topic = m_topic.group(1)
        if m_body:
            body = m_body.group(1).strip()
        
        if not topic or not body:
            return "error: publish requires topic=<name> body=<text>"
        
        timestamp = datetime.now(timezone.utc).isoformat()
        msg_id = make_msg_id(F42BBS_NODE_ID, timestamp, body)
        hmac_val = sign(F42BBS_KEY, msg_id, F42BBS_NODE_ID, topic, body)
        
        envelope = Envelope(
            ver="0.2",
            type="POST",
            msg_id=msg_id,
            origin=F42BBS_NODE_ID,
            topic=topic,
            from_=F42BBS_NODE_ID,
            to="*",
            subject=f"POST {topic}",
            timestamp=timestamp,
            hops=[F42BBS_NODE_ID],
            max_hops=10,
            hmac=hmac_val,
            body=body,
            refs=[]
        )
        
        # B3: ed25519 origin signature
        env_dict = envelope.emit()
        if _ED25519_PRIV:
            env_dict = _signing.sign_envelope(env_dict, _ED25519_PRIV)
        raw_envelope = json.dumps(env_dict)
        db.store_msg(msg_id, "POST", F42BBS_NODE_ID, topic, raw_envelope)
        
        try:
            dyn_peers = [p['address'] for p in db.get_peers() if p.get('address')]
        except Exception:
            dyn_peers = []
        all_peers = list(dict.fromkeys(dyn_peers + peer_urls))
        print(f'[fanout] peers={all_peers} topic={topic}', flush=True)
        for peer_url in all_peers:
            try:
                r = requests.post(peer_url, json=env_dict, timeout=5)
                print(f'[fanout] {peer_url} -> {r.status_code}', flush=True)
            except Exception as _fe:
                print(f'[fanout] {peer_url} -> ERROR: {_fe}', flush=True)
        
        return f"published to topic {topic}"
    
    elif cmd == "get":
        topic = None
        for part in parts[1:]:
            if part.startswith("topic="):
                topic = part[6:]
        
        if not topic:
            return "error: get requires topic=<name>"
        
        msg_body = db.get_latest(topic)
        if msg_body is None:
            return f"no messages in topic {topic}"
        
        try:
            msg_dict = json.loads(msg_body)
            return msg_dict.get("body", msg_body)
        except:
            return msg_body
    
    elif cmd == "request":
        topic = None
        query = None
        for part in parts[1:]:
            if part.startswith("topic="):
                topic = part[6:]
            elif part.startswith("query="):
                query = "=".join(part.split("=")[1:])
        if not topic:
            return "error: request requires topic=<name>"
        if not query:
            query = f"latest on {topic}"

        import time as _t
        ts = str(int(_t.time()))
        msg_id = make_msg_id(F42BBS_NODE_ID, ts, query)
        hmac_val = sign(F42BBS_KEY, msg_id, F42BBS_NODE_ID, topic, query)
        req_env = Envelope(
            ver="0.2", type="REQUEST",
            msg_id=msg_id, origin=F42BBS_NODE_ID,
            topic=topic, from_=F42BBS_NODE_ID, to="*",
            subject=f"REQUEST {topic}",
            timestamp=ts, hops=[], max_hops=10,
            hmac=hmac_val, body=query, refs=[]
        )
        _daemon.inbound(req_env)

        for _ in range(20):
            _t.sleep(0.5)
            digest = db.get_digest(msg_id)
            if digest:
                return digest
        return "no digest received (timeout 10s)"


    elif cmd == "send_private":
        # send_private to=<addr> body=<text>
        import re as _re2
        raw = " ".join(parts[1:])
        m_to   = _re2.search(r'to=(\S+)', raw)
        m_body = _re2.search(r'body=(.+)', raw)
        if not m_to or not m_body:
            return "error: send_private requires to=<addr> body=<text>"
        to_addr   = m_to.group(1)
        plaintext = m_body.group(1).strip()

        import sys as _sys2
        _sys2.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import keys as _keys
        import crypto as _crypto

        my_addr  = F42BBS_NODE_ID
        my_priv  = _keys.my_privkey(my_addr)
        peer_pub = _keys.get_peer_pubkey(to_addr, f"http://localhost:{STEP_PORT}")
        if not peer_pub:
            return f"error: no pubkey for {to_addr} in net.keys"

        ciphertext = _crypto.encrypt(plaintext, peer_pub, my_priv)
        topic      = _crypto.direct_topic(my_addr, to_addr)

        import json as _json2, time as _time2
        payload = _json2.dumps({"from": my_addr, "to": to_addr,
                                "encrypted": True, "body": ciphertext})
        ts2   = str(int(_time2.time()))
        mid2  = make_msg_id(F42BBS_NODE_ID, ts2, ciphertext[:16])
        hmac2 = sign(F42BBS_KEY, mid2, F42BBS_NODE_ID, topic, payload)
        env2  = Envelope(
            ver="0.2", type="POST",
            msg_id=mid2, origin=F42BBS_NODE_ID,
            topic=topic, from_=F42BBS_NODE_ID, to=to_addr,
            subject=f"P2P {my_addr}->{to_addr}",
            timestamp=ts2, hops=[], max_hops=10,
            hmac=hmac2, body=payload, refs=[]
        )
        _daemon.inbound(env2)
        return f"sent encrypted message to {to_addr} on topic {topic}"

    elif cmd == "read_private":
        # read_private from=<addr>
        import re as _re3
        raw = " ".join(parts[1:])
        m_from = _re3.search(r'from=(\S+)', raw)
        if not m_from:
            return "error: read_private requires from=<addr>"
        from_addr = m_from.group(1)

        import sys as _sys3
        _sys3.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import keys as _keys2
        import crypto as _crypto2
        import json as _json3

        my_addr  = F42BBS_NODE_ID
        my_priv  = _keys2.my_privkey(my_addr)
        peer_pub = _keys2.get_peer_pubkey(from_addr, f"http://localhost:{STEP_PORT}")
        if not peer_pub:
            return f"error: no pubkey for {from_addr} in net.keys"

        topic    = _crypto2.direct_topic(my_addr, from_addr)
        raw_body = db.get_latest(topic)
        if raw_body is None:
            return f"no private messages from {from_addr}"

        try:
            record     = _json3.loads(raw_body)
            ciphertext = record.get("body", "")
        except Exception:
            ciphertext = raw_body

        try:
            plaintext = _crypto2.decrypt(ciphertext, my_priv, peer_pub)
        except Exception as _e:
            return f"error: decrypt failed (authenticity check) — {_e}"

        return f"[from {from_addr}] {plaintext}"


    else:
        return "error: unknown command"


@app.route("/step", methods=["POST"])
def step():
    body = request.get_data(as_text=False).decode("utf-8", errors="replace").strip()
    
    if body.startswith(","):
        command = body[1:].strip()
        new_otp = generate_otp()
        otp_chain[new_otp] = time.time()
        result = execute_command(command)
        return Response(f"%{new_otp}% {result}", content_type="text/plain; charset=utf-8")
    
    elif body.startswith("%"):
        parts = body.split("%", 2)
        if len(parts) < 3:
            return Response("error: invalid otp", content_type="text/plain; charset=utf-8", status=400)
        
        otp_str = parts[1].strip()
        command = parts[2].strip()
        
        if not validate_otp(otp_str):
            return Response("error: invalid otp", content_type="text/plain; charset=utf-8", status=401)
        
        del otp_chain[otp_str]
        new_otp = generate_otp()
        otp_chain[new_otp] = time.time()
        
        result = execute_command(command)
        return Response(f"%{new_otp}% {result}", content_type="text/plain; charset=utf-8")
    
    return Response("error: invalid request", content_type="text/plain; charset=utf-8", status=400)



@app.route("/health", methods=["GET"])
def health():
    return "step ok", 200

# Init inbound transport
# Init inbound transport with real vars
import copy as _copy
_http_transport_obj = HttpTransport()
_peer_urls_raw = os.getenv("F42BBS_PEER_URLS", "") or os.getenv("F42BBS_PEER_URL", "")
_peer_urls = [u.strip() for u in _peer_urls_raw.split(",") if u.strip()]
_db_path = os.getenv("F42BBS_DB", "f42bbs.db")
from db import DB as _DB
_daemon_db = _DB(_db_path)
_daemon = Daemon(F42BBS_NODE_ID, _daemon_db, _http_transport_obj, F42BBS_KEY)

def _http_fanout(env):
    # Use peers from DB (populated from nodelist), fallback to env
    try:
        db_peers = [p['address'] for p in db.get_peers() if p.get('address')]
    except Exception:
        db_peers = []
    all_peers = list(dict.fromkeys(db_peers + _peer_urls))  # dedup, DB first
    for peer_url in all_peers:
        ec = _copy.deepcopy(env)
        ec.hops = env.hops + [F42BBS_NODE_ID]
        # B3: sign envelope before sending to peer
        if _ED25519_PRIV:
            import json as _j_fanout
            env_dict = _signing.sign_envelope(ec.emit(), _ED25519_PRIV)
            from envelope import Envelope as _Env
            ec = _Env.from_dict(env_dict)
        _http_transport_obj.send(ec, peer_url)
_daemon._fanout = _http_fanout
init_http_transport(_daemon, F42BBS_KEY)


@app.route('/admit', methods=['POST'])
def admit():
    """Node admission endpoint.
    Request: {addr, ed25519_pub, x25519_pub, peer_url, label?}
    Response: {status: "pending"|"admitted"|"rejected", reason?}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "rejected", "reason": "bad request"}), 400

        addr       = data.get("addr", "").strip()
        ed_pub     = data.get("ed25519_pub", "").strip()
        x_pub      = data.get("x25519_pub", "").strip()
        label      = data.get("label", addr)
        # connectors: list of inbound URLs, legacy peer_url also accepted
        connectors = data.get("connectors", [])
        peer_url   = data.get("peer_url", "").strip()
        if peer_url and peer_url not in connectors:
            connectors.insert(0, peer_url)
        if not connectors:
            peer_url = ""

        if not addr or not ed_pub or not x_pub or not connectors:
            return jsonify({"status": "rejected",
                            "reason": "addr, ed25519_pub, x25519_pub, connectors required"}), 400

        # Check if already in nodelist
        existing = next((e for e in _NODELIST if e.get("addr") == addr), None)
        if existing:
            return jsonify({"status": "admitted", "reason": "already in nodelist",
                            "nodelist": _NODELIST}), 200

        # Save to pending
        pending = _load_pending()
        pending[addr] = {
            "addr": addr, "ed25519_pub": ed_pub, "x25519_pub": x_pub,
            "connectors": connectors,
            "peer_url": connectors[0],  # primary for legacy compat
            "label": label,
            "ts": __import__("datetime").datetime.utcnow().isoformat() + "Z"
        }
        _save_pending(pending)
        print(f"[admit] pending: {addr} ({label}) connectors={connectors}", flush=True)

        # Our own connectors from env
        _my_connectors = [u.strip() for u in os.getenv("F42BBS_CONNECTORS", "").split(",") if u.strip()]

        return jsonify({
            "status": "pending",
            "reason": f"admission request saved, await admin approval: f42bbs-admin admit {addr}",
            "node": F42BBS_NODE_ID,
            "connectors": _my_connectors,
            "genesis": _GENESIS,
            "nodelist": _NODELIST,
        }), 202

    except Exception as e:
        return jsonify({"status": "rejected", "reason": str(e)}), 500


@app.route('/raw/<path:topic>', methods=['GET'])
def raw_topic(topic):
    """Return raw envelope JSON for latest message in topic.
    Used by MCP server for crypto operations (decrypt needs full envelope)."""
    row = db.get_latest_raw(topic)
    if row is None:
        return Response(json.dumps({"error": "no messages"}),
                        content_type="application/json; charset=utf-8", status=404)
    return Response(row, content_type="application/json; charset=utf-8")


# ── Point admission ────────────────────────────────────────────────────────

def should_admit(pubkey: str) -> bool:
    """Pluggable admission policy. MVP: auto-accept any valid pubkey.
    Replace with human/model-confirm interface later."""
    return bool(pubkey and len(pubkey) > 10)


@app.route('/admit_point', methods=['POST'])
def admit_point():
    """
    Register a point (agent) by its X25519 pubkey.
    Returns stable address: same pubkey always gets same addr.
    Request:  {"pubkey": "<base64>"}
    Response: {"addr": "1:42/1.N", "parent": "1:42/1", "status": "admitted"}
    Error:    {"rejected": "reason"}, 400
    """
    import sys as _sys2
    _sys2.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import keys as _keys2

    try:
        data = request.get_json()
        if not data:
            return jsonify({"rejected": "bad request"}), 400

        pubkey = data.get("pubkey", "").strip()
        if not pubkey:
            return jsonify({"rejected": "missing pubkey"}), 400

        if not should_admit(pubkey):
            return jsonify({"rejected": "not admitted"}), 403

        # Load or create point registry
        kdata = _keys2._load()
        points = kdata.setdefault("points", {})  # {pubkey: addr}

        # Stable: same pubkey → same addr
        if pubkey in points:
            addr = points[pubkey]
            return jsonify({"addr": addr, "parent": F42BBS_NODE_ID,
                            "status": "admitted", "existing": True}), 200

        # New point: assign next free N
        parent = F42BBS_NODE_ID
        existing_addrs = list(points.values())
        prefix = parent + "."
        used_ns = []
        for a in existing_addrs:
            if a.startswith(prefix):
                try:
                    used_ns.append(int(a[len(prefix):]))
                except ValueError:
                    pass
        n = max(used_ns, default=0) + 1
        addr = f"{parent}.{n}"

        # Save
        points[pubkey] = addr
        kdata["points"] = points
        _keys2._save(kdata)

        # Publish pubkey to net.keys.<addr> so others can encrypt to this point
        import json as _json2
        from datetime import datetime, timezone as _tz
        body = _json2.dumps({"addr": addr, "pubkey_x25519": pubkey,
                              "ts": datetime.now(_tz.utc).isoformat()})
        cmd  = f"publish topic=net.keys.{addr} body={body}"
        _keys2._step(f"http://localhost:{STEP_PORT}", cmd)

        return jsonify({"addr": addr, "parent": parent,
                        "status": "admitted", "existing": False}), 200

    except Exception as e:
        return jsonify({"rejected": str(e)}), 500


@app.route('/nodelist', methods=['GET'])
def nodelist_endpoint():
    """Return signed nodelist for this node."""
    return Response(json.dumps(_NODELIST),
                    content_type="application/json; charset=utf-8")

@app.route('/genesis', methods=['GET'])
def genesis_endpoint():
    """Return genesis config (root pubkeys)."""
    return Response(json.dumps(_GENESIS),
                    content_type="application/json; charset=utf-8")


import json as _json_admit
import os as _os_admit

_PENDING_FILE = os.path.join(os.getenv("F42BBS_DATA_DIR", "."), "pending.json")

def _load_pending():
    try:
        with open(_PENDING_FILE) as f: return _json_admit.load(f)
    except Exception: return {}

def _save_pending(d):
    import stat as _stat
    tmp = _PENDING_FILE + ".tmp"
    with open(tmp, "w") as f: _json_admit.dump(d, f, indent=2)
    os.replace(tmp, _PENDING_FILE)

def _publish_nodelist():
    """Publish nodelist directly to ALL known nodes (one-hop gossip)."""
    try:
        # Always read fresh from keystore (CLI admit updates disk, not memory)
        try:
            nodelist = _keystore.get_nodelist(F42BBS_NODE_ID)
            _NODELIST.clear()
            _NODELIST.extend(nodelist)
        except Exception:
            nodelist = _NODELIST
        body     = _json_admit.dumps(nodelist, ensure_ascii=False)
        timestamp = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        msg_id   = make_msg_id(F42BBS_NODE_ID, timestamp, body[:16])
        hmac_val = sign(F42BBS_KEY, msg_id, F42BBS_NODE_ID, "net.nodelist", body)
        env = Envelope(
            ver="0.2", type="POST", msg_id=msg_id,
            origin=F42BBS_NODE_ID, topic="net.nodelist",
            from_=F42BBS_NODE_ID, to="*",
            subject="nodelist update",
            timestamp=timestamp, hops=[], max_hops=1,
            hmac=hmac_val, body=body, refs=[]
        )
        if _ED25519_PRIV:
            env_dict = _signing.sign_envelope(env.emit(), _ED25519_PRIV)
        else:
            env_dict = env.emit()
        # Store locally
        raw = _json_admit.dumps(env_dict)
        db.store_msg(msg_id, "POST", F42BBS_NODE_ID, "net.nodelist", raw)

        # Send directly to ALL nodes in nodelist (any chain length, one hop)
        import requests as _rq_nl
        sent = []
        for entry in nodelist:
            if entry.get("addr") == F42BBS_NODE_ID:
                continue
            for connector in entry.get("connectors", []):
                inbound = connector if connector.endswith("/f42bbs/inbound")                           else connector.rstrip("/") + "/f42bbs/inbound"
                try:
                    r = _rq_nl.post(inbound, json=env_dict, timeout=5)
                    if r.status_code == 200:
                        sent.append(entry["addr"])
                        break  # primary connector worked, skip fallbacks
                except Exception:
                    continue  # try next connector

        print(f"[nodelist] published {len(nodelist)} entries → sent to {sent}", flush=True)
    except Exception as _e_nl:
        print(f"[nodelist] publish failed: {_e_nl}", flush=True)


@app.route('/net.nodelist', methods=['GET'])
def nodelist_gossip():
    """Return latest net.nodelist message body for gossip."""
    row = db.get_latest_raw("net.nodelist")
    if not row:
        return Response(json.dumps(_NODELIST),
                        content_type="application/json; charset=utf-8")
    try:
        env = json.loads(row)
        return Response(env.get("body", "[]"),
                        content_type="application/json; charset=utf-8")
    except Exception:
        return Response("[]", content_type="application/json; charset=utf-8")


def _bootstrap_nodelist():
    """On startup: fetch net.nodelist from bootstrap peer, update local nodelist+peers."""
    if not _peer_urls:
        return
    try:
        import keystore as _ks_bs, signing as _sg_bs, requests as _rq_bs
        _ks_file    = os.getenv("F42BBS_KEYS")
        _gs_file    = os.getenv("F42BBS_GENESIS")
        if _ks_file:    _ks_bs.KEYS_FILE    = _ks_file
        if _gs_file:    _ks_bs.GENESIS_FILE = _gs_file

        for peer_url in _peer_urls:
            base = peer_url.replace("/f42bbs/inbound", "")
            try:
                genesis = _ks_bs.load_genesis()  # load local genesis
                try:
                    gr = _rq_bs.get(f"{base}/genesis", timeout=5)
                    if gr.status_code == 200:
                        remote_genesis = gr.json()
                        remote_roots = remote_genesis.get("root_pubkeys", [])
                        local_roots  = genesis.get("root_pubkeys", [])
                        # Adopt remote genesis if:
                        # - remote has roots AND
                        # - local genesis is self-only (new node) OR empty
                        ed_priv, ed_pub = _ks_bs.get_ed25519(F42BBS_NODE_ID)
                        is_self_genesis = (local_roots == [ed_pub] or not local_roots)
                        if remote_roots and is_self_genesis:
                            genesis = remote_genesis
                            _ks_bs.init_genesis(remote_roots,
                                                remote_genesis.get("threshold", 1))
                            print(f"[bootstrap] adopted genesis from {base}: {remote_roots[0][:16]}...", flush=True)
                except Exception as _eg: print(f"[bootstrap] genesis err: {_eg}", flush=True)

                r = _rq_bs.get(f"{base}/net.nodelist", timeout=10)
                if r.status_code != 200:
                    continue
                remote_nodelist = r.json()
                if not isinstance(remote_nodelist, list) or not remote_nodelist:
                    continue

                genesis = _ks_bs.load_genesis()
                added = 0
                for entry in remote_nodelist:
                    addr = entry.get("addr", "")
                    # Skip if already known
                    if any(e.get("addr") == addr for e in _NODELIST):
                        continue
                    # Verify chain
                    test_nl = _NODELIST + [entry]
                    if genesis and not _sg_bs.verify_nodelist_chain(entry, test_nl, genesis):
                        print(f"[bootstrap] skip {addr}: chain verify failed", flush=True)
                        continue
                    _NODELIST.append(entry)
                    added += 1
                    # Add connectors as peers
                    _bs_connectors = entry.get("connectors", [])
                    if not _bs_connectors and entry.get("peer_url"):
                        _bs_connectors = [entry["peer_url"]]
                    if _bs_connectors and addr != F42BBS_NODE_ID:
                        try:
                            for _bi, _bc in enumerate(_bs_connectors):
                                _bpid = addr if _bi == 0 else f"{addr}#c{_bi}"
                                db.add_peer(_bpid, entry.get("label", addr),
                                            _bc, "trusted")
                        except Exception:
                            pass

                if added:
                    _ks_bs._load_and_save_nodelist = lambda: None
                    data = _ks_bs._load()
                    data["nodelist"] = _NODELIST
                    _ks_bs._save(data)
                    print(f"[bootstrap] added {added} nodes from {base}", flush=True)
                    # Update B4 trust anchors
                    from transport.http import init_b4_trust
                    init_b4_trust(_NODELIST, genesis)
                break
            except Exception as _e_bs2:
                print(f"[bootstrap] {base}: {_e_bs2}", flush=True)
    except Exception as _e_bs:
        print(f"[bootstrap] failed: {_e_bs}", flush=True)


@app.route('/nodelist/publish', methods=['POST'])
def nodelist_publish():
    """Trigger direct nodelist gossip to all known nodes."""
    _publish_nodelist()
    return jsonify({"status": "ok", "nodes": len(_NODELIST)}), 200


if __name__ == "__main__":
    _bootstrap_nodelist()
    app.run(host="0.0.0.0", port=STEP_PORT, debug=False)