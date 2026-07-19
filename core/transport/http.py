import requests
from flask import Blueprint, request, jsonify
from envelope import Envelope, EnvelopeError

# --- Outbound ---

class HttpTransport:
    def send(self, envelope: Envelope, to_address: str) -> bool:
        try:
            response = requests.post(to_address, json=envelope.emit(), timeout=10)
            return response.status_code == 200
        except Exception:
            return False

# --- Inbound blueprint ---

http_transport = Blueprint('http_transport', __name__)

_daemon = None
_shared_key = None


def init_http_transport(daemon, key: str) -> None:
    global _daemon, _shared_key
    _daemon = daemon
    _shared_key = key


# B4: nodelist + genesis injected at init
_nodelist = []
_genesis  = {}

def init_b4_trust(nodelist: list, genesis: dict) -> None:
    global _nodelist, _genesis
    _nodelist = nodelist
    _genesis  = genesis


def _b4_verify(env_dict: dict) -> tuple:
    """
    B4 inbound verify. Returns (ok, reason).
    Rejects on:
      1. no sig field
      2. invalid sig (tampered body/max_hops)
      3. valid sig but origin not rooted in genesis (unrooted self-signed)
    """
    if not _nodelist or not _genesis:
        return True, "b4 not init, skip"

    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
        import signing as _signing
    except ImportError:
        return True, "signing not available, skip"

    origin = env_dict.get("origin", "")
    if not env_dict.get("sig"):
        return False, f"no sig from {origin}"

    # Strict: lookup via chain, not plain dict
    origin_entry = next((e for e in _nodelist if e.get("addr") == origin), None)
    if not origin_entry:
        return False, f"origin {origin} not in nodelist"

    if not _signing.verify_nodelist_chain(origin_entry, _nodelist, _genesis):
        return False, f"origin {origin} chain not rooted in genesis"

    if not _signing.verify_envelope(env_dict, origin_entry["ed25519_pub"]):
        return False, f"invalid envelope sig from {origin}"

    return True, "ok"


@http_transport.route('/f42bbs/inbound', methods=['POST'])
def inbound():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "bad json"}), 400
    except Exception:
        return jsonify({"error": "bad json"}), 400

    # B4: ed25519 origin verify
    ok, reason = _b4_verify(data)
    if not ok:
        import sys as _sys
        print(f"[B4] REJECT inbound: {reason}", file=_sys.stderr, flush=True)
        return jsonify({"error": "rejected", "reason": reason}), 403

    try:
        env = Envelope.parse(data, _shared_key)
    except EnvelopeError:
        return jsonify({"error": "invalid hmac"}), 403

    try:
        result = _daemon.inbound(env)
        return jsonify({"status": "ok", "result": result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
