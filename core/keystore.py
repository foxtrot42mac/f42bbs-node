"""
F42BBS keystore.py — unified key storage (B0)

Schema v2 (~/.f42bbs_keys, chmod 600):
{
  "schema": 2,
  "my_addr": "1:42/1",
  "ed25519": {"priv": "<b64>", "pub": "<b64>"},
  "x25519":  {"priv": "<b64>", "pub": "<b64>"},
  "points":  {"<x25519_pub_b64>": "<addr>"},
  "confs":   {"<conf_id>": "<conf_key_b64>"},
  "nodelist": [<nodelist_entry>, ...]
}

Nodelist entry:
{
  "addr": "1:42/1",
  "ed25519_pub": "<b64>",
  "x25519_pub":  "<b64>",
  "sponsor_addr": "1:42/1",   # self for genesis/root
  "sponsor_sig":  "<b64>"     # ed25519 sig over canonical_json of entry (minus sig field)
}

Genesis config (~/.f42bbs_genesis, chmod 600):
{
  "root_pubkeys": ["<ed25519_pub_b64>"],
  "threshold": 1
}
"""
from __future__ import annotations
import base64, json, os, stat
from typing import Optional

KEYS_FILE    = os.path.expanduser("~/.f42bbs_keys")
GENESIS_FILE = os.path.expanduser("~/.f42bbs_genesis")


# ── persistence ──────────────────────────────────────────────────────────────

def _load() -> dict:
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE) as f:
        text = f.read().strip()
        if not text:
            return {}
        return json.loads(text)

def _save(data: dict) -> None:
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(KEYS_FILE, stat.S_IRUSR | stat.S_IWUSR)

def _load_genesis() -> dict:
    if not os.path.exists(GENESIS_FILE):
        return {}
    with open(GENESIS_FILE) as f:
        return json.load(f)

def _save_genesis(data: dict) -> None:
    with open(GENESIS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(GENESIS_FILE, stat.S_IRUSR | stat.S_IWUSR)


# ── migration v1 → v2 ────────────────────────────────────────────────────────

def migrate_v1_to_v2(data: dict) -> dict:
    """Migrate old flat schema to v2. Safe to call on already-v2 data."""
    if data.get("schema") == 2:
        return data
    # old schema: priv/pub = x25519
    new = {
        "schema":   2,
        "my_addr":  data.get("my_addr", ""),
        "ed25519":  {"priv": "", "pub": ""},   # will be generated on first init
        "x25519":   {
            "priv": data.get("priv", ""),
            "pub":  data.get("pub", ""),
        },
        "points":   data.get("points", {}),
        "confs":    data.get("confs", {}),
        "nodelist": data.get("nodelist", []),
    }
    # migrate peers → discard (net.keys deprecated)
    return new


def load_or_init(my_addr: str) -> dict:
    """Load keystore, migrate if needed. Does NOT generate keys (call init_keys)."""
    data = _load()
    if data:
        data = migrate_v1_to_v2(data)
        if data.get("my_addr") != my_addr:
            data["my_addr"] = my_addr
    else:
        data = {
            "schema":   2,
            "my_addr":  my_addr,
            "ed25519":  {"priv": "", "pub": ""},
            "x25519":   {"priv": "", "pub": ""},
            "points":   {},
            "confs":    {},
            "nodelist": [],
        }
    return data


# ── key access ───────────────────────────────────────────────────────────────

def get_ed25519(my_addr: str) -> tuple:
    """Return (priv_b64, pub_b64) for ed25519. Generates if missing."""
    from nacl.signing import SigningKey
    data = load_or_init(my_addr)
    if not data["ed25519"]["priv"]:
        sk = SigningKey.generate()
        data["ed25519"]["priv"] = base64.b64encode(bytes(sk)).decode()
        data["ed25519"]["pub"]  = base64.b64encode(bytes(sk.verify_key)).decode()
        _save(data)
    return data["ed25519"]["priv"], data["ed25519"]["pub"]

def get_x25519(my_addr: str) -> tuple:
    """Return (priv_b64, pub_b64) for x25519. Generates if missing."""
    from nacl.public import PrivateKey
    data = load_or_init(my_addr)
    if not data["x25519"]["priv"]:
        sk = PrivateKey.generate()
        data["x25519"]["priv"] = base64.b64encode(bytes(sk)).decode()
        data["x25519"]["pub"]  = base64.b64encode(bytes(sk.public_key)).decode()
        _save(data)
    return data["x25519"]["priv"], data["x25519"]["pub"]

def init_keys(my_addr: str) -> dict:
    """Ensure both keypairs exist. Returns {ed25519_pub, x25519_pub}."""
    ed_priv, ed_pub = get_ed25519(my_addr)
    x_priv,  x_pub  = get_x25519(my_addr)
    return {"ed25519_pub": ed_pub, "x25519_pub": x_pub}


# ── confs ────────────────────────────────────────────────────────────────────

def save_conf_key(my_addr: str, conf_key_b64: str, members: list = None) -> str:
    import hashlib
    cid = "conf-" + hashlib.sha256(base64.b64decode(conf_key_b64)).hexdigest()[:16]
    data = load_or_init(my_addr)
    existing = data["confs"].get(cid)
    if isinstance(existing, dict) and members is None:
        members = existing.get("members", [])
    data["confs"][cid] = {"key": conf_key_b64, "members": members or []}
    _save(data)
    return cid

def get_conf_key(my_addr: str, conf_id: str) -> Optional[str]:
    data = load_or_init(my_addr)
    entry = data["confs"].get(conf_id)
    if entry is None:
        return None
    if isinstance(entry, str):
        return entry  # legacy format, no membership info
    return entry.get("key")

def get_conf_members(my_addr: str, conf_id: str) -> Optional[list]:
    """Returns None if unknown or legacy (no membership tracked — deny by default)."""
    data = load_or_init(my_addr)
    entry = data["confs"].get(conf_id)
    if isinstance(entry, dict):
        return entry.get("members", [])
    return None  # legacy entries: no membership info available

def is_conf_member(my_addr: str, conf_id: str, requester_addr: str) -> bool:
    members = get_conf_members(my_addr, conf_id)
    if members is None:
        return False  # legacy/unknown — deny by default, fail closed
    return requester_addr in members

def list_my_confs(my_addr: str) -> list:
    """List conf_ids where my_addr is an actual member (single source of truth)."""
    data = load_or_init(my_addr)
    return [cid for cid in data.get("confs", {}).keys()
            if is_conf_member(my_addr, cid, my_addr)]

def remove_conf_key(my_addr: str, conf_id: str) -> None:
    data = load_or_init(my_addr)
    data["confs"].pop(conf_id, None)
    _save(data)


# ── points ───────────────────────────────────────────────────────────────────

def get_or_create_point(my_addr: str, x25519_pub_b64: str) -> str:
    """Stable: same pubkey → same point addr."""
    data = load_or_init(my_addr)
    if x25519_pub_b64 in data["points"]:
        return data["points"][x25519_pub_b64]
    prefix = my_addr + "."
    used = [int(a[len(prefix):]) for a in data["points"].values()
            if a.startswith(prefix) and a[len(prefix):].isdigit()]
    n = max(used, default=0) + 1
    addr = f"{prefix}{n}"
    data["points"][x25519_pub_b64] = addr
    _save(data)
    return addr


# ── nodelist ─────────────────────────────────────────────────────────────────

def get_nodelist(my_addr: str) -> list:
    data = load_or_init(my_addr)
    return data.get("nodelist", [])

def append_nodelist_entry(my_addr: str, entry: dict) -> None:
    """Append a verified nodelist entry."""
    data = load_or_init(my_addr)
    data.setdefault("nodelist", []).append(entry)
    _save(data)

def get_node_pubkeys(addr: str, my_addr: str) -> Optional[dict]:
    """Return {ed25519_pub, x25519_pub} for addr from nodelist. None if not found."""
    for entry in get_nodelist(my_addr):
        if entry.get("addr") == addr:
            return {
                "ed25519_pub": entry["ed25519_pub"],
                "x25519_pub":  entry["x25519_pub"],
            }
    return None


# ── genesis ───────────────────────────────────────────────────────────────────

def init_genesis(root_ed25519_pubs: list, threshold: int = 1) -> None:
    """Write genesis config. Called once by root (Doo) offline."""
    _save_genesis({"root_pubkeys": root_ed25519_pubs, "threshold": threshold})

def load_genesis() -> dict:
    return _load_genesis()

def is_root(ed25519_pub_b64: str) -> bool:
    g = load_genesis()
    return ed25519_pub_b64 in g.get("root_pubkeys", [])
