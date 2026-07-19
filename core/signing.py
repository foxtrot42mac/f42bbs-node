"""
F42BBS signing.py — canonical JSON + ed25519 sign/verify (B1+B2)

canonical_json(d): works on ANY dict (envelope, nodelist entry, etc.)
Fields excluded from envelope signing: sig, hmac, hops
max_hops is INSIDE signature (prevents relay flood amplification).
"""
from __future__ import annotations
import base64, json
from typing import Any

# Fields excluded when signing an envelope
ENVELOPE_EXCLUDED = frozenset(["sig", "hmac", "hops"])


# ── canonical JSON ────────────────────────────────────────────────────────────

def canonical_json(d: Any, excluded: frozenset = frozenset()) -> bytes:
    """
    RFC 8785-style canonical JSON: sorted keys, no whitespace.
    excluded: top-level keys to omit before canonicalization.
    Works on any dict, list, or scalar — not just envelopes.
    """
    if isinstance(d, dict):
        filtered = {k: v for k, v in d.items() if k not in excluded}
        return json.dumps(filtered, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def canonical_envelope(envelope: dict) -> bytes:
    """Canonical form of an envelope for signing (excludes sig, hmac, hops)."""
    return canonical_json(envelope, excluded=ENVELOPE_EXCLUDED)


def canonical_nodelist_entry(entry: dict) -> bytes:
    """Canonical form of a nodelist entry for sponsor signing (excludes sponsor_sig)."""
    return canonical_json(entry, excluded=frozenset(["sponsor_sig"]))


# ── sign / verify ─────────────────────────────────────────────────────────────

def sign_dict(d: dict, priv_b64: str, excluded: frozenset = frozenset(),
              sig_field: str = "sig") -> dict:
    """
    Sign canonical form of d (minus excluded fields + sig_field itself).
    Returns new dict with sig_field added.
    """
    from nacl.signing import SigningKey
    sk  = SigningKey(base64.b64decode(priv_b64))
    excl = excluded | frozenset([sig_field])
    payload = canonical_json(d, excluded=excl)
    sig = sk.sign(payload).signature
    result = dict(d)
    result[sig_field] = base64.b64encode(sig).decode()
    return result


def verify_dict(d: dict, pub_b64: str, excluded: frozenset = frozenset(),
                sig_field: str = "sig") -> bool:
    """
    Verify sig_field in d against canonical form (minus excluded + sig_field).
    Returns True if valid, False otherwise.
    """
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    sig_b64 = d.get(sig_field)
    if not sig_b64:
        return False
    excl = excluded | frozenset([sig_field])
    payload = canonical_json(d, excluded=excl)
    try:
        vk = VerifyKey(base64.b64decode(pub_b64))
        vk.verify(payload, base64.b64decode(sig_b64))
        return True
    except (BadSignatureError, Exception):
        return False


# ── envelope helpers ──────────────────────────────────────────────────────────

def sign_envelope(envelope: dict, ed25519_priv_b64: str) -> dict:
    """Sign envelope, excluding sig/hmac/hops. Returns envelope with sig field."""
    return sign_dict(envelope, ed25519_priv_b64, excluded=ENVELOPE_EXCLUDED)


def verify_envelope(envelope: dict, ed25519_pub_b64: str) -> bool:
    """Verify envelope signature."""
    return verify_dict(envelope, ed25519_pub_b64, excluded=ENVELOPE_EXCLUDED)


# ── nodelist helpers ──────────────────────────────────────────────────────────

def sign_nodelist_entry(entry: dict, sponsor_ed25519_priv_b64: str) -> dict:
    """Sponsor signs nodelist entry (excludes sponsor_sig field)."""
    return sign_dict(entry, sponsor_ed25519_priv_b64,
                     excluded=frozenset(), sig_field="sponsor_sig")


def verify_nodelist_entry(entry: dict, sponsor_ed25519_pub_b64: str) -> bool:
    """Verify sponsor signature on nodelist entry."""
    return verify_dict(entry, sponsor_ed25519_pub_b64,
                       excluded=frozenset(), sig_field="sponsor_sig")


def verify_nodelist_chain(entry: dict, nodelist: list, genesis: dict) -> bool:
    """
    Verify entry chain up to genesis root.
    genesis = {root_pubkeys: [...], threshold: 1}
    """
    sponsor_addr = entry.get("sponsor_addr")
    if not sponsor_addr:
        return False

    # Find sponsor pubkey
    if sponsor_addr == entry.get("addr"):
        # Self-signed = genesis/root entry
        sponsor_pub = entry.get("ed25519_pub")
    else:
        sponsor_entry = next((e for e in nodelist if e.get("addr") == sponsor_addr), None)
        if not sponsor_entry:
            return False
        # Recursively verify sponsor
        if not verify_nodelist_chain(sponsor_entry, nodelist, genesis):
            return False
        sponsor_pub = sponsor_entry.get("ed25519_pub")

    if not sponsor_pub:
        return False

    # Root anchor check
    if sponsor_addr == entry.get("addr"):
        if sponsor_pub not in genesis.get("root_pubkeys", []):
            return False

    return verify_nodelist_entry(entry, sponsor_pub)
