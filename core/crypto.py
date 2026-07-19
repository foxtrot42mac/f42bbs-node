"""
F42BBS crypto.py — content encryption layer (Phase 1 MVP)
P2P: PyNaCl Box (X25519 + XSalsa20-Poly1305)
Conference: PyNaCl SecretBox (XSalsa20-Poly1305)
"""
from __future__ import annotations
import base64
import hashlib
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox


# ── helpers ──────────────────────────────────────────────────────────────────

def _b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64dec(s: str) -> bytes:
    return base64.b64decode(s)


# ── P2P key management ───────────────────────────────────────────────────────

def keypair_generate() -> tuple:
    """Return (priv_b64, pub_b64) — new X25519 keypair."""
    priv = PrivateKey.generate()
    return _b64enc(bytes(priv)), _b64enc(bytes(priv.public_key))


def keypair_pub(priv_b64: str) -> str:
    """Derive pub_b64 from priv_b64."""
    priv = PrivateKey(_b64dec(priv_b64))
    return _b64enc(bytes(priv.public_key))


# ── P2P encryption ───────────────────────────────────────────────────────────

def encrypt(plaintext: str, recipient_pub_b64: str, sender_priv_b64: str) -> str:
    """
    Encrypt plaintext for recipient.
    Returns ciphertext_b64 (includes nonce).
    Authenticity: Box binds sender priv + recipient pub — decrypt succeeds
    only if sender_priv matches the pub the recipient expects.
    """
    sender_priv = PrivateKey(_b64dec(sender_priv_b64))
    recipient_pub = PublicKey(_b64dec(recipient_pub_b64))
    box = Box(sender_priv, recipient_pub)
    encrypted = box.encrypt(plaintext.encode("utf-8"))
    return _b64enc(encrypted)


def decrypt(ciphertext_b64: str, recipient_priv_b64: str, sender_pub_b64: str) -> str:
    """
    Decrypt ciphertext from sender.
    Raises nacl.exceptions.CryptoError if key mismatch (authenticity check).
    Caller: trust message IFF this succeeds — do NOT rely on envelope 'from' field.
    """
    recipient_priv = PrivateKey(_b64dec(recipient_priv_b64))
    sender_pub = PublicKey(_b64dec(sender_pub_b64))
    box = Box(recipient_priv, sender_pub)
    return box.decrypt(_b64dec(ciphertext_b64)).decode("utf-8")


# ── Direct topic name (hides participants) ────────────────────────────────────

def direct_topic(addr_a: str, addr_b: str, salt: str = "f42bbs-v1") -> str:
    """
    Compute topic name for P2P channel between addr_a and addr_b.
    Uses sorted pair + salt so both sides compute identical name.
    Result: 'direct-<16 hex chars>' — opaque to third parties.

    Known limitation (MVP): topic existence/traffic volume still visible;
    full metadata hiding requires governance-layer visibility-boundary routing.
    """
    pair = "|".join(sorted([addr_a, addr_b])) + "|" + salt
    return "direct-" + hashlib.sha256(pair.encode()).hexdigest()[:16]


# ── Conference (symmetric) ───────────────────────────────────────────────────

def conf_key_generate() -> str:
    """Generate a random 32-byte conference key, return as b64."""
    return _b64enc(nacl.utils.random(SecretBox.KEY_SIZE))


def conf_id(conf_key_b64: str) -> str:
    """Deterministic conf id from key: 'conf-<8 hex chars>'."""
    return "conf-" + hashlib.sha256(_b64dec(conf_key_b64)).hexdigest()[:16]


def conf_encrypt(plaintext: str, conf_key_b64: str) -> str:
    """Encrypt message for a conference. Returns ciphertext_b64."""
    box = SecretBox(_b64dec(conf_key_b64))
    return _b64enc(box.encrypt(plaintext.encode("utf-8")))


def conf_decrypt(ciphertext_b64: str, conf_key_b64: str) -> str:
    """
    Decrypt conference message.
    Raises nacl.exceptions.CryptoError if wrong key.
    """
    box = SecretBox(_b64dec(conf_key_b64))
    return box.decrypt(_b64dec(ciphertext_b64)).decode("utf-8")
