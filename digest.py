"""
F42BBS digest.py — Digest Broadcast: header/body objects, canonical
signing, dedup, and the deterministic (non-LLM) filter cascade.

Spec: Digest Broadcast draft v0.1 (Opus, 2026-07-23).
Implements §2 (structure), §5 (signing), §6.1 (cascade [0]-[3], no LLM).
LLM-judge (§6.2-6.6) is a separate module, added when there's a real
stream to reversal-test against -- per spec §8, digest works without it.
"""
from __future__ import annotations
import hashlib, json
import time
import secrets
from typing import Optional

from signing import canonical_json, sign_dict, verify_dict

# ── §5: what's signed vs transport-only ────────────────────────────────────
# body_avail changes as the digest propagates through the network; if it
# were part of the signature, every node adding itself to the list would
# break verification. Everything else in the header is signer-committed.
HEADER_SIGNED_FIELDS = frozenset([
    "v", "id", "topic", "title", "origin", "created",
    "body_sha256", "body_size", "lang", "kind", "tags"
])
HEADER_EXCLUDED_FROM_SIG = frozenset(["sig", "body_avail"])

BODY_EXCLUDED_FROM_SIG = frozenset(["sig"])

# ── §2.1 limits ──────────────────────────────────────────────────────────
HEADER_TARGET_BYTES = 512
HEADER_HARD_CAP_BYTES = 1024
TITLE_MAX_CHARS = 120
BODY_HARD_CAP_BYTES = 1024  # §2.2 -- larger content is a "dataset", link out

VALID_KINDS = frozenset(["result", "dataset", "question", "announce", "index", "revoke"])


class DigestError(Exception):
    pass


# ── §2: construction ────────────────────────────────────────────────────────

def make_digest_id() -> str:
    return "dg-" + secrets.token_hex(8)


def make_header(
    *, topic: str, title: str, origin: str, body_obj: dict,
    lang: str = "en", kind: str = "result", tags: Optional[list[str]] = None,
    priv_b64: str, digest_id: Optional[str] = None,
) -> dict:
    """
    Build and sign a digest header. body_obj is the (unsigned-yet) body
    dict this header will pair with -- we hash its canonical form (minus
    sig) so header.body_sha256 covers the WHOLE body, not just content
    (see verify_body_matches_header for why). Caller builds body_obj via
    _body_shape() below, then signs it separately with make_body_signed().
    """
    if kind not in VALID_KINDS:
        raise DigestError(f"invalid kind: {kind}")
    if len(title) > TITLE_MAX_CHARS:
        raise DigestError(f"title exceeds {TITLE_MAX_CHARS} chars")
    if not _valid_topic(topic):
        raise DigestError(f"invalid topic: {topic}")

    content_bytes = body_obj.get("content", "").encode("utf-8")
    if len(content_bytes) > BODY_HARD_CAP_BYTES:
        raise DigestError(
            f"body exceeds {BODY_HARD_CAP_BYTES}B hard cap "
            f"({len(content_bytes)}B) -- this is a 'dataset', publish a "
            f"description + contact, not the content itself"
        )

    body_canon = canonical_json(body_obj, excluded=frozenset(["sig"]))

    header = {
        "v": 1,
        "id": digest_id or body_obj["id"],
        "topic": topic,
        "title": title,
        "origin": origin,
        "created": int(time.time()),
        "body_sha256": hashlib.sha256(body_canon).hexdigest(),
        "body_size": len(content_bytes),
        "body_avail": [origin],  # transport field, not signed -- see below
        "lang": lang,
        "kind": kind,
        "tags": list(tags or []),  # v0.2 (Grok): fine-grained filter, cheaper than title parsing
    }

    signed = sign_dict(header, priv_b64,
                        excluded=HEADER_EXCLUDED_FROM_SIG, sig_field="sig")

    size = len(canonical_json(signed))
    if size > HEADER_HARD_CAP_BYTES:
        raise DigestError(f"header {size}B exceeds {HEADER_HARD_CAP_BYTES}B hard cap")

    return signed


def _body_shape(*, digest_id: str, content: str, content_type: str = "text/markdown",
                 refs: list = None, produced_by: str, method: str = "unknown") -> dict:
    """
    Build the unsigned body dict shape. Split from signing so make_header
    can hash this exact shape (see BLOCKER 1 fix) before the body itself
    is signed -- header and body are two objects, but body_sha256 must
    commit to everything in the body, not just its content string.
    """
    if method not in ("measured", "derived", "cited", "generated", "unknown"):
        raise DigestError(f"invalid provenance.method: {method}")
    return {
        "v": 1,
        "id": digest_id,
        "content_type": content_type,
        "content": content,
        "refs": refs or [],
        "provenance": {
            "produced_by": produced_by,
            "produced_at": int(time.time()),
            "method": method,
        },
    }


def sign_body(body_obj: dict, priv_b64: str) -> dict:
    """Signs a body dict built by _body_shape(). Separate step, see make_header docstring."""
    return sign_dict(body_obj, priv_b64, excluded=BODY_EXCLUDED_FROM_SIG, sig_field="sig")


def make_digest(*, topic: str, title: str, origin: str, content: str,
                 content_type: str = "text/markdown", refs: list = None,
                 method: str = "unknown", lang: str = "en", kind: str = "result",
                 tags: Optional[list[str]] = None, priv_b64: str,
                 digest_id: Optional[str] = None) -> tuple[dict, dict]:
    """
    Convenience: builds header+body together with correct hash linkage.
    Prefer this over calling make_header/_body_shape/sign_body separately
    unless you have a reason to build body first (e.g. deriving digest_id
    from body content). Returns (header, signed_body).
    """
    digest_id = digest_id or make_digest_id()
    body_obj = _body_shape(digest_id=digest_id, content=content, content_type=content_type,
                            refs=refs, produced_by=origin, method=method)
    header = make_header(topic=topic, title=title, origin=origin, body_obj=body_obj,
                          lang=lang, kind=kind, tags=tags, priv_b64=priv_b64,
                          digest_id=digest_id)
    signed_body = sign_body(body_obj, priv_b64)
    return header, signed_body


def make_revoke(*, target_id: str, origin: str, reason: str, priv_b64: str,
                 supersedes: Optional[str] = None) -> dict:
    """
    supersedes (v0.2, Grok): when reason='superseded', names the new
    digest id that replaces target_id -- lets a reader follow an update
    chain instead of just knowing the old one is dead.
    """
    if reason not in ("superseded", "error", "withdrawn"):
        raise DigestError(f"invalid revoke reason: {reason}")
    if reason == "superseded" and not supersedes:
        raise DigestError("reason='superseded' requires supersedes=<new digest id>")
    revoke = {"v": 1, "kind": "revoke", "target": target_id,
              "origin": origin, "reason": reason}
    if supersedes:
        revoke["supersedes"] = supersedes
    return sign_dict(revoke, priv_b64, excluded=frozenset(["sig"]), sig_field="sig")


# ── §5: verification ────────────────────────────────────────────────────────

def verify_header(header: dict, pub_b64: str) -> bool:
    """Verifies signature over HEADER_SIGNED_FIELDS only (body_avail excluded)."""
    return verify_dict(header, pub_b64,
                        excluded=HEADER_EXCLUDED_FROM_SIG, sig_field="sig")


def verify_body(body: dict, pub_b64: str) -> bool:
    return verify_dict(body, pub_b64, excluded=BODY_EXCLUDED_FROM_SIG, sig_field="sig")


def verify_body_matches_header(body: dict, header: dict) -> bool:
    """
    Body integrity is via body_sha256 in the header, not a shared signature.
    Hashes the CANONICAL FORM OF THE WHOLE BODY (minus sig), not just
    content -- otherwise provenance/refs/id can be swapped in transit
    without breaking this check (found by Claude Opus, 2026-07-24).
    id is included in the hash, so BLOCKER 2 (body swapped between
    different digest ids with matching content) closes as a side effect.
    """
    canon = canonical_json(body, excluded=frozenset(["sig"]))
    return hashlib.sha256(canon).hexdigest() == header.get("body_sha256")


# ── §3: topic validation ─────────────────────────────────────────────────────

_TOPIC_ROOTS = frozenset(["research", "data", "ops", "net", "meta", "announce"])
_TOPIC_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")


def _valid_topic(topic: str) -> bool:
    if not topic or any(c not in _TOPIC_CHARS for c in topic):
        return False
    parts = topic.split(".")
    if len(parts) > 4:
        return False
    if parts[0] not in _TOPIC_ROOTS:
        return False
    return all(parts)  # no empty segments (e.g. "research..x")


def topic_matches_subscription(topic: str, subscription_prefix: str) -> bool:
    """§3: prefix match -- 'research.crypto' catches 'research.crypto.ecdlp'."""
    return topic == subscription_prefix or topic.startswith(subscription_prefix + ".")


# ── §6.1: deterministic cascade, stages [0]-[3], no LLM ─────────────────────

def content_fingerprint(content: str) -> str:
    """
    Hash of CONTENT TEXT ONLY, independent of provenance/timestamp/refs.
    Used for corroboration detection (cascade_dedup) -- NOT the same as
    header.body_sha256, which now covers the whole body including
    produced_at, so two independent publications of identical text will
    have different body_sha256 (correctly -- their bodies genuinely
    differ) but the same content_fingerprint (their TEXT is the same).
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def cascade_dedup(headers: list[dict], bodies_by_id: dict, seen_ids: set,
                   seen_fingerprints_by_origin: dict
                   ) -> tuple[list[dict], dict, list[dict]]:
    """
    Stage [0]: dedup by id ONLY -- same id seen before means a true
    repeat (retransmission/gossip loop), drop it. Free.

    Same CONTENT (not body_sha256 -- see content_fingerprint) from a
    DIFFERENT id/origin is NOT a duplicate -- it's independent
    corroboration (two publishers citing the same text, kind='cited').
    That's signal, not noise (Opus, 2026-07-24, correcting the original
    spec wording which conflated the two).

    bodies_by_id: {digest_id: body_dict} -- corroboration needs the
    actual content text, which lives in the body, not the header.
    Headers without a known body just skip corroboration detection
    (still pass through as survivors).

    Returns (survivors, {id: repeat_count}, corroborations) where
    corroborations is the subset of survivors whose content matched a
    body already seen from a *different* origin.
    """
    survivors, repeats, corroborations = [], {}, []
    for h in headers:
        key_id = h["id"]
        if key_id in seen_ids:
            repeats[key_id] = repeats.get(key_id, 0) + 1
            continue
        seen_ids.add(key_id)

        body = bodies_by_id.get(key_id)
        content = body.get("content", "") if body is not None else ""
        # Skip corroboration detection on empty/trivial content -- an
        # empty fingerprint from two different publishers doesn't mean
        # they're confirming the same claim, it means neither had a
        # body attached. Threshold is arbitrary but keeps it out of
        # "looks like real corroboration" territory (Opus, 2026-07-24).
        if len(content.encode("utf-8")) >= 32:
            fp = content_fingerprint(content)
            origins_for_fp = seen_fingerprints_by_origin.setdefault(fp, set())
            if origins_for_fp and h["origin"] not in origins_for_fp:
                corroborations.append(h)
            origins_for_fp.add(h["origin"])

        survivors.append(h)
    return survivors, repeats, corroborations


def cascade_metadata_filter(
    headers: list[dict], *,
    topic_prefixes: Optional[list[str]] = None,
    allowed_langs: Optional[set[str]] = None,
    allowed_kinds: Optional[set[str]] = None,
    blocked_origins: Optional[set[str]] = None,
    required_tags: Optional[set[str]] = None,  # v0.2 (Grok): match ANY tag in the set
) -> list[dict]:
    """Stage [1]: metadata filter, no body read. Free. None = accept-all for that field."""
    out = []
    for h in headers:
        if blocked_origins and h["origin"] in blocked_origins:
            continue
        if topic_prefixes and not any(
            topic_matches_subscription(h["topic"], p) for p in topic_prefixes
        ):
            continue
        if allowed_langs and h["lang"] not in allowed_langs:
            continue
        if allowed_kinds and h["kind"] not in allowed_kinds:
            continue
        if required_tags and not (required_tags & set(h.get("tags", []))):
            continue
        out.append(h)
    return out


def cascade_verdict_cache(headers: list[dict], verdict_cache: dict) -> tuple[list[dict], list[dict]]:
    """
    Stage [2]: cache lookup keyed by (origin, topic). Free.
    Returns (cached_verdicts, still_undecided).
    verdict_cache: {(origin, topic): verdict_dict}
    """
    cached, undecided = [], []
    for h in headers:
        key = (h["origin"], h["topic"])
        if key in verdict_cache:
            v = dict(verdict_cache[key])
            v["id"] = h["id"]
            cached.append(v)
        else:
            undecided.append(h)
    return cached, undecided


def _simhash64(text: str) -> int:
    """
    Minimal simhash over whitespace tokens -- cheap, no embedding call.
    sha256 (truncated), not md5 -- no cryptographic need here, but a
    codebase that's ed25519+sha256 everywhere else and md5 in one spot
    invites a "why is this weaker" question on every security review
    (Opus, 2026-07-24, nit but cheap to fix now).
    """
    v = [0] * 64
    for token in text.lower().split():
        h = int(hashlib.sha256(token.encode()).hexdigest()[:16], 16)
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    bits = 0
    for i in range(64):
        if v[i] > 0:
            bits |= (1 << i)
    return bits


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def cascade_near_dup(headers: list[dict], *, hamming_threshold: int = 3) -> tuple[list[dict], dict]:
    """
    Stage [3]: near-dup clustering by title simhash. Cheap (no LLM call).
    Returns (representatives, {cluster_representative_id: [duplicate_ids]}).
    """
    reps: list[tuple[int, dict]] = []
    clusters: dict[str, list[str]] = {}
    representatives = []

    for h in headers:
        sh = _simhash64(h["title"])
        match = next((r for hsh, r in reps if _hamming(sh, hsh) <= hamming_threshold), None)
        if match:
            clusters.setdefault(match["id"], []).append(h["id"])
        else:
            reps.append((sh, h))
            representatives.append(h)

    return representatives, clusters


# ── §5 verification chain: node vouches for point (Doo's variant 2) ────────

def get_node_ed25519_pub(node_addr: str, step_url: str) -> Optional[str]:
    """
    Fetch node's ed25519_pub from the LIVE net.nodelist endpoint -- the
    actual source of truth, not a hardcoded/cached value. Returns None
    if the node isn't in the requesting node's nodelist.
    """
    import requests
    r = requests.get(f"{step_url}/net.nodelist", timeout=10)
    r.raise_for_status()
    nodelist = r.json()
    for entry in nodelist:
        if entry.get("addr") == node_addr:
            return entry.get("ed25519_pub")
    return None


def get_point_ed25519_pub(point_addr: str, node_addr: str, step_url: str) -> Optional[str]:
    """
    Full trust chain for a digest's origin point (Doo's variant 2 --
    node vouches, no per-point lookup):
      1. Fetch node's ed25519_pub from LIVE net.nodelist (not hardcoded).
      2. Fetch net.sigkeys.<node_addr>, verify the NODE's signature over it.
      3. Extract the point's ed25519_pub from the verified list.
    Returns None at any failed step -- caller should treat as unverifiable.
    """
    import requests

    node_pub = get_node_ed25519_pub(node_addr, step_url)
    if not node_pub:
        return None

    r = requests.get(f"{step_url}/raw/net.sigkeys.{node_addr}", timeout=10)
    if r.status_code != 200:
        return None
    envelope = r.json()
    sigkeys_body = json.loads(envelope.get("body", "{}"))

    if not verify_dict(sigkeys_body, node_pub, sig_field="sig"):
        return None  # node's signature over its own points list is invalid

    return sigkeys_body.get("points", {}).get(point_addr)


def verify_digest_full_chain(header: dict, body: Optional[dict], step_url: str) -> bool:
    """
    Convenience: full verification of a received digest using ONLY live
    network sources, no caller-supplied pub keys. This is what a real
    consumer should call, not verify_header/verify_body directly with a
    pub it got from who-knows-where.

    Note (Opus, 2026-07-24): header/body are verified against the SAME
    point_pub (header.origin's key). This assumes the point that signs
    the header also signs the body, even if provenance.produced_by
    names a different producer -- produced_by is a metadata claim about
    who created the content, not a second signer. If that assumption
    ever needs to change (body signed by produced_by instead), this
    function is the one place to update.
    """
    origin = header.get("origin", "")
    # Must be a POINT address (node.N), not a bare node address -- a node
    # is never allowed to publish digests as if it were one of its own
    # points (Opus, 2026-07-24: nodes don't list themselves in their own
    # sigkeys today, but this makes the requirement explicit rather than
    # accidental).
    if "." not in origin:
        return False
    node_addr = origin.rsplit(".", 1)[0]
    point_pub = get_point_ed25519_pub(origin, node_addr, step_url)
    if not point_pub:
        return False
    if not verify_header(header, point_pub):
        return False
    if body is not None:
        if not verify_body(body, point_pub):
            return False
        if not verify_body_matches_header(body, header):
            return False
    return True
