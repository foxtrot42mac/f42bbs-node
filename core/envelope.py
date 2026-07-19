import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any


class EnvelopeError(Exception):
    pass


def make_msg_id(origin: str, timestamp: str, body: str) -> str:
    hash_input = origin + timestamp + body
    hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    return origin + "-" + hash_value


def sign(key: str, msg_id: str, origin: str, topic: str, body: str) -> str:
    sign_input = msg_id + origin + topic + body
    return hmac.new(key.encode(), sign_input.encode(), hashlib.sha256).hexdigest()


def verify(key: str, msg_id: str, origin: str, topic: str, body: str, hmac_val: str) -> bool:
    expected = sign(key, msg_id, origin, topic, body)
    return hmac.compare_digest(expected, hmac_val)


@dataclass
class Envelope:
    ver: str
    type: str
    msg_id: str
    origin: str
    topic: str
    from_: str
    to: str
    subject: str
    timestamp: str
    hops: list
    max_hops: int
    hmac: str
    body: str
    refs: list = field(default_factory=list)

    @classmethod
    def parse(cls, data: dict, key: str) -> "Envelope":
        required_fields = [
            "ver", "type", "msg_id", "origin", "topic", "from",
            "to", "subject", "timestamp", "hops", "max_hops", "hmac", "body", "refs"
        ]
        
        for field_name in required_fields:
            if field_name not in data:
                raise EnvelopeError(f"missing field: {field_name}")
        
        if data["ver"] != "0.2":
            raise EnvelopeError("unsupported ver")
        
        if not verify(key, data["msg_id"], data["origin"], data["topic"], data["body"], data["hmac"]):
            raise EnvelopeError("hmac mismatch")
        
        if data["type"] == "DIGEST" and data["refs"] == []:
            raise EnvelopeError("DIGEST requires refs")
        
        return cls(
            ver=data["ver"],
            type=data["type"],
            msg_id=data["msg_id"],
            origin=data["origin"],
            topic=data["topic"],
            from_=data["from"],
            to=data["to"],
            subject=data["subject"],
            timestamp=data["timestamp"],
            hops=data["hops"],
            max_hops=data["max_hops"],
            hmac=data["hmac"],
            body=data["body"],
            refs=data["refs"]
        )

    def emit(self) -> dict:
        return {
            "ver": self.ver,
            "type": self.type,
            "msg_id": self.msg_id,
            "origin": self.origin,
            "topic": self.topic,
            "from": self.from_,
            "to": self.to,
            "subject": self.subject,
            "timestamp": self.timestamp,
            "hops": self.hops,
            "max_hops": self.max_hops,
            "hmac": self.hmac,
            "body": self.body,
            "refs": self.refs
        }