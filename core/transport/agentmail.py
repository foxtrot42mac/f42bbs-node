import json
from typing import Optional

from envelope import Envelope, EnvelopeError


def strip_footer(body: str) -> str:
    """Remove trailing AgentMail footer starting with "\\n--\\n" or "\\n\\n--\\n"."""
    footer_markers = ["\n--\n", "\n\n--\n"]
    for marker in footer_markers:
        if marker in body:
            return body.split(marker)[0]
    return body


def parse_envelope_from_mail(raw: str, key: str) -> Optional[Envelope]:
    """Parse envelope from raw mail content.
    
    Strip footer from raw, try json.loads, then Envelope.parse.
    Return None if any step fails.
    """
    stripped = strip_footer(raw)
    
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    
    try:
        return Envelope.parse(data, key)
    except EnvelopeError:
        return None


class AgentMailTransport:
    """F42BBS protocol AgentMail transport binding."""
    
    def __init__(self, inbox_id: str, shared_key: str, poll_interval: int = 60) -> None:
        """Initialize AgentMailTransport.
        
        Args:
            inbox_id: The AgentMail inbox identifier
            shared_key: Shared key for envelope encryption
            poll_interval: Polling interval in seconds (default: 60)
        """
        self.inbox_id = inbox_id
        self.shared_key = shared_key
        self.poll_interval = poll_interval
        self._backoff = 0
        self._client = None
    
    def send(self, env: Envelope, to_address: str) -> None:
        """Send an envelope via AgentMail.
        
        Args:
            env: The envelope to send
            to_address: Recipient address
        """
        if self._client is None:
            raise RuntimeError("AgentMail client not configured")
        
        self._client.send_message(
            inbox_id=self.inbox_id,
            to=[to_address],
            subject=f"[{env.topic}] {env.subject}",
            text=json.dumps(env.emit())
        )
    
    def _on_rate_limit(self) -> None:
        """Handle rate limit by exponential backoff."""
        if self._backoff == 0:
            self._backoff = 60
        else:
            self._backoff = min(self._backoff * 2, 3600)
    
    def _on_success(self) -> None:
        """Reset backoff on successful operation."""
        self._backoff = 0