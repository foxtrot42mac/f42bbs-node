import sqlite3
from datetime import datetime, timezone
from typing import Optional, List, Dict


class DB:
    def __init__(self, path: str):
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY,
                type TEXT,
                origin TEXT,
                topic TEXT,
                raw TEXT,
                created_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                node_id TEXT PRIMARY KEY,
                name TEXT,
                address TEXT,
                trust TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                node_id TEXT,
                topic TEXT,
                PRIMARY KEY(node_id, topic)
            )
        """)

        self.connection.commit()

    def close(self):
        self.connection.close()

    def seen(self, msg_id: str) -> bool:
        cursor = self.connection.cursor()
        cursor.execute("SELECT 1 FROM messages WHERE msg_id = ?", (msg_id,))
        return cursor.fetchone() is not None

    def store_msg(self, msg_id: str, type: str, origin: str, topic: str, raw: str):
        cursor = self.connection.cursor()
        created_at = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT OR IGNORE INTO messages
            (msg_id, type, origin, topic, raw, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (msg_id, type, origin, topic, raw, created_at),
        )
        self.connection.commit()

    def msg_count(self) -> int:
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM messages")
        return cursor.fetchone()[0]

    def add_peer(self, node_id: str, name: str, address: str, trust: str):
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO peers
            (node_id, name, address, trust)
            VALUES (?, ?, ?, ?)
            """,
            (node_id, name, address, trust),
        )
        self.connection.commit()

    def get_peers(self, trust: Optional[str] = None) -> List[Dict]:
        cursor = self.connection.cursor()
        if trust is None:
            cursor.execute("SELECT node_id, name, address, trust FROM peers")
        else:
            cursor.execute(
                "SELECT node_id, name, address, trust FROM peers WHERE trust = ?",
                (trust,),
            )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def set_peer_trust(self, node_id: str, trust: str):
        cursor = self.connection.cursor()
        cursor.execute(
            "UPDATE peers SET trust = ? WHERE node_id = ?", (trust, node_id)
        )
        self.connection.commit()

    def subscribe(self, node_id: str, topic: str):
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO subscriptions (node_id, topic) VALUES (?, ?)",
            (node_id, topic),
        )
        self.connection.commit()

    def unsubscribe(self, node_id: str, topic: str):
        cursor = self.connection.cursor()
        cursor.execute(
            "DELETE FROM subscriptions WHERE node_id = ? AND topic = ?",
            (node_id, topic),
        )
        self.connection.commit()

    def get_subscribers(self, topic: str) -> List[str]:
        cursor = self.connection.cursor()
        cursor.execute("SELECT node_id FROM subscriptions WHERE topic = ? OR topic = '*'", (topic,))
        rows = cursor.fetchall()
        return list(set(row[0] for row in rows))

    def get_node_topics(self, node_id: str) -> List[str]:
        cursor = self.connection.cursor()
        cursor.execute("SELECT topic FROM subscriptions WHERE node_id = ?", (node_id,))
        rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_latest_post(self, topic: str):
        """Get latest POST body for a topic (for auto-DIGEST response)"""
        import json as _json
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT raw FROM messages WHERE topic=? AND type='POST' ORDER BY created_at DESC LIMIT 1",
            (topic,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        try:
            d = _json.loads(row[0])
            return d.get('body')
        except Exception:
            return row[0]

    def store_digest(self, corr_msg_id: str, topic: str, body: str):
        """Store incoming DIGEST keyed by corr_msg_id"""
        import time as _time
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO messages (msg_id, type, origin, topic, raw, created_at) VALUES (?,?,?,?,?,?)",
            (f"digest:{corr_msg_id}", 'DIGEST', 'remote', topic, body, int(_time.time()))
        )
        self.connection.commit()

    def get_digest(self, corr_msg_id: str) -> str:
        """Get DIGEST body for a given REQUEST msg_id"""
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT raw FROM messages WHERE msg_id=? AND type='DIGEST'",
            (f"digest:{corr_msg_id}",)
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def get_latest(self, topic: str) -> Optional[str]:
        import json as _json
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT raw FROM messages WHERE topic = ? ORDER BY created_at DESC LIMIT 1",
            (topic,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        try:
            return _json.loads(row[0]).get('body')
        except Exception:
            return row[0]

    def get_latest_raw(self, topic: str):
        """Return full raw envelope JSON for latest message in topic (for crypto ops)."""
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT raw FROM messages WHERE topic = ? ORDER BY created_at DESC LIMIT 1",
            (topic,)
        )
        row = cursor.fetchone()
        return row[0] if row else None
