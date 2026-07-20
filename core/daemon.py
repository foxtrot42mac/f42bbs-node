import json
import copy
from typing import Optional, List, Dict
from envelope import Envelope
from db import DB


class Daemon:
    def __init__(self, node_id: str, db: DB, transport, shared_key: str) -> None:
        self.node_id = node_id
        self.db = db
        self.transport = transport
        self.shared_key = shared_key

    def inbound(self, env: Envelope) -> str:
        # 1. SEEN-BY check (only for relay, not origin)
        if self.node_id in env.hops and env.origin != self.node_id:
            return "loop"
        
        # 2. max_hops check
        if len(env.hops) >= env.max_hops:
            return "max_hops"
        
        # 3. Dedup
        if self.db.seen(env.msg_id):
            return "duplicate"
        
        # 4. Store
        self.db.store_msg(
            env.msg_id,
            env.type,
            env.origin,
            env.topic,
            json.dumps(env.emit())
        )
        
        # 5. Handle by type
        if env.topic == "areafix":
            return self._handle_areafix(env)

        if env.topic == "net.nodelist":
            self._handle_nodelist_gossip(env)
            # still fanout so chain propagates


        if env.type == "DIGEST":
            # DIGEST: store keyed by corr ref, do NOT fanout
            corr = next((r for r in (env.refs or []) if r.startswith("corr:")), None)
            if corr:
                corr_id = corr[5:]
                self.db.store_digest(corr_id, env.topic, env.body)
            return "ok_digest"

        if env.type == "REQUEST":
            # AUTO-RESPOND: send DIGEST back with latest POST for this topic
            self._auto_digest(env)

        # 6. Fan-out (POST and REQUEST)
        self._fanout(env)

        # 7. Return ok
        return "ok"

    def _auto_digest(self, req_env) -> None:
        """Respond to REQUEST with a DIGEST of latest POST on that topic"""
        import time as _t
        latest = self.db.get_latest_post(req_env.topic)
        if not latest:
            return  # nothing to answer with
        from envelope import make_msg_id, sign, Envelope
        ts = str(int(_t.time()))
        body = latest
        refs = [f"corr:{req_env.msg_id}"]
        msg_id = make_msg_id(self.node_id, ts, body)
        hmac_val = sign(self.shared_key, msg_id, self.node_id, req_env.topic, body)
        digest = Envelope(
            ver="0.2", type="DIGEST",
            msg_id=msg_id, origin=self.node_id,
            topic=req_env.topic,
            from_=self.node_id, to=req_env.origin,
            subject=f"DIGEST {req_env.topic}",
            timestamp=ts, hops=[self.node_id],
            max_hops=req_env.max_hops,
            hmac=hmac_val, body=body, refs=refs
        )
        self._fanout(digest)


    def _handle_areafix(self, env: Envelope) -> str:
        body = env.body.strip()
        
        if body.startswith("+"):
            topic = body[1:].strip()
            self.db.subscribe(env.origin, topic)
            return "areafix_sub"
        
        if body.startswith("-"):
            topic = body[1:].strip()
            self.db.unsubscribe(env.origin, topic)
            return "areafix_unsub"
        
        if body == "%LIST":
            return "areafix_list"
        
        if body == "%QUERY":
            return "areafix_query"
        
        return "areafix_unknown"

    def _handle_nodelist_gossip(self, env: Envelope) -> None:
        """Update local nodelist+peers from gossip."""
        try:
            import json as _j, sys as _sys, os as _os
            _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
            import keystore as _ks, signing as _sg

            keys_file    = _os.getenv("F42BBS_KEYS")
            genesis_file = _os.getenv("F42BBS_GENESIS")
            if keys_file:    _ks.KEYS_FILE    = keys_file
            if genesis_file: _ks.GENESIS_FILE = genesis_file

            remote_nl = _j.loads(env.body)
            if not isinstance(remote_nl, list):
                return

            genesis = _ks.load_genesis()
            current = _ks.get_nodelist(self.node_id)
            current_addrs = {e.get("addr") for e in current}
            added = 0

            for entry in remote_nl:
                addr = entry.get("addr", "")
                if addr == self.node_id or addr in current_addrs:
                    continue
                # Verify chain
                test_nl = current + [entry]
                if not _sg.verify_nodelist_chain(entry, test_nl, genesis):
                    print(f"[gossip] skip {addr}: chain verify failed", flush=True)
                    continue
                current.append(entry)
                current_addrs.add(addr)
                added += 1
                # Add connectors to peers
                for i, conn in enumerate(entry.get("connectors", [])):
                    pid = addr if i == 0 else f"{addr}#c{i}"
                    try:
                        self.db.add_peer(pid, entry.get("label", addr), conn, "trusted")
                    except Exception:
                        pass

            if added:
                data = _ks._load()
                data["nodelist"] = current
                _ks._save(data)
                print(f"[gossip] added {added} nodes from net.nodelist", flush=True)
        except Exception as _e:
            print(f"[gossip] handle failed: {_e}", flush=True)

    def _fanout(self, env: Envelope) -> None:
        subscribers = self.db.get_subscribers(env.topic)
        
        for node_id in subscribers:
            if node_id == env.origin:
                continue
            if node_id == self.node_id:
                continue
            peers = self.db.get_peers()
            peer = next((p for p in peers if p["node_id"] == node_id), None)
            if peer is None:
                continue
            if peer["trust"] == "blocked":
                continue
            address = peer["address"]
            if address.startswith("agentmail:"):
                address = address[len("agentmail:"):]
            env_copy = copy.deepcopy(env)
            env_copy.hops = env.hops + [self.node_id]
            self.transport.send(env_copy, to_address=address)