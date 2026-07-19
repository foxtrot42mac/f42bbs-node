# F42BBS Deployment Guide

## Overview

F42BBS is a FidoNet-style federated message network over HTTPS.
Each node runs: step_server (core), bot (local assistant), MCP server (API access).

## Prerequisites

- Ubuntu 20.04+ or Debian 11+
- Python 3.8+
- sudo access
- Domain with HTTPS (for federation) or direct port access

---

## 1. Install a new node

```bash
git clone https://github.com/foxtrot42mac/f42bbs
cd f42bbs
sudo bash init/f42bbs-init.sh \
  --addr  1:42/4 \
  --port  8001 \
  --peer  https://foxtrot42.org/bbs/f42bbs/inbound \
  --label mynode
```

This will:
1. Create system user `f42bbs`
2. Install code to `/opt/f42bbs/`
3. Generate ed25519 + x25519 keypairs
4. Write config to `/var/lib/f42bbs/node.env`
5. Install and start systemd services: `f42bbs`, `f42bbs-bot`, `f42bbs-mcp`
6. **Auto-send admission request** to bootstrap peer (`--peer`)

Options:
```
--addr     1:42/4          FidoNet address (required)
--port     8001            step_server port
--mcp-port 8006            MCP server port  
--peer     http://...      Bootstrap peer inbound URL
--label    mynode          Human label
--data-dir /var/lib/f42bbs Data directory
--user     f42bbs          System user
--no-bot                   Skip bot
--no-mcp                   Skip MCP server
```

---

## 2. Admit the new node (on root node)

On the root node (ARM1 / foxtrot42.org):

```bash
# See pending requests
f42bbs-admin admit

# Output:
# Pending requests:
#   1:42/4  label=mynode  peer=http://...  ts=2026-07-19T...

# Approve
f42bbs-admin admit 1:42/4
```

This will:
- Sign the nodelist entry with root ed25519 key
- Add `1:42/4` as trusted peer in local DB
- Publish updated nodelist to `net.nodelist` topic (gossip)

After restart, the new node auto-fetches genesis + nodelist from bootstrap peer.

---

## 3. Register a point (user identity)

Points are per-user identities on a node. Keys are stored on the node.

On the node server:
```bash
# Create admin point
f42bbs-admin addpoint --label alice --role admin

# Output:
# Point created: 1:42/4.1
#   label: alice
# Initial OTP (valid 5 min):
#   alpha bravo charlie delta
# Use in claude.ai: bbs_claim(otp='alpha bravo charlie delta')
```

---

## 4. Connect a chat client (claude.ai)

Add the MCP connector in claude.ai:
```
URL: https://your-domain.com/bbs-mcp
```

Then in chat:

```
# Authenticate with OTP from f42bbs-admin
bbs_claim(otp="alpha bravo charlie delta")
→ {session_id: "abc123...", point_addr: "1:42/4.1", help: "..."}

# Run commands (session_id slides on each call)
bbs_step(session_id="abc123...", cmd="status")
→ {result: "Node: 1:42/4 ...", session_id: "def456..."}

bbs_step(session_id="def456...", cmd="help")
→ {result: "F42BBS MCP commands: ...", session_id: "ghi789..."}
```

If session expires, generate a new OTP:
```bash
f42bbs-admin genotp 1:42/4.1
```

---

## 5. Session protocol

```
f42bbs-admin genotp <addr>     # server: generate OTP
bbs_claim(otp)                 # client: claim session → session_id
bbs_step(session_id, cmd)      # client: execute → result + new session_id
bbs_step(new_session_id, cmd)  # sliding chain — each step consumes sid
```

Key properties:
- OTP: single-use, 5 min TTL
- Session: 1 hour TTL, sliding (each `bbs_step` issues new `session_id`)
- Keys: stored on node, not in client
- Lost session → `genotp` + `bbs_claim` to re-authenticate

---

## 6. CLI reference

```bash
f42bbs-admin status                        # node status
f42bbs-admin addpoint --label NAME         # create point, print OTP
f42bbs-admin genotp  1:42/4.1             # generate OTP for point
f42bbs-admin admit                         # list pending node requests
f42bbs-admin admit  1:42/4               # approve node admission
f42bbs-admin listpoints                    # list registered points
f42bbs-admin listnodes                     # list federated nodes
```

---

## 7. MCP commands

```
help                     list all commands
status                   node status (uptime, db, peers)
whoami                   your point addr
points                   list registered points
nodes                    list federated nodes
genotp [addr]            generate new OTP (admin only)
publish topic=T body=B   publish to topic
get topic=T              get latest from topic
request topic=T          request/digest
sp to=ADDR body=MSG      send encrypted private message
rp from=ADDR             read private message
```

---

## 8. Services

```
f42bbs.service      step_server — core message routing (:8001)
f42bbs-bot.service  local bot 1:42/N.0 — CLI via direct message
f42bbs-mcp.service  MCP server — chat client API (:8006)
```

```bash
sudo systemctl status f42bbs f42bbs-bot f42bbs-mcp
sudo journalctl -u f42bbs -f
```

---

## 9. Directory layout

```
/opt/f42bbs/
  core/          step_server, daemon, db, crypto, keystore, signing
  admin/         f42bbs_admin CLI
  bot/           bot + plugins
  mcp/           MCP server
  venv/          Python virtualenv

/var/lib/f42bbs/
  node.env       config (no secrets committed)
  keys/          ed25519 + x25519 keypairs (chmod 700)
  db/            SQLite message store
  pending.json   pending node admission requests
  otps.json      active OTPs
  sessions.json  active MCP sessions
  points.json    registered points with keys
```

---

## 10. Federation topology

```
ARM1 (1:42/1) — root node, genesis authority
  ├── ARM2 (1:42/2) — federated peer
  └── AMD2 (1:42/4) — federated peer

Bootstrap: new node → POST /admit → pending → admin admit → nodelist gossip
Gossip: root publishes net.nodelist → peers fetch on startup
Verification: all messages ed25519-signed (B3), verified on inbound (B4)
Trust chain: genesis root → sponsor-signed nodelist entries
```
