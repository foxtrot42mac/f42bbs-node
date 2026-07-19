# F42BBS Node

FidoNet-style federated message network over HTTPS.

## Quick Install

```bash
git clone https://github.com/tango4004/f42bbs-node
cd f42bbs-node
sudo bash init/f42bbs-init.sh --addr 1:42/3 --peer https://foxtrot42.org/bbs/f42bbs/inbound
```

## CLI

```bash
f42bbs-admin addpoint --label doo --role admin   # create admin point
f42bbs-admin genotp 1:42/3.1                     # generate OTP
f42bbs-admin listpoints                          # list points
f42bbs-admin listnodes                           # list federated nodes
f42bbs-admin status                              # node status
```

## MCP

Connect at: `https://<your-domain>/bbs-mcp`

```
bbs_claim(otp)             → session_id + point_addr
bbs_step(session_id, cmd)  → result + new session_id
```

Commands: help, status, whoami, points, nodes, genotp,
publish, get, request, sp (send_private), rp (read_private)

## Architecture

```
/opt/f42bbs/
  core/        step_server, daemon, db, crypto, keystore, signing
  admin/       f42bbs_admin CLI
  bot/         1:42/N.0 local bot, plugins
  mcp/         session-based MCP server

/var/lib/f42bbs/
  node.env     config (no secrets committed)
  keys/        ed25519 + x25519 keypairs (chmod 700)
  db/          SQLite message store
  plugins/     bot plugins
```

## Federation

Nodes federate via HTTP POST to `/f42bbs/inbound`.
All messages are ed25519-signed (B3) and verified on inbound (B4).
Trust chain: genesis root → sponsor-signed nodelist entries.
