# F42BBS

FidoNet-style federated message network over HTTPS with end-to-end encryption.

## Quick Install

```bash
git clone https://github.com/foxtrot42mac/f42bbs
cd f42bbs
sudo bash init/f42bbs-init.sh --addr 1:42/4 --peer https://foxtrot42.org/bbs/f42bbs/inbound
```

Then on root node: `f42bbs-admin admit 1:42/4`

→ See [DEPLOY.md](DEPLOY.md) for full guide.

## Architecture

```
/opt/f42bbs/
  core/    step_server, daemon, db, crypto, keystore, signing
  admin/   CLI (f42bbs-admin)
  bot/     local bot + plugins
  mcp/     session-based MCP server
```

## Key features

- **Federation**: nodes exchange messages via HTTP POST, ed25519-signed (B3/B4)
- **Encryption**: X25519 P2P + SecretBox conferences (M1-M5)
- **Identity**: points = per-user keys stored on node, OTP-based session auth
- **MCP**: charlie-style sliding session_id, connect from claude.ai
- **Bot**: local `1:42/N.0` assistant, direct message, plugin-based

## CLI

```bash
f42bbs-admin addpoint --label alice   # create user, print OTP
f42bbs-admin genotp  1:42/4.1        # new OTP for existing user
f42bbs-admin admit                    # list / approve new nodes
f42bbs-admin status                   # node status
```

## MCP

Connect at `https://your-domain/bbs-mcp`:

```
bbs_claim(otp)             → session_id + point_addr
bbs_step(session_id, cmd)  → result + new session_id
```

Commands: `help status whoami points nodes genotp publish get sp rp`

## Repo

- `foxtrot42mac/f42bbs` — this repo (node software)
- `tango4004/f42charlie` — Charlie MCP server
