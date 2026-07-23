#!/bin/bash
# f42bbs-init.sh — bootstrap a new F42BBS node
# Usage: sudo bash f42bbs-init.sh --addr 1:42/3 [options]
#   --addr     1:42/3          Node address (required)
#   --port     8001            Step server port
#   --mcp-port 8006            MCP server port
#   --peer     http://...      Peer inbound URL
#   --label    mynode          Human label
#   --data-dir /var/lib/f42bbs Data directory
#   --user     f42bbs          System user
#   --no-bot                   Skip bot
#   --no-mcp                   Skip MCP

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

NODE_ADDR="" STEP_PORT=8001 MCP_PORT=8006 PEER_URL=""
NODE_LABEL="" DATA_DIR="/var/lib/f42bbs" SVC_USER="f42bbs"
INSTALL_BOT=1 INSTALL_MCP=1

while [[ $# -gt 0 ]]; do case $1 in
  --addr)     NODE_ADDR="$2";   shift 2 ;;
  --port)     STEP_PORT="$2";   shift 2 ;;
  --mcp-port) MCP_PORT="$2";    shift 2 ;;
  --peer)     PEER_URL="$2";    shift 2 ;;
  --label)    NODE_LABEL="$2";  shift 2 ;;
  --data-dir) DATA_DIR="$2";    shift 2 ;;
  --user)     SVC_USER="$2";    shift 2 ;;
  --no-bot)   INSTALL_BOT=0;    shift   ;;
  --no-mcp)   INSTALL_MCP=0;    shift   ;;
  *) echo "unknown: $1"; exit 1 ;;
esac; done

[[ -z "$NODE_ADDR" ]] && { echo "error: --addr required"; exit 1; }
NODE_LABEL="${NODE_LABEL:-$NODE_ADDR}"
INSTALL_DIR="/opt/f42bbs"
VENV="$INSTALL_DIR/venv"

echo "F42BBS Init: $NODE_ADDR  port=$STEP_PORT  data=$DATA_DIR  user=$SVC_USER"

# 1. system user
id "$SVC_USER" &>/dev/null || useradd -r -s /sbin/nologin -d "$DATA_DIR" "$SVC_USER"
echo "[1/8] user: $SVC_USER"

# 2. directories
mkdir -p "$DATA_DIR"/{keys,db,plugins} "$INSTALL_DIR"/{core,admin,bot/plugins,mcp}
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR" "$INSTALL_DIR"
chmod 750 "$DATA_DIR"; chmod 700 "$DATA_DIR/keys"
echo "[2/8] directories created"

# 3. install code
cp "$REPO_DIR"/core/*.py           "$INSTALL_DIR/core/"
cp -r "$REPO_DIR"/core/transport   "$INSTALL_DIR/core/"
cp "$REPO_DIR"/admin/*.py          "$INSTALL_DIR/admin/"
cp "$REPO_DIR"/bot/bot.py          "$INSTALL_DIR/bot/"
cp "$REPO_DIR"/bot/plugins/*.py    "$INSTALL_DIR/bot/plugins/"
cp "$REPO_DIR"/mcp/*.py            "$INSTALL_DIR/mcp/"
cp "$REPO_DIR"/core/crypto.py      "$INSTALL_DIR/mcp/"
cp "$REPO_DIR"/core/keystore.py    "$INSTALL_DIR/mcp/"
cp "$REPO_DIR"/core/signing.py     "$INSTALL_DIR/mcp/"  # used by keystore/crypto
cp "$REPO_DIR"/core/requirements.txt "$INSTALL_DIR/"
cp "$REPO_DIR"/init/init_keys.py "$INSTALL_DIR/"
chown -R "$SVC_USER:$SVC_USER" "$INSTALL_DIR"
# nodes.json required by step_server (legacy peer discovery)
echo '{"nodes":[]}' > "$INSTALL_DIR/core/nodes.json"
chown "$SVC_USER:$SVC_USER" "$INSTALL_DIR/core/nodes.json"
echo "[3/8] code installed to $INSTALL_DIR"

# 4. venv
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q flask python-dotenv requests pynacl
chown -R "$SVC_USER:$SVC_USER" "$VENV"
echo "[4/8] venv ready"

# 5. generate keys
F42BBS_KEY=$(python3 -c "import secrets; print(secrets.token_hex(24))")
sudo -u "$SVC_USER" \
  F42BBS_KEYS="$DATA_DIR/keys/node.keys" \
  F42BBS_GENESIS="$DATA_DIR/keys/genesis.json" \
  NODE_ADDR="$NODE_ADDR" \
  "$VENV/bin/python3" /opt/f42bbs/init_keys.py
echo "[5/8] keys generated"

# 6. config
cat > "$DATA_DIR/node.env" << ENVEOF
F42BBS_NODE_ID=$NODE_ADDR
F42BBS_KEY=$F42BBS_KEY
F42BBS_DB=$DATA_DIR/db/f42bbs.db
STEP_PORT=$STEP_PORT
F42BBS_PEER_URLS=$PEER_URL
F42BBS_DATA_DIR=$DATA_DIR
F42BBS_KEYS=$DATA_DIR/keys/node.keys
F42BBS_GENESIS=$DATA_DIR/keys/genesis.json
F42BBS_STEP_URL=http://localhost:$STEP_PORT
BBS_MCP_PORT=$MCP_PORT
BBS_MCP_PATH=/bbs-mcp
F42BBS_CONNECTORS=
ENVEOF
chmod 640 "$DATA_DIR/node.env"
chown "$SVC_USER:$SVC_USER" "$DATA_DIR/node.env"

cat > /usr/local/bin/f42bbs-admin << WRAPEOF
#!/bin/bash
set -a; source $DATA_DIR/node.env; set +a
exec sudo -u $SVC_USER $VENV/bin/python3 /opt/f42bbs/admin/f42bbs_admin.py "\$@"
WRAPEOF
chmod +x /usr/local/bin/f42bbs-admin
echo "[6/8] config written"

# 7. systemd units
cat > /etc/systemd/system/f42bbs.service << SVCEOF
[Unit]
Description=F42BBS Node $NODE_ADDR
After=network.target
[Service]
User=$SVC_USER
WorkingDirectory=/opt/f42bbs/core
ExecStart=$VENV/bin/python3 step_server.py
Restart=always
RestartSec=5
EnvironmentFile=$DATA_DIR/node.env
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF

[[ $INSTALL_BOT -eq 1 ]] && cat > /etc/systemd/system/f42bbs-bot.service << SVCEOF
[Unit]
Description=F42BBS Bot ${NODE_ADDR}.0
After=f42bbs.service
[Service]
User=$SVC_USER
WorkingDirectory=/opt/f42bbs/bot
ExecStart=$VENV/bin/python3 bot.py
Restart=always
RestartSec=5
EnvironmentFile=$DATA_DIR/node.env
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF

[[ $INSTALL_MCP -eq 1 ]] && cat > /etc/systemd/system/f42bbs-mcp.service << SVCEOF
[Unit]
Description=F42BBS MCP $NODE_ADDR
After=f42bbs.service
[Service]
User=$SVC_USER
WorkingDirectory=/opt/f42bbs/mcp
ExecStart=$VENV/bin/python3 bbs_mcp_server.py
Restart=always
RestartSec=5
EnvironmentFile=$DATA_DIR/node.env
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
SVCEOF
echo "[7/8] systemd units installed"

# 8. start
systemctl daemon-reload
systemctl enable --now f42bbs
[[ $INSTALL_BOT -eq 1 ]] && systemctl enable --now f42bbs-bot  || true
[[ $INSTALL_MCP -eq 1 ]] && systemctl enable --now f42bbs-mcp || true
sleep 3

echo "[8/8] services started"
echo
echo "=== F42BBS Init Complete ==="
curl -s http://localhost:$STEP_PORT/health && echo "  step_server OK"
echo
echo "Next steps:"
echo "  f42bbs-admin addpoint --label admin --role admin"
echo "  f42bbs-admin status"
