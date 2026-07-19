#!/usr/bin/env python3
"""Called by f42bbs-init.sh to generate node keypairs and genesis."""
import sys, os
sys.path.insert(0, "/opt/f42bbs/core")
import keystore, signing

NODE_ADDR = os.environ["NODE_ADDR"]
keystore.KEYS_FILE    = os.environ["F42BBS_KEYS"]
keystore.GENESIS_FILE = os.environ["F42BBS_GENESIS"]

pubs = keystore.init_keys(NODE_ADDR)
ed_priv, ed_pub = keystore.get_ed25519(NODE_ADDR)
x_priv,  x_pub  = keystore.get_x25519(NODE_ADDR)

keystore.init_genesis([ed_pub], threshold=1)

entry = signing.sign_nodelist_entry({
    "addr": NODE_ADDR, "ed25519_pub": ed_pub,
    "x25519_pub": x_pub, "sponsor_addr": NODE_ADDR,
}, ed_priv)
data = keystore._load()
data["nodelist"] = [entry]
keystore._save(data)

print(f"  ed25519: {ed_pub[:24]}...")
print(f"  x25519:  {x_pub[:24]}...")
print(f"  genesis: root={ed_pub[:24]}...")
