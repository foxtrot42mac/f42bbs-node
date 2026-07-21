"""fs plugin — file system operations"""
import os, re

HELP = "read path=PATH | list path=PATH | mkdir path=PATH"

def _read(args, ctx):
    m = re.search(r"path=([^\s]+)", args)
    if not m:
        return "usage: fs read path=PATH"
    path = m.group(1).strip()
    try:
        with open(path) as f:
            content = f.read(2000)
        return f"{path}:\n{content}"
    except Exception as e:
        return f"error: {e}"

def _list(args, ctx):
    m = re.search(r"path=([^\s]+)", args)
    path = m.group(1).strip() if m else "."
    try:
        entries = os.listdir(path)
        lines = []
        for e in sorted(entries):
            full = os.path.join(path, e)
            size = os.path.getsize(full) if os.path.isfile(full) else "-"
            typ  = "d" if os.path.isdir(full) else "f"
            lines.append(f"  {typ} {e} {size}")
        return f"{path}/\n" + "\n".join(lines[:30])
    except Exception as e:
        return f"error: {e}"

def _mkdir(args, ctx):
    m = re.search(r"path=([^\s]+)", args)
    if not m:
        return "usage: fs mkdir path=PATH"
    path = m.group(1).strip()
    try:
        os.makedirs(path, exist_ok=True)
        return f"created {path}"
    except Exception as e:
        return f"error: {e}"

COMMANDS = {"read": _read, "list": _list, "mkdir": _mkdir}
