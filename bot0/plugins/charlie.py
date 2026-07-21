"""charlie plugin — run shell commands via Charlie MCP or direct"""
import re, subprocess

HELP = "exec cmd=SHELL_CMD | python cmd=PYTHON_CODE"

def _exec(args, ctx):
    m = re.search(r"cmd=(.+)", args, re.DOTALL)
    if not m:
        return "usage: charlie exec cmd=SHELL_CMD"
    cmd = m.group(1).strip()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15,
            cwd="/home/f42agent"
        )
        out = (result.stdout + result.stderr)[:800]
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "error: timeout (15s)"
    except Exception as e:
        return f"error: {e}"

COMMANDS = {"exec": _exec}
