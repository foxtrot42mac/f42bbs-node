"""python plugin — write and exec python files"""
import os, subprocess, re, tempfile

HELP = "write file=PATH content=CODE | exec file=PATH | exec cmd=CODE"

def _write(args, ctx):
    m_file    = re.search(r"file=([^\s]+)", args)
    m_content = re.search(r"content=(.+)", args, re.DOTALL)
    if not m_file or not m_content:
        return "usage: python write file=PATH content=CODE"
    path    = m_file.group(1).strip()
    content = m_content.group(1).strip()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return f"written {len(content)} bytes to {path}"

def _exec(args, ctx):
    m_file = re.search(r"file=([^\s]+)", args)
    m_cmd  = re.search(r"cmd=(.+)", args, re.DOTALL)
    if m_file:
        path = m_file.group(1).strip()
        cmd  = ["python3", path]
    elif m_cmd:
        code = m_cmd.group(1).strip()
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            tmp = f.name
        cmd = ["python3", tmp]
    else:
        return "usage: python exec file=PATH or python exec cmd=CODE"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        out = result.stdout[:500] + result.stderr[:200]
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "error: timeout (10s)"
    except Exception as e:
        return f"error: {e}"
    finally:
        if m_cmd:
            try: os.unlink(tmp)
            except: pass

COMMANDS = {"write": _write, "exec": _exec}
