#!/usr/bin/env python3
"""Toggle the system proxy onto a residential proxy.

Most apps handle proxy passwords badly, so this runs a small local
forwarder on 127.0.0.1 that adds the login to every request and passes
it on to the upstream proxy. The system proxy is pointed at the
forwarder. Whatever proxy was set before is saved and put back on "off".

Works with macOS network settings, the Windows user proxy settings and
GNOME-based Linux desktops. Set RESPROXY_BACKEND=macos, windows or gnome
to pick one by hand.

Usage: resproxy.py on | off | toggle | status | state | is-on | serve
"""

import ast
import asyncio
import base64
import errno
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import msvcrt
except ImportError:
    msvcrt = None

WINDOWS = sys.platform == "win32"
HERE = Path(__file__).resolve().parent
SCRIPT = str(Path(__file__).resolve())
CONFIG_FILE = HERE / "config.json"


def default_state_dir():
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "resproxy"
    if WINDOWS:
        appdata = os.environ.get("APPDATA")
        return (Path(appdata) if appdata else Path.home() / "AppData" / "Roaming") / "resproxy"
    xdg = os.environ.get("XDG_STATE_HOME", "")
    return (Path(xdg) if os.path.isabs(xdg) else Path.home() / ".local" / "state") / "resproxy"


STATE_DIR = default_state_dir()
PID_FILE = STATE_DIR / "forwarder.pid"
SAVED_FILE = STATE_DIR / "saved-settings.json"
LOG_FILE = STATE_DIR / "forwarder.log"
LOCK_FILE = STATE_DIR / "lock"

PLACEHOLDER_HOST = "proxy.example.com"
LOCK_WAIT = 10
ID_PATH = b"/resproxy-id"


class ProxyError(Exception):
    """Something the user needs to see as a plain message, not a traceback."""


class ConfigError(ProxyError):
    """config.json is missing or wrong."""


def load_config():
    if not CONFIG_FILE.exists():
        raise ConfigError(f"No config.json found. Copy config.example.json to config.json "
                          f"in {HERE} and fill in your proxy details.")
    try:
        # utf-8-sig also takes the BOM Notepad and PowerShell add.
        with open(CONFIG_FILE, encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{CONFIG_FILE} is not valid JSON: {e.msg} "
                          f"(line {e.lineno}, column {e.colno})")
    except UnicodeDecodeError:
        raise ConfigError(f"{CONFIG_FILE} is not saved as UTF-8. Save it as UTF-8 and try again.")
    except OSError as e:
        raise ConfigError(f"Could not read {CONFIG_FILE}: {e}")
    if not isinstance(cfg, dict):
        raise ConfigError(f"{CONFIG_FILE} should hold a JSON object like config.example.json")
    for k in ("upstream_host", "username", "password"):
        v = cfg.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            cfg[k] = str(v)
        elif v is not None and not isinstance(v, str):
            raise ConfigError(f"{k} in {CONFIG_FILE} should be text in quotes")
    missing = [k for k in ("upstream_host", "upstream_port", "username", "password")
               if cfg.get(k) in (None, "") or str(cfg[k]).startswith("YOUR_")
               or cfg[k] == PLACEHOLDER_HOST]
    if missing:
        raise ConfigError(f"Fill in {', '.join(missing)} in {CONFIG_FILE}")
    cfg["upstream_host"] = cfg["upstream_host"].strip()
    if not re.fullmatch(r"[A-Za-z0-9.\-_]+|\[?[0-9A-Fa-f:]+\]?", cfg["upstream_host"]) \
            or re.fullmatch(r"[^:\[\]]+:\d+", cfg["upstream_host"]):
        raise ConfigError(f"upstream_host in {CONFIG_FILE} should be just the host name, like "
                          f"proxy.example.com, with no http:// in front and the port in upstream_port")
    cfg["upstream_host"] = cfg["upstream_host"].strip("[]")
    cfg.setdefault("local_port", 8899)
    for k in ("upstream_port", "local_port"):
        v = cfg[k]
        try:
            cfg[k] = 0 if isinstance(v, (bool, float)) else int(v)
        except (TypeError, ValueError):
            cfg[k] = 0
        if not 0 < cfg[k] < 65536:
            raise ConfigError(f"{k} in {CONFIG_FILE} should be a port number, like 8899")
    services = cfg.get("services") or []
    if not isinstance(services, list) or not all(isinstance(s, str) for s in services):
        raise ConfigError(f'services in {CONFIG_FILE} should be a list of names, like ["Wi-Fi"], or []')
    cfg["services"] = services
    private_config()
    return cfg


def private_config():
    """config.json holds the proxy password, so keep it readable by this user only."""
    if WINDOWS:
        return
    try:
        mode = CONFIG_FILE.stat().st_mode & 0o777
        if not mode & 0o077:
            return
    except OSError:
        return
    try:
        os.chmod(CONFIG_FILE, 0o600)
        print(f"Note: {CONFIG_FILE} could be read by other users, so it was made private to you.",
              file=sys.stderr)
    except OSError as e:
        print(f"Note: {CONFIG_FILE} can be read by other users and could not be made private: "
              f"{e.strerror or e}", file=sys.stderr)


def this_computer(addr):
    """True for a loopback or unspecified address, v4-mapped and scoped v6 too."""
    try:
        ip = ipaddress.ip_address(str(addr).split("%")[0])
    except ValueError:
        return False
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_loopback or ip.is_unspecified


def check_upstream(cfg):
    """Refuse an upstream that is this computer at the forwarder's own port,
    which would send every request back into the forwarder. A name that
    doesn't resolve right now (offline, say) is let through."""
    if cfg["upstream_port"] != cfg["local_port"]:
        return
    try:
        found = socket.getaddrinfo(cfg["upstream_host"], cfg["upstream_port"],
                                   type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return
    for f in found:
        if this_computer(f[4][0]):
            raise ConfigError(f"upstream_host and upstream_port in {CONFIG_FILE} point at this "
                              "computer's own forwarder. Use your proxy provider's host and port.")


# ---------------------------------------------------------------- forwarder

HEAD_LIMIT = 65536
IDLE = 600      # a connection with no traffic either way for this long is closed
LINGER = 45     # once one side has finished, how long the other may stay silent


class HeadTooBig(Exception):
    pass


async def read_head(reader, timeout):
    """Lines of an HTTP head without line endings, or None on EOF. Accepts
    CRLF and bare LF. The whole head must arrive within timeout seconds."""
    lines, size = [], 0
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        left = deadline - loop.time()
        if left <= 0:
            raise asyncio.TimeoutError()
        try:
            line = await asyncio.wait_for(reader.readline(), left)
        except ValueError:
            raise HeadTooBig()
        if not line:
            return None
        size += len(line)
        if size > HEAD_LIMIT:
            raise HeadTooBig()
        if not line.endswith(b"\n"):
            return None
        line = line.rstrip(b"\r\n")
        if not line:
            if lines:
                return lines
            continue
        lines.append(line)


def header(lines, name):
    name = name.lower() + b":"
    for h in lines:
        if h.lower().startswith(name):
            return h[len(name):].strip()
    return None


async def pipe(reader, writer, act):
    """Copy until EOF, then half-close. act["t"] is the last time data moved
    either way; time spent waiting for a peer that doesn't read counts as
    silence. Only tunnel() decides when silence has gone on too long."""
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            act["t"] = loop.time()
            writer.write(data)
            await writer.drain()
            act["t"] = loop.time()
        if writer.can_write_eof():
            writer.write_eof()
    except asyncio.CancelledError:
        writer.close()
    except Exception:
        # A reset on one side is passed on as a reset, not a clean end.
        reset(writer)


def reset(*writers):
    # Reset rather than close, so the other end sees an error and not what
    # looks like a complete reply.
    for w in writers:
        if w is None:
            continue
        try:
            w.get_extra_info("socket").setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH" if WINDOWS else "ii", 1, 0))
        except (AttributeError, OSError):
            pass
        w.transport.abort()


def write_buffers(*writers):
    sizes = []
    for w in writers:
        if w is None:
            continue
        try:
            sizes.append(w.transport.get_write_buffer_size())
        except Exception:
            sizes.append(None)
    return sizes


async def tunnel(client_r, client_w, up_r, up_w):
    """Copy both ways until both sides are done. With no client_r, copy only
    from the upstream to the client. A tunnel silent for IDLE, or silent for
    LINGER once one side has finished, is cut with a reset."""
    loop = asyncio.get_running_loop()
    act = {"t": loop.time()}
    pending = {asyncio.ensure_future(pipe(up_r, client_w, act))}
    if client_r is not None:
        pending.add(asyncio.ensure_future(pipe(client_r, up_w, act)))
    limit = IDLE
    buffered = write_buffers(client_w, up_w)
    while pending:
        done, pending = await asyncio.wait(pending, timeout=5, return_when=asyncio.FIRST_COMPLETED)
        # A peer that reads slowly keeps a write waiting in drain() for a
        # long time; its buffer shrinking still counts as data moving.
        sizes = write_buffers(client_w, up_w)
        if sizes != buffered:
            buffered = sizes
            act["t"] = loop.time()
        if done and limit == IDLE:
            # One side is done. The other may finish its reply for as long
            # as data keeps moving, but not stay silent longer than LINGER.
            # A side stuck writing to a peer that stopped reading can't
            # notice that itself.
            limit = LINGER
            act["t"] = loop.time()
        if pending and loop.time() - act["t"] >= limit:
            for t in pending:
                t.cancel()
            reset(client_w, up_w)
            return


async def drain(writer):
    # A peer that stops reading is reset if the wait times out or is
    # cancelled. A close would wait forever to send what is still buffered.
    try:
        await asyncio.wait_for(writer.drain(), IDLE)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        reset(writer)
        raise


async def copy_exact(reader, writer, n):
    while n > 0:
        data = await asyncio.wait_for(reader.read(min(n, 65536)), IDLE)
        if not data:
            raise ConnectionError("connection closed early")
        n -= len(data)
        writer.write(data)
        await drain(writer)


async def copy_chunked(reader, writer):
    while True:
        line = await asyncio.wait_for(reader.readline(), IDLE)
        if not line.endswith(b"\n"):
            raise ConnectionError("connection closed early")
        writer.write(line)
        size = line.split(b";")[0].strip(b" \t\r\n")
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size):
            raise ConnectionError("bad chunk size")
        size = int(size, 16)
        if size == 0:
            while True:
                line = await asyncio.wait_for(reader.readline(), IDLE)
                if not line.endswith(b"\n"):
                    raise ConnectionError("connection closed early")
                writer.write(line)
                if not line.strip():
                    await drain(writer)
                    return
        await copy_exact(reader, writer, size + 2)


async def copy_body(reader, writer, lines, until_eof):
    """Copy one message body as framed by its head. Without a length, copy
    until the connection closes if until_eof is set, else there is no body."""
    te = header(lines, b"transfer-encoding")
    cl = header(lines, b"content-length")
    if te and b"chunked" in te.lower():
        await copy_chunked(reader, writer)
    elif cl is not None and cl.isdigit():
        await copy_exact(reader, writer, int(cl))
    elif until_eof:
        await tunnel(None, writer, reader, None)


async def send_status(writer, status, body=b""):
    try:
        writer.write(f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n".encode()
                     + (b"Content-Type: text/plain\r\n" if body else b"")
                     + b"Connection: close\r\n\r\n" + body)
        await writer.drain()
    except Exception:
        pass


async def reject(client_r, client_w, status):
    await send_status(client_w, status)
    try:
        client_w.write_eof()
        # Read what the client is still sending so closing doesn't reset the
        # connection before it sees the error.
        while await asyncio.wait_for(client_r.read(65536), 2):
            pass
    except Exception:
        pass


def status_code(line):
    parts = line.split()
    return parts[1] if len(parts) > 1 and line.startswith(b"HTTP/") else b""


# Sent instead of the upstream's 407, so browsers don't ask for a login
# that would be replaced anyway. on looks for this text.
LOGIN_REJECTED = b"The upstream proxy rejected the username or password in config.json.\n"


async def login_rejected(writer):
    log("upstream rejected credentials")
    await send_status(writer, "502 Bad Gateway", LOGIN_REJECTED)


# Never dropped, even if named in Connection: the body is copied as framed by these.
FRAMING = {b"content-length", b"transfer-encoding", b"host"}


def hop_headers(lines, extra=()):
    """Names (lowercase) of the headers that only concern this hop: the
    standard ones and the ones named in Connection. Proxy-* headers are
    always dropped by strip_headers."""
    names = {b"connection", b"keep-alive", b"te"} | set(extra)
    for h in lines:
        if h.lower().startswith(b"connection:"):
            names.update(t.strip().lower() for t in h.split(b":", 1)[1].split(b","))
    return names - FRAMING - {b""}


def strip_headers(lines, names):
    out = []
    for h in lines:
        name = h.split(b":", 1)[0].strip().lower()
        if name not in names and not name.startswith(b"proxy-"):
            out.append(h)
    return out


async def relay_plain(client_r, client_w, up_r, up_w, method, body):
    """One plain HTTP request: pass back exactly one response marked
    Connection: close, then hang up. A second request on the same
    connection would otherwise reach the upstream without the login.
    body is the task still copying the request body."""
    sent = False
    try:
        resp = await read_head(up_r, IDLE)
        while resp and status_code(resp[0]).startswith(b"1") and status_code(resp[0]) != b"101":
            client_w.write(b"\r\n".join(resp) + b"\r\n\r\n")
            sent = True
            resp = await read_head(up_r, IDLE)
        if not resp:
            if not sent:
                await send_status(client_w, "502 Bad Gateway")
            return
        code = status_code(resp[0])
        if code == b"101":
            # Upgraded (a WebSocket, say): from here on it's a plain tunnel.
            # The client may wait for the 101 before sending the rest of the
            # request body, so pass it on first and let the body finish
            # before anything else reads from the client.
            client_w.write(b"\r\n".join(resp) + b"\r\n\r\n")
            await client_w.drain()
            try:
                await body
            except Exception:
                reset(client_w, up_w)
                return
            await tunnel(client_r, client_w, up_r, up_w)
            return
        if code == b"407" and not sent:
            await login_rejected(client_w)
            return
        kept = strip_headers(resp[1:], hop_headers(resp[1:], [b"upgrade"]))
        client_w.write(b"\r\n".join([resp[0]] + kept + [b"Connection: close"]) + b"\r\n\r\n")
        sent = True
        await client_w.drain()
        if method != b"HEAD" and code not in (b"204", b"304"):
            await copy_body(up_r, client_w, resp, True)
    except HeadTooBig:
        if not sent:
            await send_status(client_w, "502 Bad Gateway")
        else:
            reset(client_w, up_w)
    except Exception:
        # Cut short after the reply started: reset, so it can't look complete.
        if sent:
            reset(client_w, up_w)


async def handle_client(client_r, client_w, cfg, auth, token):
    try:
        try:
            head = await read_head(client_r, 30)
        except HeadTooBig:
            await reject(client_r, client_w, "431 Request Header Fields Too Large")
            return
        except Exception:
            return
        if not head:
            return
        request_line, headers = head[0], head[1:]
        parts = request_line.split()
        if len(parts) != 3:
            await reject(client_r, client_w, "400 Bad Request")
            return
        method = parts[0].upper()
        path, _, query = parts[1].partition(b"?")
        if method == b"GET" and path == ID_PATH:
            # Lets resproxy tell its own forwarder apart from anything else
            # on the port or with a reused process ID. The token itself is
            # never sent, only proof of it for the caller's nonce.
            d = {"pid": os.getpid()}
            if re.fullmatch(rb"n=[0-9a-f]{16,64}", query):
                d["proof"] = proof(token, query[2:].decode())
            body = json.dumps(d).encode()
            client_w.write(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                           b"Connection: close\r\n\r\n" + body)
            await client_w.drain()
            return
        is_connect = method == b"CONNECT"
        if not is_connect and parts[1][:7].lower() != b"http://":
            # Only proxy requests (GET http://host/...). A plain "GET /" is
            # someone treating this as a web server; don't send the login on.
            await reject(client_r, client_w, "400 Bad Request")
            return

        # Drop anything the client sent about proxy auth or this hop and add ours.
        upgrade = not is_connect and header(headers, b"upgrade") is not None
        if is_connect:
            kept = strip_headers(headers, set())
        elif upgrade:
            kept = strip_headers(headers, {b"connection", b"keep-alive", b"te"})
        else:
            kept = strip_headers(headers, hop_headers(headers, [b"upgrade"]))
        kept.append(b"Proxy-Authorization: Basic " + auth)
        if upgrade:
            # Keep the client's own tokens (HTTP2-Settings, say), not the
            # ones about this hop.
            tokens = [t.strip() for h in headers if h.lower().startswith(b"connection:")
                      for t in h.split(b":", 1)[1].split(b",")]
            tokens = [t for t in tokens if t and t.lower() not in (b"keep-alive", b"close")
                      and not t.lower().startswith(b"proxy-")]
            if b"upgrade" not in [t.lower() for t in tokens]:
                tokens.insert(0, b"upgrade")
            kept.append(b"Connection: " + b", ".join(tokens))
        elif not is_connect:
            kept.append(b"Connection: close")
        new_head = b"\r\n".join([request_line] + kept) + b"\r\n\r\n"

        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(cfg["upstream_host"], cfg["upstream_port"]), 20)
        except Exception as e:
            await send_status(client_w, "502 Bad Gateway")
            log(f"upstream connect failed: {e}")
            return
        peer = up_w.get_extra_info("peername")
        if peer and peer[1] == cfg["local_port"] and this_computer(peer[0]):
            # The upstream name now leads back to this forwarder.
            up_w.close()
            await send_status(client_w, "508 Loop Detected")
            log(f"upstream {cfg['upstream_host']} is this forwarder, not connecting")
            return
        try:
            up_w.write(new_head)
            await up_w.drain()
            if is_connect:
                try:
                    resp = await read_head(up_r, 60)
                except Exception:
                    resp = None
                if not resp:
                    await send_status(client_w, "502 Bad Gateway")
                    return
                if status_code(resp[0]) == b"407":
                    await login_rejected(client_w)
                    return
                client_w.write(b"\r\n".join(resp) + b"\r\n\r\n")
                await client_w.drain()
                if status_code(resp[0]).startswith(b"2"):
                    await tunnel(client_r, client_w, up_r, up_w)
                else:
                    try:
                        await copy_body(up_r, client_w, resp, False)
                    except Exception:
                        pass
                return
            body = asyncio.ensure_future(copy_body(client_r, up_w, headers, False))
            try:
                await relay_plain(client_r, client_w, up_r, up_w, method, body)
            finally:
                body.cancel()
        finally:
            up_w.close()
    finally:
        client_w.close()


def proof(token, nonce):
    return hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def raise_fd_limit():
    # Apps started from Finder get a soft limit of 256 open files, which a
    # browser's connections use up quickly.
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 10240 if hard == resource.RLIM_INFINITY else min(hard, 10240)
        if soft != resource.RLIM_INFINITY and soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except (ImportError, ValueError, OSError):
        pass


def serve():
    cfg = load_config()
    check_upstream(cfg)
    auth = base64.b64encode(f"{cfg['username']}:{cfg['password']}".encode())
    token = os.environ.pop("RESPROXY_TOKEN", "") or secrets.token_hex(16)
    raise_fd_limit()

    async def main():
        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, cfg, auth, token),
            "127.0.0.1", cfg["local_port"])
        log(f"forwarding 127.0.0.1:{cfg['local_port']} -> "
            f"{cfg['upstream_host']}:{cfg['upstream_port']}")
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", None)):
            raise ProxyError(f"Port {cfg['local_port']} is already in use (is serve already running?)")
        raise ProxyError(f"Could not listen on 127.0.0.1:{cfg['local_port']}: {e.strerror or e}")


# ---------------------------------------------------------- forwarder process

def make_dir(d):
    """Create d (and any missing parents) for this user only, whatever the
    umask, so nobody else can plant a save or PID file in it."""
    missing = [x for x in [d, *d.parents] if not x.exists()]
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if WINDOWS:
        return
    try:
        for x in missing:
            os.chmod(x, 0o700)
        mode = d.stat().st_mode & 0o777
        if mode & 0o077:
            # One made by an older version: only take away other users' access.
            os.chmod(d, mode & 0o700)
    except OSError:
        pass


def atomic_write(path, text):
    tmp = path.with_name(path.name + ".tmp")
    try:
        make_dir(path.parent)
        tmp.unlink(missing_ok=True)
        # Readable by this user only: the PID file holds the forwarder's token.
        with open(os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                         | getattr(os, "O_BINARY", 0), 0o600), "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        raise ProxyError(f"Could not write {path}: {e.strerror or e}")
    if not WINDOWS:
        try:
            fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass


def _try_lock(f):
    try:
        if msvcrt:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, PermissionError):
        return False
    except OSError as e:
        raise ProxyError(f"Could not lock {LOCK_FILE}: {e}")


def _unlock(f):
    try:
        if msvcrt:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(f, fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def locked():
    """Only one on/off at a time (dashboard, menu bar and terminal can overlap)."""
    try:
        make_dir(STATE_DIR)
        f = open(LOCK_FILE, "a+")
    except OSError:
        try:
            f = open(LOCK_FILE, "r")
        except OSError as e:
            raise ProxyError(f"Could not open {LOCK_FILE}: {e}")
    with f:
        deadline = time.monotonic() + LOCK_WAIT
        while not _try_lock(f):
            if time.monotonic() > deadline:
                raise ProxyError("Another on/off is still running. Try again in a moment.")
            time.sleep(0.1)
        try:
            yield
        finally:
            _unlock(f)


@contextmanager
def no_interrupt():
    """Hold off Ctrl-C while settings are being put back."""
    try:
        old = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:
        old = None
    try:
        yield
    finally:
        if old is not None:
            signal.signal(signal.SIGINT, old)


def config_hash(cfg, token):
    raw = json.dumps([token, cfg["upstream_host"], cfg["upstream_port"], cfg["username"],
                      cfg["password"], cfg["local_port"]])
    return hashlib.sha256(raw.encode()).hexdigest()


def _port(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 65536 else None


def forwarder_info():
    """What the PID file says about the forwarder, or None. Older versions
    wrote just the process ID."""
    try:
        text = PID_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        d = json.loads(text)
    except ValueError:
        return None
    if isinstance(d, int) and not isinstance(d, bool):
        d = {"pid": d}
    if not isinstance(d, dict):
        return None
    pid = d.get("pid")
    if not (isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid < 2 ** 31):
        return None
    s = lambda k: d.get(k) if isinstance(d.get(k), str) else None
    token = s("token") if s("token") and re.fullmatch(r"[0-9a-f]+", s("token")) else None
    return {"pid": pid, "token": token, "port": _port(d.get("port")),
            "script": s("script"), "config_hash": s("config_hash")}


def ping(port, nonce="", timeout=1.0):
    """Ask the forwarder on this port who it is. Gives up after timeout
    seconds in all, however slowly the other end answers."""
    deadline = time.monotonic() + timeout
    data = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(b"GET " + ID_PATH + (b"?n=" + nonce.encode() if nonce else b"")
                      + b" HTTP/1.0\r\n\r\n")
            while len(data) < 4096:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                s.settimeout(left)
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.0 200"):
        return None
    try:
        d = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return d if isinstance(d, dict) else None


def running(info):
    """True if the forwarder this info describes is up and answering."""
    if not info or not info.get("token") or not info.get("port"):
        return False
    nonce = secrets.token_hex(16)
    d = ping(info["port"], nonce)
    p = d.get("proof") if d else None
    return isinstance(p, str) and re.fullmatch(r"[0-9a-f]{64}", p) is not None \
        and d.get("pid") == info["pid"] \
        and hmac.compare_digest(p.encode(), proof(info["token"], nonce).encode())


def _reap(pid):
    # If we started it (the dashboard does), reap it so a dead one doesn't
    # linger as a zombie.
    if hasattr(os, "WNOHANG"):
        try:
            os.waitpid(pid, os.WNOHANG)
        except (OSError, OverflowError):
            pass


def owned_process(info):
    """The process in the PID file runs this script's forwarder, judged by
    its command line. Used for one that is stuck or from an older version."""
    if WINDOWS or not info:
        return False
    pid = info["pid"]
    _reap(pid)
    script = info.get("script") or SCRIPT
    if sys.platform.startswith("linux"):
        try:
            args = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        except OSError:
            return False
        cmd = " ".join(a.decode(errors="replace") for a in args)
    else:
        try:
            cmd = subprocess.run(["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return False
    return script in cmd and cmd.endswith(" serve")


def _gone(info):
    if WINDOWS:
        return not running(info)
    pid = info["pid"]
    _reap(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def _wait_gone(info, secs):
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        if _gone(info):
            return True
        time.sleep(0.1)
    return _gone(info)


def find_forwarder(port):
    """A forwarder of this script on the port, found without the PID file
    (lost, or written to another state dir). Only trusted once its command
    line shows it really is one."""
    d = ping(port)
    pid = d.get("pid") if d else None
    if not (isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid < 2 ** 31):
        return None
    info = {"pid": pid, "token": None, "port": port, "script": SCRIPT, "config_hash": None}
    return info if pid != os.getpid() and owned_process(info) else None


def forwarder_pid():
    info = forwarder_info()
    return info["pid"] if running(info) else None


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", int(port))) == 0


LOG_MAX = 1024 * 1024


def spawn_forwarder(token):
    env = dict(os.environ, RESPROXY_TOKEN=token)
    try:
        make_dir(STATE_DIR)
        # Keep the log small: past 1 MB, start a new one and keep one old one.
        try:
            if LOG_FILE.stat().st_size > LOG_MAX:
                os.replace(LOG_FILE, LOG_FILE.with_name(LOG_FILE.name + ".1"))
        except OSError:
            pass
        logf = open(LOG_FILE, "a")
    except OSError as e:
        raise ProxyError(f"Could not write {LOG_FILE}: {e.strerror or e}")
    with logf:
        args = dict(stdout=logf, stderr=logf, stdin=subprocess.DEVNULL, env=env, cwd=str(HERE))
        cmd = [sys.executable, SCRIPT, "serve"]
        if not WINDOWS:
            return subprocess.Popen(cmd, start_new_session=True, **args)
        detached, new_group, breakaway = 0x8, 0x200, 0x01000000
        try:
            # Break away from the terminal's job so closing the window
            # doesn't take the forwarder with it.
            return subprocess.Popen(cmd, creationflags=detached | new_group | breakaway, **args)
        except OSError:
            return subprocess.Popen(cmd, creationflags=detached | new_group, **args)


def start_forwarder(cfg):
    port = cfg["local_port"]
    info = forwarder_info()
    if running(info):
        if info["port"] == port and info.get("config_hash") == config_hash(cfg, info["token"]):
            return info
        # config.json changed since it started: restart it with the new values.
        if not stop_forwarder(info):
            raise ProxyError("The running forwarder did not stop, so the new settings "
                             "in config.json can't be used yet.")
    elif info:
        stop_forwarder(info)
    PID_FILE.unlink(missing_ok=True)
    if port_open(port):
        # Ours with a lost PID file (BROKEN says to run on): stop it first.
        found = find_forwarder(port)
        if found and not stop_forwarder(found):
            raise ProxyError(f"The forwarder on port {port} (process {found['pid']}) did not stop. "
                             "End that process yourself.")
        if port_open(port):
            raise ProxyError(f"Port {port} is already in use by something else. "
                             "Change local_port in config.json.")
    token = secrets.token_hex(16)
    proc = spawn_forwarder(token)
    info = {"pid": proc.pid, "token": token, "port": port, "script": SCRIPT,
            "config_hash": config_hash(cfg, token)}
    try:
        atomic_write(PID_FILE, json.dumps(info))
    except ProxyError:
        # Nothing could find it again without the PID file.
        proc.kill()
        proc.wait()
        raise
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if running(info):
            return info
        time.sleep(0.1)
    stop_forwarder(info)
    raise ProxyError(f"Forwarder did not start. See {LOG_FILE}")


CHECK_TARGET = b"example.com:443"
CHECK_TIMEOUT = 10


def check_login(port):
    """Open one tunnel through the forwarder, so a wrong login shows up now
    rather than as pages that won't load. Only a refused login stops on;
    anything else (offline, say) is just a note. Set RESPROXY_NO_LOGIN_CHECK=1
    to skip it."""
    if os.environ.get("RESPROXY_NO_LOGIN_CHECK"):
        return
    deadline = time.monotonic() + CHECK_TIMEOUT
    data = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=CHECK_TIMEOUT) as s:
            s.sendall(b"CONNECT " + CHECK_TARGET + b" HTTP/1.1\r\nHost: " + CHECK_TARGET + b"\r\n\r\n")
            while len(data) < 4096 and not (b"\r\n\r\n" in data and data.startswith(b"HTTP/1.1 2")):
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout("timed out")
                s.settimeout(left)
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except OSError as e:
        if not data:
            print(f"Note: could not check the proxy login just now ({e}). "
                  "If pages don't load, check your connection and config.json.")
            return
    if LOGIN_REJECTED in data:
        raise ProxyError("The proxy rejected your username or password. Check config.json.")
    if not data.startswith(b"HTTP/1.1 2"):
        status = data.split(b"\r\n", 1)[0].decode("latin-1")[:60] or "no answer"
        print(f"Note: could not check the proxy login just now ({status}). "
              "If pages don't load, check your connection and config.json.")


def stop_forwarder(info=None):
    """Stop our forwarder. Returns False if it is still running afterwards."""
    info = info if info is not None else forwarder_info()
    if info and (running(info) or owned_process(info)):
        pid = info["pid"]
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        if not _wait_gone(info, 3):
            if hasattr(signal, "SIGKILL"):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            if not _wait_gone(info, 2):
                return False
    PID_FILE.unlink(missing_ok=True)
    return True


# ------------------------------------------------------------ system tools

TOOLS = {"networksetup": "/usr/sbin/networksetup", "route": "/sbin/route",
         "ifconfig": "/sbin/ifconfig", "gsettings": "/usr/bin/gsettings"}


def tool(name):
    """Absolute path of a system tool. Apps started from Finder get a bare
    PATH, so don't rely on it. RESPROXY_TOOL_DIR overrides the folder."""
    d = os.environ.get("RESPROXY_TOOL_DIR")
    if d:
        return os.path.join(d, name)
    path = TOOLS[name]
    if name == "gsettings" and not os.path.exists(path):
        path = shutil.which("gsettings") or path
    return path


def utf8_locale():
    """A UTF-8 locale name for child tools if this shell's locale isn't one,
    "" if it already is, or None if none is installed."""
    loc = os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE") or os.environ.get("LANG") or ""
    utf8 = "utf-8" in loc.lower() or "utf8" in loc.lower()
    import locale
    old = locale.setlocale(locale.LC_CTYPE)
    try:
        # The name alone isn't enough: one that isn't installed means C.
        for name in ([loc] if utf8 else []) + ["C.UTF-8", "en_US.UTF-8"]:
            try:
                locale.setlocale(locale.LC_CTYPE, name)
                return "" if utf8 and name == loc else name
            except locale.Error:
                pass
    finally:
        locale.setlocale(locale.LC_CTYPE, old)
    return None


def run_tool(name, *args):
    env = None
    if name == "gsettings":
        # Older GLib prints anything non-ASCII as '?' under a non-UTF-8
        # locale, which would then be saved and written back that way.
        loc = utf8_locale()
        if loc:
            env = dict(os.environ, LC_ALL=loc)
    try:
        return subprocess.run([tool(name), *args], capture_output=True, encoding="utf-8",
                              errors="replace", timeout=30, stdin=subprocess.DEVNULL, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        raise ProxyError(f"Could not run {tool(name)}: {e}")


def dedupe(items):
    seen, out = set(), []
    for i in items:
        if i.lower() not in seen:
            seen.add(i.lower())
            out.append(i)
    return out


# ------------------------------------------------------------ macOS settings

class MacBackend:
    """Network services through networksetup. Each service has its own
    proxy settings, so the ones in use are switched."""
    name = "macos"
    KINDS = ["webproxy", "securewebproxy", "socksfirewallproxy"]
    BLANK = {"enabled": False, "server": "", "port": "0", "auth": False}
    EXTRA_BYPASS = ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16", "100.64.0.0/10",
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    def check(self, cfg):
        if not os.path.exists(tool("networksetup")):
            raise ProxyError(f"{tool('networksetup')} not found. Is this a Mac? "
                             "Set RESPROXY_BACKEND to windows or gnome otherwise.")

    def ns(self, *args):
        r = run_tool("networksetup", *args)
        if r.returncode != 0:
            msg = (r.stdout.strip() or r.stderr.strip() or f"exit status {r.returncode}")
            msg = msg.splitlines()[-1].rstrip(".")
            raise ProxyError(f"networksetup {' '.join(args)} failed: {msg}")
        return r.stdout

    def all_targets(self):
        lines = self.ns("-listallnetworkservices").splitlines()[1:]
        return [l.lstrip("*").strip() for l in lines if l.strip()]

    def iface_active(self, dev):
        try:
            out = run_tool("ifconfig", dev).stdout
        except ProxyError:
            return False
        return "status: active" in out

    def targets(self, cfg):
        """Network services to switch: the ones in config.json, or the one for
        the interface that carries the default route."""
        configured = (cfg or {}).get("services") or []
        if configured:
            known = self.all_targets()
            unknown = [s for s in configured if s not in known]
            if unknown:
                raise ProxyError(f"No network service called {', '.join(unknown)}. "
                                 f"Services on this Mac: {', '.join(known)}")
            return configured
        out = run_tool("route", "-n", "get", "default").stdout
        m = re.search(r"interface:\s*(\S+)", out)
        iface = m.group(1) if m else ""
        order = re.findall(r"\(\d+\)\s*(.+)\n\(Hardware Port: .*?, Device: (\S*)\)",
                           self.ns("-listnetworkserviceorder"))
        for name, dev in order:
            if dev and dev == iface:
                return [name.strip()]
        # The default route is on a VPN tunnel (utun) or missing. Use the first
        # service in the Mac's order whose hardware is actually connected.
        for name, dev in order:
            if dev and self.iface_active(dev):
                return [name.strip()]
        raise ProxyError("Could not tell which network service you're on"
                         + (f" (default route is on {iface}, maybe a VPN)" if iface else "")
                         + '. Set services in config.json, like ["Wi-Fi"].')

    def read_proxy(self, kind, service):
        out = self.ns(f"-get{kind}", service)
        get = lambda key: (re.search(rf"^{key}:[ \t]*(.*)$", out, re.M) or [None, ""])[1].strip()
        return {"enabled": get("Enabled") == "Yes", "server": get("Server"), "port": get("Port"),
                "auth": get("Authenticated Proxy Enabled") == "1"}

    def read_bypass(self, service):
        out = self.ns("-getproxybypassdomains", service).strip()
        if not out or "There aren't any" in out:
            return []
        return out.splitlines()

    def read(self, service):
        snap = {k: self.read_proxy(k, service) for k in self.KINDS}
        snap["bypass"] = self.read_bypass(service)
        return snap

    def valid(self, snap):
        kind_ok = lambda p: isinstance(p, dict) and isinstance(p.get("enabled"), bool) \
            and isinstance(p.get("server"), str) and isinstance(p.get("port"), str) \
            and isinstance(p.get("auth", False), bool)
        return isinstance(snap, dict) and all(kind_ok(snap.get(k)) for k in self.KINDS) \
            and isinstance(snap.get("bypass"), list) and all(isinstance(d, str) for d in snap["bypass"])

    def _ours(self, p, ports):
        return p["enabled"] and p["server"] == "127.0.0.1" and p["port"] in {str(x) for x in ports}

    def is_ours(self, snap, port):
        return self._ours(snap["webproxy"], [port]) and self._ours(snap["securewebproxy"], [port]) \
            and not snap["socksfirewallproxy"]["enabled"]

    def touches_us(self, snap, ports):
        return any(self._ours(snap[k], ports) for k in ("webproxy", "securewebproxy"))

    def without_us(self, snap, ports):
        snap = dict(snap)
        snap.update({k: dict(self.BLANK) for k in self.KINDS if self._ours(snap[k], ports)})
        return snap

    def apply_proxy(self, kind, service, p):
        if p["server"] and p["port"] and p["port"] != "0":
            args = [f"-set{kind}", service, p["server"], p["port"]]
            if p.get("auth"):
                try:
                    self.ns(*args, "on")
                except ProxyError:
                    self.ns(*args)
                    print(f"Note: the old {kind} on {service} used a password. "
                          "Re-enter it in System Settings > Network > Proxies.")
            else:
                self.ns(*args)
        else:
            # No server before. Clear ours so the checkbox doesn't point at a
            # dead forwarder if someone ticks it later.
            try:
                self.ns(f"-set{kind}", service, "", p["port"] if p["port"].isdigit() else "0")
            except ProxyError:
                pass
        self.ns(f"-set{kind}state", service, "on" if p["enabled"] else "off")

    def set_bypass(self, service, domains):
        self.ns("-setproxybypassdomains", service, *(domains or ["Empty"]))

    def apply_ours(self, service, orig, port):
        ours = {"enabled": True, "server": "127.0.0.1", "port": str(port)}
        self.apply_proxy("webproxy", service, ours)
        self.apply_proxy("securewebproxy", service, ours)
        self.ns("-setsocksfirewallproxystate", service, "off")
        self.set_bypass(service, dedupe(orig["bypass"] + self.EXTRA_BYPASS))

    def restore(self, service, saved, cur, notes=None):
        """Put one service back as saved. Returns a list of errors."""
        errors = []
        # SOCKS and bypass first, web and secure last.
        for k in ("socksfirewallproxy", "bypass", "webproxy", "securewebproxy"):
            if cur.get(k) == saved[k]:
                continue
            try:
                if k == "bypass":
                    self.set_bypass(service, saved[k])
                else:
                    self.apply_proxy(k, service, saved[k])
            except ProxyError as e:
                errors.append(str(e))
        return errors

    def clear_ours(self, service, cur, ports):
        errors = []
        for k in ("webproxy", "securewebproxy"):
            if self._ours(cur[k], ports):
                try:
                    self.apply_proxy(k, service, self.BLANK)
                except ProxyError as e:
                    errors.append(str(e))
        return errors

    def notes(self, service, snap):
        try:
            pac = self.ns("-getautoproxyurl", service)
            wpad = self.ns("-getproxyautodiscovery", service)
        except ProxyError:
            return []
        if re.search(r"^Enabled:\s*Yes", pac, re.M) or re.search(r":\s*On\b", wpad):
            return [f"{service} has automatic proxy configuration on. "
                    "Some apps may use that instead of this proxy."]
        return []

    def describe(self, snap):
        p = snap["webproxy"]
        return f"{p['server']}:{p['port']}" if p["enabled"] else "no proxy"

    def system_proxies(self, snap):
        out = {}
        for scheme, k in (("http", "webproxy"), ("https", "securewebproxy")):
            p = snap[k]
            if p["enabled"] and p["server"]:
                out[scheme] = f"http://{p['server']}:{p['port']}"
        return out

    def label(self, targets):
        return ", ".join(targets)


# ------------------------------------------------------------ Windows settings

class WindowsBackend:
    """The current user's Internet Settings in the registry (WinINET), which
    browsers and most apps follow. WinHTTP (netsh winhttp) is not changed."""
    name = "windows"
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    CONN_KEY = KEY + r"\Connections"
    VALUES = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"]
    BLOB = "DefaultConnectionSettings"
    # No CIDR here, so the private ranges are spelled as wildcards. <local>
    # is names without a dot, like a printer or router.
    EXTRA_BYPASS = ["localhost", "127.0.0.1", "[::1]", "*.local", "169.254.*", "10.*", "192.168.*"] \
        + [f"172.{n}.*" for n in range(16, 32)] + ["<local>"]

    def reg(self):
        try:
            import winreg
        except ImportError:
            raise ProxyError("The windows setting needs Windows.")
        return winreg

    def check(self, cfg):
        self.reg()

    def targets(self, cfg):
        return ["user"]

    def all_targets(self):
        return ["user"]

    def _where(self, name):
        return self.CONN_KEY if name == self.BLOB else self.KEY

    def _get(self, name):
        winreg = self.reg()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._where(name)) as k:
                value, kind = winreg.QueryValueEx(k, name)
        except FileNotFoundError:
            return {"present": False}
        except OSError as e:
            raise ProxyError(f"Could not read {name} from the registry: {e}")
        if value is None:
            # An empty binary value reads back as None.
            value = b""
        if isinstance(value, bytes):
            return {"present": True, "type": kind, "b64": base64.b64encode(value).decode()}
        return {"present": True, "type": kind, "value": value}

    def _put(self, name, entry):
        winreg = self.reg()
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self._where(name), 0,
                                    winreg.KEY_SET_VALUE) as k:
                if not entry.get("present"):
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
                    return
                value = base64.b64decode(entry["b64"]) if "b64" in entry else entry["value"]
                winreg.SetValueEx(k, name, 0, entry["type"], value)
        except (OSError, ValueError, TypeError) as e:
            raise ProxyError(f"Could not write {name} to the registry: {e}")

    def refresh(self):
        """Tell running apps the settings changed."""
        try:
            import ctypes
            wininet = ctypes.windll.wininet
            ok = wininet.InternetSetOptionW(None, 39, None, 0) and \
                wininet.InternetSetOptionW(None, 37, None, 0)
        except (ImportError, AttributeError, OSError):
            ok = False
        if not ok:
            print("Note: could not tell running apps about the change. "
                  "Restart your browser if it doesn't pick it up.")

    def read(self, target):
        return {n: self._get(n) for n in self.VALUES + [self.BLOB]}

    def valid(self, snap):
        def ok(e):
            if not isinstance(e, dict) or not isinstance(e.get("present"), bool):
                return False
            if not e["present"]:
                return True
            if not isinstance(e.get("type"), int):
                return False
            if "b64" in e:
                try:
                    base64.b64decode(e["b64"], validate=True)
                    return True
                except (ValueError, TypeError):
                    return False
            return isinstance(e.get("value"), (int, str, list))
        return isinstance(snap, dict) and all(ok(snap.get(n)) for n in self.VALUES + [self.BLOB])

    @staticmethod
    def servers(text):
        """ProxyServer as {scheme: host:port}. A bare host:port is for all."""
        out = {}
        for part in str(text or "").split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip().lower()] = re.sub(r"^\w+://", "", v.strip())
            else:
                v = re.sub(r"^\w+://", "", part)
                for k in ("http", "https", "ftp"):
                    out.setdefault(k, v)
        return out

    def _enabled(self, snap):
        e = snap["ProxyEnable"]
        try:
            return e.get("present", False) and int(e.get("value", 0)) == 1
        except (TypeError, ValueError):
            return False

    def _server(self, snap):
        e = snap["ProxyServer"]
        return self.servers(e.get("value") if e.get("present") else "")

    def is_ours(self, snap, port):
        s = self._server(snap)
        me = f"127.0.0.1:{port}"
        pac = snap["AutoConfigURL"]
        return self._enabled(snap) and s.get("http") == me and s.get("https") == me \
            and "socks" not in s and not (pac.get("present") and pac.get("value"))

    def touches_us(self, snap, ports):
        s = self._server(snap)
        mine = {f"127.0.0.1:{p}" for p in ports}
        return self._enabled(snap) and (s.get("http") in mine or s.get("https") in mine)

    def without_us(self, snap, ports):
        if not self.touches_us(snap, ports):
            return snap
        snap = dict(snap)
        snap["ProxyEnable"] = {"present": True, "type": 4, "value": 0}
        return snap

    def apply_ours(self, target, orig, port):
        o = orig["ProxyOverride"]
        old = [x.strip() for x in str(o.get("value", "") if o.get("present") else "").split(";")]
        bypass = dedupe([x for x in old if x] + self.EXTRA_BYPASS)
        try:
            self._put("ProxyServer", {"present": True, "type": 1,
                                      "value": f"http=127.0.0.1:{port};https=127.0.0.1:{port}"})
            self._put("ProxyOverride", {"present": True, "type": 1, "value": ";".join(bypass)})
            self._put("ProxyEnable", {"present": True, "type": 4, "value": 1})
            # A setup script would win over the proxy, even one set since
            # on. Off puts back the one that was there before.
            if self._get("AutoConfigURL").get("present"):
                self._put("AutoConfigURL", {"present": False})
        finally:
            self.refresh()

    def restore(self, target, saved, cur, notes=None):
        errors = []
        for n in ["ProxyOverride", "AutoConfigURL", self.BLOB, "ProxyServer", "ProxyEnable"]:
            if cur.get(n) == saved[n]:
                continue
            try:
                self._put(n, saved[n])
            except ProxyError as e:
                if n == "AutoConfigURL" and not saved[n].get("present") and notes is not None:
                    # Added while on by something else (a policy, say), and
                    # not ours to remove.
                    notes.append("a setup script (AutoConfigURL) added while this was on "
                                 "couldn't be removed, so it was left as it is")
                else:
                    errors.append(str(e))
        self.refresh()
        return errors

    def clear_ours(self, target, cur, ports):
        try:
            self._put("ProxyEnable", {"present": True, "type": 4, "value": 0})
        except ProxyError as e:
            return [str(e)]
        finally:
            self.refresh()
        return []

    def notes(self, target, snap):
        out = []
        pac = snap["AutoConfigURL"]
        if pac.get("present") and pac.get("value"):
            out.append("a setup script (AutoConfigURL) was set. It is paused while this is on "
                       "and comes back with off.")
        blob = snap[self.BLOB]
        try:
            flags = base64.b64decode(blob["b64"])[8] if blob.get("present") and "b64" in blob else 0
        except (ValueError, IndexError):
            flags = 0
        if flags & 0x08:
            out.append("'Automatically detect settings' is on. On a network that offers "
                       "a setup script, apps use that instead.")
        return out

    def describe(self, snap):
        pac = snap["AutoConfigURL"]
        if pac.get("present") and pac.get("value"):
            return "setup script"
        if not self._enabled(snap):
            return "no proxy"
        s = self._server(snap)
        return s.get("https") or s.get("http") or "no proxy"

    def system_proxies(self, snap):
        if not self._enabled(snap):
            return {}
        s = self._server(snap)
        return {k: f"http://{s[k]}" for k in ("http", "https") if s.get(k)}

    def label(self, targets):
        return "this user"


# ------------------------------------------------------------ GNOME settings

class GnomeBackend:
    """org.gnome.system.proxy through gsettings. Used by GNOME, Ubuntu,
    Cinnamon, Budgie and Pantheon desktops."""
    name = "gnome"
    BASE = "org.gnome.system.proxy"
    KEYS = [(BASE, "mode"), (BASE, "ignore-hosts"),
            (BASE + ".http", "host"), (BASE + ".http", "port"),
            (BASE + ".https", "host"), (BASE + ".https", "port"),
            (BASE + ".socks", "host"), (BASE + ".socks", "port")]
    DESKTOPS = {"gnome", "ubuntu", "unity", "cinnamon", "x-cinnamon", "budgie", "pantheon"}
    EXTRA_BYPASS = ["localhost", "127.0.0.0/8", "::1", "*.local", "169.254.0.0/16", "100.64.0.0/10",
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    def __init__(self):
        self.port = 8899

    def fallback(self):
        p = self.port
        return ("This desktop's proxy settings can't be switched automatically.\n"
                "Run: python3 resproxy.py serve   (keep it open)\n"
                "then in the shell or app that should use the proxy:\n"
                f"  export http_proxy=http://127.0.0.1:{p} https_proxy=http://127.0.0.1:{p} "
                "no_proxy=localhost,127.0.0.1,::1")

    def check(self, cfg):
        self.port = cfg["local_port"]
        if not os.path.exists(tool("gsettings")):
            raise ProxyError(self.fallback())
        if os.environ.get("RESPROXY_BACKEND") != "gnome":
            desktops = {d.strip().lower() for d in os.environ.get("XDG_CURRENT_DESKTOP", "").split(":")}
            if not desktops & self.DESKTOPS:
                raise ProxyError(self.fallback())
        runtime = os.environ.get("XDG_RUNTIME_DIR", "")
        if not os.environ.get("DBUS_SESSION_BUS_ADDRESS") and \
                not (runtime and os.path.exists(os.path.join(runtime, "bus"))):
            raise ProxyError(self.fallback())
        r = run_tool("gsettings", "list-schemas")
        if r.returncode != 0 or self.BASE not in r.stdout.split():
            raise ProxyError(self.fallback())

    def targets(self, cfg):
        return ["user"]

    def all_targets(self):
        return ["user"]

    @staticmethod
    def parse(text):
        t = re.sub(r"^@\w+\s+", "", text.strip())
        if t in ("true", "false"):
            return t == "true"
        try:
            return ast.literal_eval(t)
        except (ValueError, SyntaxError):
            return t

    @staticmethod
    def text(value):
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, list):
            return "[" + ", ".join(GnomeBackend.text(v) for v in value) + "]" if value else "@as []"
        return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"

    def get(self, schema, key):
        r = run_tool("gsettings", "get", schema, key)
        if r.returncode != 0:
            msg = (r.stderr.strip() or r.stdout.strip() or f"exit status {r.returncode}").splitlines()[-1]
            raise ProxyError(f"gsettings get {schema} {key} failed: {msg}")
        return r.stdout.strip()

    def set(self, schema, key, text):
        r = run_tool("gsettings", "set", schema, key, text)
        if r.returncode != 0:
            msg = (r.stderr.strip() or r.stdout.strip() or f"exit status {r.returncode}").splitlines()[-1]
            raise ProxyError(f"gsettings set {schema} {key} failed: {msg}")
        # Without a session bus gsettings reports success but keeps nothing.
        if self.parse(self.get(schema, key)) != self.parse(text):
            raise ProxyError(f"gsettings did not keep {schema} {key}.\n" + self.fallback())

    def put_back(self, schema, key, text):
        """Write a saved value back, as a reset if it was the default."""
        r = run_tool("gsettings", "reset", schema, key)
        if r.returncode == 0:
            try:
                if self.parse(self.get(schema, key)) == self.parse(text):
                    return
            except ProxyError:
                pass
        self.set(schema, key, text)

    def read(self, target):
        return {f"{s} {k}": self.get(s, k) for s, k in self.KEYS}

    def valid(self, snap):
        return isinstance(snap, dict) and all(isinstance(snap.get(f"{s} {k}"), str) for s, k in self.KEYS)

    def v(self, snap, schema, key):
        return self.parse(snap[f"{self.BASE}{schema} {key}"])

    def _at(self, snap, kind, ports):
        return self.v(snap, kind, "host") == "127.0.0.1" and self.v(snap, kind, "port") in ports

    def is_ours(self, snap, port):
        return self.v(snap, "", "mode") == "manual" and self._at(snap, ".http", [port]) \
            and self._at(snap, ".https", [port]) and self.v(snap, ".socks", "host") == ""

    def touches_us(self, snap, ports):
        return self.v(snap, "", "mode") == "manual" and \
            (self._at(snap, ".http", ports) or self._at(snap, ".https", ports))

    def without_us(self, snap, ports):
        if not self.touches_us(snap, ports):
            return snap
        snap = dict(snap)
        snap[f"{self.BASE} mode"] = "'none'"
        return snap

    def apply_ours(self, target, orig, port):
        hosts = self.v(orig, "", "ignore-hosts")
        hosts = [h for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else []
        if utf8_locale() is None and any("?" in h for h in hosts):
            raise ProxyError("ignore-hosts may have non-ASCII names this shell can't read "
                             "(no UTF-8 locale installed), so it was left alone. "
                             "Run on from a UTF-8 locale.")
        b = self.BASE
        cur = self.read(target)
        for s, k, value in [(b + ".http", "host", "127.0.0.1"), (b + ".http", "port", port),
                            (b + ".https", "host", "127.0.0.1"), (b + ".https", "port", port),
                            (b + ".socks", "host", ""),
                            (b, "ignore-hosts", dedupe(hosts + self.EXTRA_BYPASS)),
                            (b, "mode", "manual")]:
            # Only write what differs, so keys left at their defaults stay that way.
            if self.parse(cur[f"{s} {k}"]) != value:
                self.set(s, k, self.text(value))

    def restore(self, target, saved, cur, notes=None):
        errors = []
        b = self.BASE
        order = [(b + ".socks", "host"), (b + ".socks", "port"), (b, "ignore-hosts"),
                 (b + ".http", "host"), (b + ".http", "port"),
                 (b + ".https", "host"), (b + ".https", "port"), (b, "mode")]
        for s, k in order:
            key = f"{s} {k}"
            if self.parse(cur.get(key, "")) == self.parse(saved[key]):
                continue
            try:
                self.put_back(s, k, saved[key])
            except ProxyError as e:
                errors.append(str(e))
        return errors

    def clear_ours(self, target, cur, ports):
        try:
            self.set(self.BASE, "mode", "'none'")
        except ProxyError as e:
            return [str(e)]
        return []

    def notes(self, target, snap):
        if self.v(snap, "", "mode") == "auto":
            return ["automatic proxy configuration was on. It is paused while this is on "
                    "and comes back with off."]
        return []

    def describe(self, snap):
        mode = self.v(snap, "", "mode")
        if mode == "auto":
            return "automatic proxy"
        if mode == "manual" and self.v(snap, ".http", "host"):
            return f"{self.v(snap, '.http', 'host')}:{self.v(snap, '.http', 'port')}"
        return "no proxy"

    def system_proxies(self, snap):
        if self.v(snap, "", "mode") != "manual":
            return {}
        out = {}
        for scheme in ("http", "https"):
            host = self.v(snap, "." + scheme, "host")
            if host:
                out[scheme] = f"http://{host}:{self.v(snap, '.' + scheme, 'port')}"
        return out

    def label(self, targets):
        return "this user"


BACKENDS = {"macos": MacBackend, "windows": WindowsBackend, "gnome": GnomeBackend}


def get_backend():
    name = os.environ.get("RESPROXY_BACKEND") or \
        {"darwin": "macos", "win32": "windows"}.get(sys.platform, "gnome")
    if name not in BACKENDS:
        raise ProxyError(f"RESPROXY_BACKEND should be one of {', '.join(BACKENDS)}, not {name!r}")
    return BACKENDS[name]()


# ------------------------------------------------------------ saved settings

def load_saved(backend):
    """The saved settings, {} if there are none, or None if the file is
    unreadable. Returns {"backend", "ports", "script", "targets", "pending"}."""
    try:
        saved = json.loads(SAVED_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    if isinstance(saved, dict) and "version" not in saved:
        # Older versions saved {service: settings} for macOS only.
        saved = {"version": 2, "backend": "macos", "ports": [], "script": None,
                 "targets": saved, "pending": []}
    if not isinstance(saved, dict) or saved.get("version") != 2 or \
            not isinstance(saved.get("targets"), dict):
        return None
    ports = saved.get("ports") if isinstance(saved.get("ports"), list) else []
    pending = saved.get("pending") if isinstance(saved.get("pending"), list) else []
    out = {"backend": saved.get("backend"), "ports": [p for p in ports if _port(p)],
           "script": saved.get("script") if isinstance(saved.get("script"), str) else None,
           "targets": saved["targets"], "pending": [p for p in pending if p in saved["targets"]]}
    if out["backend"] == backend.name and not all(backend.valid(s) for s in out["targets"].values()):
        return None
    return out


def write_saved(backend, saved):
    atomic_write(SAVED_FILE, json.dumps({
        "version": 2, "backend": backend.name, "ports": sorted(set(saved["ports"])),
        "script": SCRIPT, "targets": saved["targets"], "pending": saved["pending"]}, indent=2))


def set_aside_bad_save():
    bad = SAVED_FILE.with_name(SAVED_FILE.name + ".bad")
    try:
        os.replace(SAVED_FILE, bad)
    except OSError:
        pass
    return bad


def saved_targets(backend):
    """True if there are saved settings of this backend still to put back."""
    saved = load_saved(backend)
    return bool(saved and saved["backend"] == backend.name and saved["targets"])


def check_backend(backend, saved):
    if saved and saved["backend"] != backend.name:
        raise ProxyError(f"The saved settings in {SAVED_FILE} are for {saved['backend']}, "
                         f"not {backend.name}. Set RESPROXY_BACKEND={saved['backend']} "
                         "and run off, or move that file away.")


def known_targets(backend, saved, notes):
    """Saved targets that still exist. Ones that are gone (an adapter that
    was unplugged for good, say) are dropped with a note."""
    if not saved or not saved["targets"]:
        return {}
    try:
        exist = set(backend.all_targets())
    except ProxyError:
        return dict(saved["targets"])
    gone = [t for t in saved["targets"] if t not in exist]
    if gone:
        notes.append(f"{', '.join(gone)} no longer exists, so its saved settings were dropped")
    return {t: s for t, s in saved["targets"].items() if t in exist}


def our_ports(cfg, saved, info):
    ports = {cfg["local_port"]}
    ports.update((saved or {}).get("ports") or [])
    if info and info.get("port"):
        ports.add(info["port"])
    return ports


# ------------------------------------------------------------ on / off

def switch_off(cfg, backend):
    """Put back every saved target that still points at the forwarder (or
    whose last restore failed) and stop it. Returns (errors, notes, done),
    where done is "restored" if saved settings were put back, "cleared" if
    our address was switched off with nothing saved for it, else None."""
    notes = []
    saved = load_saved(backend)
    if saved is None:
        bad = set_aside_bad_save()
        notes.append(f"saved settings were unreadable (moved to {bad.name}), "
                     "so the proxy was just switched off")
        saved = {}
    check_backend(backend, saved)
    info = forwarder_info()
    ports = our_ports(cfg, saved, info)
    targets = known_targets(backend, saved, notes)
    pending = set(saved.get("pending", []))
    check = list(targets)
    try:
        check += [t for t in backend.targets(cfg) if t not in check]
    except ProxyError:
        pass
    errors, keep, done, seen = [], {}, None, set()
    for t in check:
        try:
            cur = backend.read(t)
        except ProxyError as e:
            errors.append(str(e))
            if t in targets:
                keep[t] = targets[t]
            continue
        seen.update(p for p in ports if backend.touches_us(cur, [p]))
        if t in targets:
            if not (backend.touches_us(cur, ports) or t in pending):
                # Another app or the user changed it since; leave it alone.
                continue
            errs = backend.restore(t, targets[t], cur, notes)
            done = "restored"
        elif backend.touches_us(cur, ports):
            errs = backend.clear_ours(t, cur, ports)
            done = done or "cleared"
        else:
            errs = []
        if errs:
            errors += errs
            if t in targets:
                keep[t] = targets[t]
    if errors:
        # Leave the forwarder running so the web keeps working, and keep the
        # save for what isn't restored yet so "off" can be run again.
        if keep:
            write_saved(backend, {"ports": list(ports), "targets": keep, "pending": list(keep)})
        else:
            SAVED_FILE.unlink(missing_ok=True)
        return errors, notes, done
    SAVED_FILE.unlink(missing_ok=True)
    if not running(info):
        # No PID file for the forwarder the settings pointed at: find it by
        # its port instead of leaving it running.
        for p in sorted(seen):
            found = find_forwarder(p)
            if found:
                info = found
                break
    if not stop_forwarder(info):
        raise ProxyError(("Settings put back" if done == "restored" else "Proxy switched off")
                         + f", but the forwarder (process {info['pid']}) did not stop. "
                         "End that process yourself.")
    return [], notes, done


def switch_on(cfg, backend, targets, port):
    saved = load_saved(backend)
    if saved is None:
        bad = set_aside_bad_save()
        print(f"Note: saved settings were unreadable, moved to {bad.name}.")
        saved = {}
    check_backend(backend, saved)
    notes = []
    info = forwarder_info()
    ports = our_ports(cfg, saved, info) | {port}
    # A target in the save keeps its originals until a restore of it fully
    # succeeds. Never record our own forwarder address as an original.
    kept = known_targets(backend, saved, notes)
    for n in notes:
        print(f"Note: {n}.")
    for t in targets:
        if t in kept:
            continue
        cur = backend.read(t)
        if backend.touches_us(cur, ports):
            cur = backend.without_us(cur, ports)
            print(f"Note: {backend.label([t])} already pointed at this forwarder with no "
                  "saved settings. Off will switch its proxy off.")
        kept[t] = cur
        for n in backend.notes(t, cur):
            print(f"Note: {n}")
    pending = [p for p in saved.get("pending", []) if p in kept]
    write_saved(backend, {"ports": list(ports), "targets": kept, "pending": pending})
    for t in targets:
        backend.apply_ours(t, kept[t], port)
    # Once ours is applied again, off restores those anyway: they point at us.
    # One no longer in use gets the restore an earlier off didn't finish.
    finished = []
    for t in pending:
        if t in targets:
            continue
        try:
            if not backend.restore(t, kept[t], backend.read(t), []):
                finished.append(t)
                print(f"Note: {backend.label([t])}'s saved settings from an earlier off were put back.")
        except ProxyError:
            pass
    if any(p in targets for p in pending) or finished:
        for t in finished:
            del kept[t]
        write_saved(backend, {"ports": list(ports), "targets": kept,
                              "pending": [p for p in pending if p not in targets and p not in finished]})


def _turn_on(cfg, backend):
    check_upstream(cfg)
    backend.check(cfg)
    if cfg["services"] and backend.name != "macos":
        print("Note: services in config.json is only used on macOS.")
    targets = backend.targets(cfg)
    info = forwarder_info()
    if running(info):
        if info.get("script") != SCRIPT:
            raise ProxyError(f"Another copy of resproxy ({Path(info['script'] or '?').parent}) "
                             "has the proxy on. Turn it off first; off works from either copy.")
        if info["port"] == cfg["local_port"] and \
                info.get("config_hash") == config_hash(cfg, info["token"]):
            try:
                if state(cfg, backend) == "on":
                    print("Already on.")
                    return
            except ProxyError:
                pass
    try:
        info = start_forwarder(cfg)
        check_login(info["port"])
        switch_on(cfg, backend, targets, info["port"])
    except BaseException as e:
        after = ""
        with no_interrupt():
            try:
                errors, _, done = switch_off(cfg, backend)
                if errors:
                    after = (f"Putting the old settings back also failed: {errors[0].rstrip('.')}. "
                             "Run off again.")
                elif done == "restored":
                    after = "Your previous settings were put back."
                elif done == "cleared":
                    after = "The proxy was switched off (nothing was saved to restore)."
            except ProxyError as e2:
                after = str(e2)
        if isinstance(e, ProxyError):
            msg = str(e) if "\n" in str(e) else str(e).rstrip(".") + "."
            raise ProxyError((msg + ("\n" if "\n" in msg else " ") + after) if after else msg)
        if after:
            print(after, file=sys.stderr)
        raise
    st = state(cfg, backend)
    if st != "on":
        # Something still wins over the proxy settings just written.
        raise ProxyError(MESSAGES.get(st, st.upper()))
    if backend.name == "macos":
        print(f"ON  - {', '.join(targets)} now goes through the residential proxy.")
    else:
        print("ON  - the system proxy now goes through the residential proxy.")


UNREADABLE = ("Can't read this desktop's proxy settings from here (no desktop session in this "
              "shell?), so nothing was changed. Run off from a terminal in your desktop session.")


def _turn_off(cfg, backend):
    try:
        backend.check(cfg)
    except ProxyError:
        if saved_targets(backend):
            raise ProxyError(UNREADABLE)
        info = forwarder_info()
        if info and (running(info) or owned_process(info)):
            if not stop_forwarder(info):
                raise ProxyError(f"The forwarder (process {info['pid']}) did not stop. "
                                 "End that process yourself.")
            print("OFF - forwarder stopped.")
        else:
            PID_FILE.unlink(missing_ok=True)
            print("Nothing to switch on this desktop. If you started serve yourself, "
                  "stop it with Ctrl-C.")
        return
    errors, notes, done = switch_off(cfg, backend)
    if errors:
        raise ProxyError(f"Could not put back all settings: {errors[0].rstrip('.')}. "
                         "The forwarder is still running. Run off again.")
    if notes:
        print(f"OFF - {'; '.join(notes)}.")
    elif done == "cleared":
        print("OFF - proxy switched off (no saved settings were found to restore).")
    elif done:
        print("OFF - previous proxy settings restored.")
    else:
        print("OFF - the proxy was already off.")


def turn_on():
    cfg = load_config()
    backend = get_backend()
    with locked():
        _turn_on(cfg, backend)


def turn_off():
    cfg = load_config()
    backend = get_backend()
    with locked():
        _turn_off(cfg, backend)


def turn_toggle():
    """Decide and act under one lock, so two toggles at once don't both turn on."""
    cfg = load_config()
    backend = get_backend()
    with locked():
        if state(cfg, backend) in ("on", "broken", "unfinished", "unknown"):
            _turn_off(cfg, backend)
        else:
            _turn_on(cfg, backend)


def survey(cfg, backend):
    """Current settings of every target that matters: (snaps, active, ports, info)."""
    saved = load_saved(backend) or {}
    if saved and saved["backend"] != backend.name:
        saved = {}
    info = forwarder_info()
    try:
        active = backend.targets(cfg)
    except ProxyError:
        active = []
    names = [t for t in (saved.get("targets") or {})] + active
    snaps = {}
    for t in dict.fromkeys(names):
        try:
            snaps[t] = backend.read(t)
        except ProxyError:
            pass
    return snaps, active, our_ports(cfg, saved, info), info


def state(cfg=None, backend=None):
    """One of on, partial, broken, unfinished, unknown or off. Broken means
    the system proxy points at the forwarder but it isn't running, so
    nothing gets through. Partial means it runs but not everything in use
    points at it (the network changed, or something else switched part of
    it). Unfinished means nothing points at it any more but the forwarder
    still runs or an off didn't put everything back. Unknown means the
    settings can't be read from here while there is something to restore."""
    cfg = cfg or load_config()
    backend = backend or get_backend()
    try:
        backend.check(cfg)
    except ProxyError:
        if saved_targets(backend):
            return "unknown"
        return "unfinished" if running(forwarder_info()) else "off"
    snaps, active, ports, info = survey(cfg, backend)
    if not any(backend.touches_us(s, ports) for s in snaps.values()):
        saved = load_saved(backend) or {}
        if saved.get("backend") == backend.name and saved.get("targets") and not snaps:
            return "unknown"
        if (saved.get("backend") == backend.name and saved.get("pending")) or running(info):
            return "unfinished"
        return "off"
    saved = load_saved(backend) or {}
    if saved.get("backend") == backend.name:
        # An off that failed partway: what it didn't finish isn't ours either.
        port = info["port"] if info and info.get("port") else cfg["local_port"]
        if any(t not in snaps or not backend.is_ours(snaps[t], port) for t in saved.get("pending", [])):
            return "unfinished"
    if not running(info):
        return "broken"
    if active and all(t in snaps and backend.is_ours(snaps[t], info["port"]) for t in active):
        return "on"
    return "partial"


def is_on():
    return state() == "on"


def system_proxies(cfg, backend=None):
    """The proxy apps use right now, as a urllib proxies dict."""
    backend = backend or get_backend()
    try:
        return backend.system_proxies(backend.read(backend.targets(cfg)[0]))
    except (ProxyError, IndexError, KeyError):
        return {}


def restore_summary(cfg, backend=None):
    """What off goes back to, in a few words."""
    backend = backend or get_backend()
    saved = load_saved(backend)
    if saved and saved["targets"] and saved["backend"] == backend.name:
        return backend.describe(next(iter(saved["targets"].values())))
    return backend.describe(backend.read(backend.targets(cfg)[0]))


BROKEN_MSG = ("BROKEN - the system proxy points at the forwarder but it isn't running "
              "(after a restart, for example), so apps can't connect. "
              "Run off to restore your old settings, or on to start it again.")
PARTIAL_MSG = ("PARTIAL - the forwarder is running but the network in use isn't pointed at it "
               "(the network changed, for example). Run on to switch it too, or off.")
UNFINISHED_MSG = ("UNFINISHED - an off didn't put back every saved setting, or the forwarder is "
                  "still running with nothing pointing at it. Run off to finish.")
UNKNOWN_MSG = ("UNKNOWN - can't read this desktop's proxy settings from here (no desktop session "
               "in this shell?). Run status from a terminal in your desktop session.")
MESSAGES = {"broken": BROKEN_MSG, "partial": PARTIAL_MSG, "unfinished": UNFINISHED_MSG,
            "unknown": UNKNOWN_MSG}


# Free IP lookup sites, tried in order. Residential IPs are shared, so one
# site often refuses with 429 because other people used up its daily limit.
IP_SITES = (
    ("https://ipinfo.io/json",
     lambda d: {"ip": d.get("ip"), "city": d.get("city"), "region": d.get("region"),
                "country": d.get("country"), "org": d.get("org")}),
    ("http://ip-api.com/json",
     lambda d: {"ip": d.get("query"), "city": d.get("city"), "region": d.get("regionName"),
                "country": d.get("countryCode"), "org": d.get("as") or d.get("isp")}),
    ("https://api.ipify.org?format=json",
     lambda d: {"ip": d.get("ip")}),
)


def lookup_exit_ip(proxies, timeout=10):
    """The IP (and where it is, when known) that sites see through proxies.
    Returns {"error": ...} only if every lookup site failed."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
    error = None
    for url, parse in IP_SITES:
        try:
            info = parse(json.load(opener.open(url, timeout=timeout)))
        except Exception as e:
            error = e
            continue
        if info.get("ip"):
            return info
    return {"error": str(error)[:60] if error else "no lookup site answered"}


def status():
    cfg = load_config()
    st = state(cfg)
    print("Residential proxy:", MESSAGES.get(st, st.upper()))
    info = forwarder_info()
    if st in ("on", "partial") and info and info.get("port"):
        # Go through the forwarder itself, the path apps take while it's on,
        # and ignore any proxy set in this shell.
        url = f"http://127.0.0.1:{info['port']}"
        info = lookup_exit_ip({"http": url, "https": url})
        if "error" in info:
            print("Could not reach the internet through the proxy:", info["error"])
        elif info.get("city"):
            print(f"Exit IP: {info['ip']}  {info.get('city')}, {info.get('region')}  "
                  f"({info.get('org')})")
        else:
            print(f"Exit IP: {info['ip']}")


def main():
    cmds = {"serve": serve, "on": turn_on, "off": turn_off, "toggle": turn_toggle,
            "status": status, "state": lambda: print(state()),
            "is-on": lambda: print("1" if is_on() else "0")}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__.strip())
    # A service name the terminal can't show is escaped, not an error that
    # stops the command halfway.
    for f in (sys.stdout, sys.stderr):
        try:
            f.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    try:
        cmds[sys.argv[1]]()
    except ProxyError as e:
        sys.exit(str(e))
    except KeyboardInterrupt:
        sys.exit("Stopped.")


if __name__ == "__main__":
    main()
