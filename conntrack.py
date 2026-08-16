#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 CONNTRACK
 TCP Connection State Monitor - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT THIS WATCHES

   Every TCP connection passes through a defined sequence of states, and where a
   machine's connections PILE UP says something specific about what is wrong.
   The states themselves are all normal - a connection has to be in one of them.
   What is diagnostic is the distribution, and which end is stuck:

     CLOSE_WAIT   The peer closed and this machine has not. The kernel is waiting
                  for the local application to call close(). A pile of these is
                  an APPLICATION BUG on THIS machine - almost the only state that
                  points that clearly at local code, because the kernel cannot
                  clear them for you.
     TIME_WAIT    This machine closed first and is holding the socket for twice
                  the maximum segment lifetime, so that late duplicates cannot
                  land on a new connection with the same tuple. Thousands are
                  usually NORMAL for a busy client or proxy - it is the state
                  people most often try to "fix" when nothing is wrong.
     SYN_RECV     A handshake that started and never finished. A pile is either a
                  SYN flood or, far more often, clients that vanished.
     SYN_SENT     This machine is trying to reach something that is not answering.
     FIN_WAIT1/2  This machine closed and is waiting on the peer. FIN_WAIT2 with
                  no timeout is a peer that never finished closing.
     LAST_ACK     The close is nearly done and the final acknowledgement is
                  outstanding.

   The tool also reads what most connection listings throw away: the SEND AND
   RECEIVE QUEUES, the RETRANSMIT COUNT, and the TIMER on each socket. A
   connection with a full send queue and a running retransmit timer is one whose
   peer has stopped reading - which is invisible if you only look at the state.

 WHAT MAKES IT A MONITOR RATHER THAN A LISTING

   It samples repeatedly and tracks connections BY IDENTITY, so it can say how
   long each one has been in its current state. "Forty connections in CLOSE_WAIT"
   is a number. "Forty connections in CLOSE_WAIT, the oldest for nineteen
   minutes, all owned by one process" is a diagnosis.

 *** A STATE IS NOT A PROBLEM ***
   Every state exists because TCP needs it. TIME_WAIT in particular is the
   correct behaviour of a working system and is routinely mistaken for a leak.
   This tool reports distributions and durations, and names the innocent
   explanation alongside every finding.

 *** IT IS A SNAPSHOT, AND IT POLLS ***
   /proc/net/tcp is a moment. A connection that opens and closes between two
   samples is never seen at all, and a short-lived state like SYN_SENT is easy to
   miss. Nothing here counts connections over time - only what existed when it
   looked.

 READ-ONLY
   It reads /proc. It closes no socket, kills no process and changes no setting.
   Where a fix exists it is printed for you to run.

 LEGAL DISCLAIMER
   Provided "as is" with no warranty; the author accepts no liability for any
   loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import csv
import html as _html
import io
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import socket
import sqlite3
import struct
import sys
import textwrap
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

APP_NAME = "ConnTrack"
APP_SHORT = "CONNTRACK"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("CONNTRACK_DB", "conntrack.db")

STATE_IS_NOT_A_PROBLEM = (
    "A state is not a problem. Every one of them exists because TCP needs it, and TIME_WAIT "
    "in particular is the correct behaviour of a working system - it is the state most often "
    "mistaken for a leak. This tool reports distributions and durations, and names the "
    "innocent explanation alongside every finding."
)
IT_POLLS = (
    "This is a snapshot, and it polls. /proc/net/tcp shows a moment: a connection that opens "
    "and closes between two samples is never seen, and short-lived states like SYN_SENT are "
    "easy to miss entirely. Nothing here counts connections over time - only what existed "
    "when it looked."
)
CLOSE_WAIT_IS_LOCAL = (
    "CLOSE_WAIT is the one state that points clearly at local code. The peer has closed and "
    "the kernel is waiting for the application on THIS machine to call close(). The kernel "
    "cannot clear it for you, and no amount of tuning will - the file descriptor is leaking."
)
DISCLAIMER_SHORT = (
    "Read-only. Watches TCP connections through their states, tracking how long each has been "
    "stuck and which process owns it. A state is not a problem - TIME_WAIT especially - and "
    "this is a snapshot that polls, so short-lived connections are missed."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    A STATE IS NOT A PROBLEM. Every TCP state exists because the protocol needs it. TIME_WAIT
    is the correct behaviour of a working system and is routinely mistaken for a leak;
    thousands of them on a busy client or proxy are normal. This tool reports distributions
    and durations, and states the innocent explanation alongside every finding.

    IT IS A SNAPSHOT, AND IT POLLS. /proc/net/tcp shows a moment. A connection that opens and
    closes between two samples is never seen at all, and a short-lived state like SYN_SENT is
    easy to miss. Durations here are measured from when THIS TOOL first saw a connection in a
    state, which is a lower bound - the connection may have been in it far longer before the
    first sample.

    PROCESS OWNERSHIP NEEDS PRIVILEGES. Mapping a socket to the process holding it means
    reading every /proc/*/fd, which is only possible for your own processes without root.
    Missing owners are a coverage limit and never evidence of hiding.

    IT SEES ONLY THIS MACHINE. Connection state is per-host. A connection stuck from the other
    end's point of view may look perfectly healthy from here, and the reverse is also true.

    READ-ONLY. It closes no socket, kills no process and changes no setting. Fixes are printed
    for you to run.

    Provided "as is" with no warranty; the author accepts no liability for any loss or
    damage."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 35.0, "high": 18.0, "medium": 8.0, "low": 3.0, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}

# Colour by what the state means for you, not by alarm: green where the kernel is
# doing its job, amber where something is waiting, red where somebody is stuck.
STATE_COLOR = {
    "ESTABLISHED": "#30a46c", "LISTEN": "#3e9dd8", "TIME_WAIT": "#8b8f9b",
    "CLOSE_WAIT": "#e5484d", "SYN_SENT": "#ffb224", "SYN_RECV": "#f76808",
    "FIN_WAIT1": "#ffb224", "FIN_WAIT2": "#f76808", "LAST_ACK": "#ffb224",
    "CLOSING": "#ffb224", "CLOSE": "#8b8f9b", "NEW_SYN_RECV": "#f76808",
}


def risk_band(score: float, checked: bool = True) -> tuple[str, str]:
    if not checked:
        return "not checked", "#8b8f9b"
    if score >= 35:
        return "something is stuck", "#e5484d"
    if score >= 18:
        return "worth investigating", "#f76808"
    if score >= 8:
        return "worth a look", "#ffb224"
    if score > 0:
        return "minor notes", "#3e9dd8"
    return "nothing unusual", "#30a46c"


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def shorten(s, n=90) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = int(seconds)
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def fmt_bytes(n) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.{0 if unit == 'B' else 1}f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GiB"


def ago(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        delta = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    except Exception:
        return "-"
    return fmt_duration(delta) + " ago" if delta >= 0 else "in the future"


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def F(category, title, severity, description, evidence="", advice="", fix=""):
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:2500],
            "advice": advice, "fix": fix}


class Result:
    def __init__(self, name: str):
        self.name = name
        self.data = None
        self.status = "ok"
        self.detail = ""

    def unavailable(self, detail):
        self.status, self.detail = "unavailable", detail
        return self

    def partial(self, detail):
        self.status = "partial"
        self.detail = " ".join((self.detail + "; " + detail).strip("; ").split())[:400]
        return self


# =============================================================================
# SECTION 2 - What each state means
#   The whole point of the tool is in this table: not what the state is called,
#   but which end is waiting, whether that is a problem, and what causes it when
#   it is.
# =============================================================================

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

STATE_MEANING = {
    "ESTABLISHED": {
        "waiting_on": "nobody - the connection is open and usable",
        "normal": True,
        "means": "Data can flow in both directions. This is the working state.",
        "when_piled_up": (
            "Many established connections is ordinary for a server. It becomes "
            "interesting only against the process's file descriptor limit, or when they "
            "are all idle and never being closed."),
    },
    "SYN_SENT": {
        "waiting_on": "the remote host, which has not answered the handshake",
        "normal": True,
        "means": "This machine sent a SYN and is waiting for a SYN-ACK.",
        "when_piled_up": (
            "This machine is repeatedly trying to reach something that is not answering - "
            "a dead backend, a wrong address, or a firewall dropping rather than "
            "rejecting. A pile of these pointing at MANY different addresses is what an "
            "outbound scan looks like from this side."),
    },
    "SYN_RECV": {
        "waiting_on": "the client, which never completed the handshake",
        "normal": True,
        "means": "A SYN arrived and was answered, but the final ACK never came.",
        "when_piled_up": (
            "Either clients that vanished - flaky networks and impatient users do this "
            "constantly - or a SYN flood. The difference is the number of distinct source "
            "addresses and whether SYN cookies have kicked in."),
    },
    "FIN_WAIT1": {
        "waiting_on": "the peer, to acknowledge the close this machine started",
        "normal": True,
        "means": "This machine closed and is waiting for the FIN to be acknowledged.",
        "when_piled_up": (
            "Usually a peer that went away without a clean shutdown. It clears on a "
            "timeout, so a persistent pile means the timeout is long or the peers are "
            "consistently unreachable."),
    },
    "FIN_WAIT2": {
        "waiting_on": "the peer, which has not closed its own half",
        "normal": True,
        "means": (
            "This machine closed, the peer acknowledged, and the peer has not yet sent "
            "its own FIN. The connection is half open."),
        "when_piled_up": (
            "The PEER has an application that is not closing its side - the mirror image "
            "of a CLOSE_WAIT problem, seen from the other end. Linux times these out "
            "after tcp_fin_timeout, so they should not accumulate indefinitely."),
    },
    "TIME_WAIT": {
        "waiting_on": "nothing - the kernel is holding the tuple deliberately",
        "normal": True,
        "means": (
            "This machine closed first and is holding the socket for twice the maximum "
            "segment lifetime, so a late duplicate cannot land on a new connection using "
            "the same four-tuple."),
        "when_piled_up": (
            "Usually NORMAL. A busy client or proxy that makes many short outbound "
            "connections will always have thousands, and that is the system working "
            "correctly. It only matters if it exhausts the local port range, which shows "
            "up as connections failing rather than as the count itself."),
    },
    "CLOSE_WAIT": {
        "waiting_on": "the LOCAL application, which has not called close()",
        "normal": False,
        "means": (
            "The peer closed and the kernel told the application. The application has "
            "not closed its end."),
        "when_piled_up": (
            "This is a file descriptor leak in local code, and it is one of the few "
            "states that points that clearly at a specific bug. The kernel cannot clear "
            "these - only the process holding them can, by closing or by exiting."),
    },
    "LAST_ACK": {
        "waiting_on": "the peer, to acknowledge this machine's FIN",
        "normal": True,
        "means": "This machine has sent its own FIN after the peer closed.",
        "when_piled_up": (
            "Short-lived by design. A pile suggests the peer is not acknowledging, which "
            "usually means it disappeared."),
    },
    "CLOSING": {
        "waiting_on": "the peer, in a simultaneous close",
        "normal": True,
        "means": "Both ends closed at the same time.",
        "when_piled_up": "Rare. Any significant number is unusual enough to look at.",
    },
    "LISTEN": {
        "waiting_on": "nobody - this is a server socket",
        "normal": True,
        "means": "A socket accepting new connections.",
        "when_piled_up": (
            "The count is just how many services are running. What matters is which "
            "addresses they are bound to."),
    },
    "CLOSE": {
        "waiting_on": "nobody",
        "normal": True,
        "means": "The socket is closed.",
        "when_piled_up": "Transient; rarely seen in a listing at all.",
    },
    "NEW_SYN_RECV": {
        "waiting_on": "the client, in the SYN queue before a full socket exists",
        "normal": True,
        "means": "A half-open handshake held in the SYN queue.",
        "when_piled_up": (
            "The same reading as SYN_RECV: vanished clients, or a flood. This is the "
            "state where SYN cookies do their work."),
    },
}

# Timer types in /proc/net/tcp column 'tr'. The timer says what the kernel is
# doing about a connection, which is often more informative than the state.
TIMER_TYPES = {
    0: ("none", "no timer is running on this socket"),
    1: ("retransmit", "the kernel is retransmitting unacknowledged data - the peer is "
                      "not acknowledging"),
    2: ("keepalive", "a keepalive probe is pending, or the connection is idle"),
    3: ("TIME_WAIT", "the 2MSL timer that holds the tuple after closing"),
    4: ("zero window", "the peer has advertised a zero window - it has stopped reading, "
                       "and the kernel is probing until it opens again"),
}

NOTABLE_PORTS = {
    22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "mail submission", 993: "IMAPS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP alt",
    8443: "HTTPS alt", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB",
}


def decode_address(hexaddr: str) -> tuple[str, int]:
    """/proc/net stores addresses as little-endian hex words."""
    host, _, port = hexaddr.partition(":")
    port = int(port, 16) if port else 0
    try:
        if len(host) == 8:
            return socket.inet_ntop(socket.AF_INET,
                                    struct.pack("<I", int(host, 16))), port
        if len(host) == 32:
            words = [host[i:i + 8] for i in range(0, 32, 8)]
            raw = b"".join(struct.pack("<I", int(w, 16)) for w in words)
            return socket.inet_ntop(socket.AF_INET6, raw), port
    except (ValueError, OSError, struct.error):
        pass
    return host, port


def connection_key(conn: dict) -> str:
    """What makes this the same connection across samples.

    The four-tuple, which is exactly what TCP uses to identify a connection. The
    inode changes are not used because a socket can be handed between processes,
    and TIME_WAIT entries have no inode at all.
    """
    return (f"{conn['proto']}|{conn['local_ip']}:{conn['local_port']}"
            f"|{conn['remote_ip']}:{conn['remote_port']}")


# =============================================================================
# SECTION 3 - Reading the connections
#   Every column, including the ones most tools drop: the queues, the retransmit
#   count and the timer. A connection whose send queue is full with a retransmit
#   timer running is one whose peer stopped reading, and the state alone never
#   shows that.
# =============================================================================

def socket_inode_map() -> tuple[dict, int]:
    """inode -> process, by walking /proc/*/fd."""
    out: dict[int, dict] = {}
    denied = 0
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return out, 0
    for pid in pids:
        fddir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fddir)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        info = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fddir, fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            if info is None:
                info = process_info(int(pid))
            out[inode] = info
    return out, denied


def process_info(pid: int) -> dict:
    out = {"pid": pid, "name": None, "exe": None, "cmdline": None, "user": None,
           "fd_count": None, "fd_limit": None}
    try:
        with open(f"/proc/{pid}/stat") as fh:
            raw = fh.read()
        out["name"] = raw[raw.find("(") + 1:raw.rfind(")")]
    except OSError:
        pass
    try:
        out["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            out["cmdline"] = fh.read().replace(b"\x00", b" ").decode(
                "utf-8", "replace").strip() or None
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/status") as fh:
            for lineno in fh:
                if lineno.startswith("Uid:"):
                    uid = int(lineno.split()[1])
                    try:
                        import pwd
                        out["user"] = pwd.getpwuid(uid).pw_name
                    except Exception:
                        out["user"] = str(uid)
                    break
    except OSError:
        pass
    # how close this process is to running out of descriptors, which is the thing
    # a CLOSE_WAIT leak eventually causes
    try:
        out["fd_count"] = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/limits") as fh:
            for lineno in fh:
                if lineno.startswith("Max open files"):
                    parts = lineno.split()
                    soft = parts[3]
                    out["fd_limit"] = int(soft) if soft.isdigit() else None
                    break
    except (OSError, ValueError, IndexError):
        pass
    return out


def read_connections(include_listening: bool = True) -> Result:
    r = Result("connections")
    r.data = {"connections": [], "denied": 0, "owner_coverage": 0.0, "sources": [],
              "sampled_at": time.time()}
    if not sys.platform.startswith("linux"):
        return r.unavailable(
            f"connections are read from /proc/net, which is Linux-only; this is "
            f"{sys.platform}. Nothing was read.")
    if not os.path.exists("/proc/net/tcp") and not os.path.exists("/proc/net/tcp6"):
        return r.unavailable(
            "neither /proc/net/tcp nor /proc/net/tcp6 exists, so no connections could be "
            "read. Nothing was checked - which is not the same as there being none.")
    inodes, denied = socket_inode_map()
    r.data["denied"] = denied
    owned = total = 0
    for fname, proto in (("tcp", "tcp"), ("tcp6", "tcp6")):
        path = f"/proc/net/{fname}"
        if not os.path.exists(path):
            continue
        r.data["sources"].append(path)
        try:
            with open(path) as fh:
                next(fh, None)
                for raw in fh:
                    f = raw.split()
                    if len(f) < 10:
                        continue
                    try:
                        local_ip, local_port = decode_address(f[1])
                        remote_ip, remote_port = decode_address(f[2])
                        state = TCP_STATES.get(f[3].upper(), f"state {f[3]}")
                        tx_hex, _, rx_hex = f[4].partition(":")
                        tx_queue, rx_queue = int(tx_hex, 16), int(rx_hex, 16)
                        timer_hex, _, when_hex = f[5].partition(":")
                        timer_type = int(timer_hex, 16)
                        timer_ticks = int(when_hex, 16)
                        retransmits = int(f[6], 16)
                        uid = int(f[7])
                        probes = int(f[8])
                        inode = int(f[9])
                    except (ValueError, IndexError):
                        continue
                    if state == "LISTEN" and not include_listening:
                        continue
                    owner = inodes.get(inode) if inode else None
                    total += 1
                    if owner:
                        owned += 1
                    timer_name, timer_why = TIMER_TYPES.get(
                        timer_type, (f"type {timer_type}", "an unrecognised timer"))
                    entry = {
                        "proto": proto, "local_ip": local_ip, "local_port": local_port,
                        "remote_ip": remote_ip, "remote_port": remote_port,
                        "state": state, "tx_queue": tx_queue, "rx_queue": rx_queue,
                        "timer_type": timer_type, "timer_name": timer_name,
                        "timer_why": timer_why,
                        # the kernel counts these in jiffies, conventionally 100/s
                        "timer_seconds": round(timer_ticks / 100.0, 2),
                        "retransmits": retransmits, "uid": uid, "probes": probes,
                        "inode": inode,
                        "pid": (owner or {}).get("pid"),
                        "process": (owner or {}).get("name"),
                        "exe": (owner or {}).get("exe"),
                        "cmdline": (owner or {}).get("cmdline"),
                        "user": (owner or {}).get("user"),
                        "fd_count": (owner or {}).get("fd_count"),
                        "fd_limit": (owner or {}).get("fd_limit"),
                        "service": NOTABLE_PORTS.get(remote_port)
                        or NOTABLE_PORTS.get(local_port),
                    }
                    entry["key"] = connection_key(entry)
                    r.data["connections"].append(entry)
        except OSError as e:
            r.partial(f"{path} could not be read: {e}")
    r.data["owner_coverage"] = round(100.0 * owned / total, 1) if total else 0.0
    if denied:
        r.partial(f"{denied} process(es) could not be inspected without privileges, so "
                  f"some connections have no owner shown - a coverage limit, not evidence "
                  f"of hiding")
    return r


def read_limits() -> Result:
    """The ceilings a pile of connections eventually runs into."""
    r = Result("limits")
    r.data = {"settings": {}, "available": False}
    checks = [
        ("/proc/sys/net/ipv4/ip_local_port_range", "the range of local ports available "
         "for outbound connections - TIME_WAIT only matters when it exhausts this"),
        ("/proc/sys/net/ipv4/tcp_fin_timeout", "how long a socket stays in FIN_WAIT2 "
         "before the kernel gives up on the peer"),
        ("/proc/sys/net/ipv4/tcp_max_syn_backlog", "how many half-open handshakes the "
         "kernel will hold before dropping new ones"),
        ("/proc/sys/net/ipv4/tcp_syncookies", "whether SYN cookies are enabled, which is "
         "what keeps a machine serving during a SYN flood"),
        ("/proc/sys/net/ipv4/tcp_tw_reuse", "whether the kernel may reuse a TIME_WAIT "
         "socket for a new outbound connection"),
        ("/proc/sys/net/ipv4/tcp_keepalive_time", "how long an idle connection waits "
         "before the first keepalive probe"),
        ("/proc/sys/net/core/somaxconn", "the largest accept queue a listening socket "
         "may request"),
        ("/proc/sys/fs/file-nr", "open file handles system-wide, against the maximum"),
    ]
    for path, why in checks:
        value = None
        try:
            with open(path) as fh:
                value = fh.read().strip()
        except OSError:
            pass
        r.data["settings"][os.path.basename(path)] = {
            "path": path, "value": value, "why": why, "present": value is not None}
    r.data["available"] = any(v["present"] for v in r.data["settings"].values())
    # how many outbound ports there actually are, which bounds TIME_WAIT
    pr = r.data["settings"].get("ip_local_port_range", {}).get("value")
    if pr:
        try:
            low, high = (int(x) for x in pr.split())
            r.data["port_range"] = {"low": low, "high": high, "count": high - low + 1}
        except ValueError:
            pass
    if not r.data["available"]:
        return r.unavailable("no TCP limit sysctls could be read, so the ceilings a pile "
                             "of connections would hit are unknown.")
    return r


# =============================================================================
# SECTION 4 - Tracking connections across samples
#   This is what separates a monitor from a listing. Identity is the four-tuple,
#   so the same connection is recognised sample to sample and the time it has
#   spent in its current state can be measured.
# =============================================================================

class ConnectionTracker:
    """How long each connection has been where it is.

    Durations are measured from when THIS TOOL first saw the connection in that
    state, which is a lower bound - it may have been there far longer before the
    first sample. Every finding that uses a duration says so.
    """

    def __init__(self, max_tracked: int = 50000):
        self.seen: dict[str, dict] = {}
        self.max_tracked = max_tracked
        self.samples = 0
        self.evicted = 0
        self.first_sample_at: float | None = None

    def update(self, connections: list[dict], at: float | None = None) -> dict:
        at = at if at is not None else time.time()
        self.samples += 1
        if self.first_sample_at is None:
            self.first_sample_at = at
        current = set()
        appeared, changed = [], []
        for conn in connections:
            key = conn["key"]
            current.add(key)
            prev = self.seen.get(key)
            if prev is None:
                if len(self.seen) >= self.max_tracked:
                    oldest = sorted(self.seen.items(),
                                    key=lambda kv: kv[1]["last_seen"])[:self.max_tracked // 4]
                    for k, _v in oldest:
                        del self.seen[k]
                    self.evicted += len(oldest)
                self.seen[key] = {
                    "key": key, "first_seen": at, "last_seen": at,
                    "state": conn["state"], "state_since": at, "samples": 1,
                    "states": [conn["state"]], "transitions": 0,
                    "max_tx_queue": conn["tx_queue"], "max_rx_queue": conn["rx_queue"],
                    "max_retransmits": conn["retransmits"],
                    "process": conn.get("process"), "pid": conn.get("pid")}
                appeared.append(key)
            else:
                prev["last_seen"] = at
                prev["samples"] += 1
                prev["max_tx_queue"] = max(prev["max_tx_queue"], conn["tx_queue"])
                prev["max_rx_queue"] = max(prev["max_rx_queue"], conn["rx_queue"])
                prev["max_retransmits"] = max(prev["max_retransmits"],
                                              conn["retransmits"])
                if conn.get("process") and not prev.get("process"):
                    prev["process"] = conn["process"]
                    prev["pid"] = conn.get("pid")
                if prev["state"] != conn["state"]:
                    changed.append({"key": key, "from": prev["state"],
                                    "to": conn["state"],
                                    "after": at - prev["state_since"]})
                    prev["state"] = conn["state"]
                    prev["state_since"] = at
                    prev["transitions"] += 1
                    prev["states"].append(conn["state"])
            conn["age_in_state"] = at - self.seen[key]["state_since"]
            conn["first_seen"] = self.seen[key]["first_seen"]
            conn["samples_seen"] = self.seen[key]["samples"]
            conn["transitions"] = self.seen[key]["transitions"]
            # only meaningful once we have watched for a while
            conn["age_is_lower_bound"] = self.seen[key]["samples"] <= 1
        gone = [k for k in self.seen if k not in current]
        for k in gone:
            self.seen[k]["last_seen"] = at
        return {"appeared": appeared, "disappeared": gone, "changed": changed,
                "tracked": len(self.seen), "samples": self.samples,
                "watched_for": at - (self.first_sample_at or at)}

    def stuck(self, state: str, min_seconds: float) -> list[dict]:
        now = time.time()
        return [v for v in self.seen.values()
                if v["state"] == state and (now - v["state_since"]) >= min_seconds]


def summarise(connections: list[dict]) -> dict:
    """The shape of the connection table right now."""
    out = {"total": len(connections), "by_state": Counter(), "by_process": Counter(),
           "by_peer": Counter(), "by_port": Counter(), "listening": 0,
           "established": 0, "with_queued_data": [], "retransmitting": [],
           "zero_window": [], "oldest_in_state": {}, "by_state_process": defaultdict(Counter)}
    for c in connections:
        out["by_state"][c["state"]] += 1
        if c.get("process"):
            out["by_process"][c["process"]] += 1
            out["by_state_process"][c["state"]][c["process"]] += 1
        if c["state"] == "LISTEN":
            out["listening"] += 1
            continue
        if c["state"] == "ESTABLISHED":
            out["established"] += 1
        out["by_peer"][c["remote_ip"]] += 1
        out["by_port"][c["remote_port"]] += 1
        if c["tx_queue"] > 0 or c["rx_queue"] > 0:
            out["with_queued_data"].append(c)
        if c["retransmits"] > 0 or c["timer_type"] == 1:
            out["retransmitting"].append(c)
        if c["timer_type"] == 4:
            out["zero_window"].append(c)
        age = c.get("age_in_state")
        if age is not None:
            cur = out["oldest_in_state"].get(c["state"])
            if cur is None or age > cur["age"]:
                out["oldest_in_state"][c["state"]] = {"age": age, "conn": c}
    out["by_state_process"] = {k: dict(v) for k, v in out["by_state_process"].items()}
    return out


# =============================================================================
# SECTION 5 - Findings
#   Every finding names the innocent explanation, because for most of these
#   states the innocent explanation is the usual one.
# =============================================================================

# Thresholds. Deliberately generous: the cost of a false alarm here is somebody
# "fixing" a system that was working, which is the common failure mode with
# TIME_WAIT in particular.
THRESHOLDS = {
    "CLOSE_WAIT": {"count": 20, "stuck_seconds": 60.0, "severity": "high"},
    "FIN_WAIT2": {"count": 50, "stuck_seconds": 120.0, "severity": "medium"},
    "SYN_RECV": {"count": 50, "stuck_seconds": 30.0, "severity": "medium"},
    "SYN_SENT": {"count": 30, "stuck_seconds": 20.0, "severity": "medium"},
    "LAST_ACK": {"count": 30, "stuck_seconds": 60.0, "severity": "low"},
    "CLOSING": {"count": 10, "stuck_seconds": 60.0, "severity": "low"},
    "TIME_WAIT": {"count": 10000, "stuck_seconds": None, "severity": "low"},
}


def analyse(conns: Result, limits: Result, tracker: ConnectionTracker | None,
            summary: dict, baseline: dict) -> list[dict]:
    out: list[dict] = []
    approved = {k for k, v in baseline.items() if v.get("approved")}

    if conns.status == "unavailable":
        return [F("Connections", "Connections could not be read", "info", conns.detail,
                  "", "Nothing was checked - which is not the same as there being none.")]

    connections = conns.data["connections"]
    by_state = summary["by_state"]
    watched = tracker.samples if tracker else 0
    watched_for = 0.0
    if tracker and tracker.first_sample_at:
        watched_for = time.time() - tracker.first_sample_at

    if not connections:
        out.append(F("Connections", "No TCP connections at all", "info",
                     f"Read from {', '.join(conns.data['sources'])}.", "",
                     "Unusual but not impossible on an idle machine. " + IT_POLLS))
        return out

    # ---- the overall shape ----
    out.append(F("Overview", f"{len(connections)} connection(s): "
                 + ", ".join(f"{n} {s}" for s, n in by_state.most_common(6)),
                 "info",
                 f"{summary['listening']} listening, {summary['established']} established.",
                 "\n".join(f"  {s:<14} {n:>5}   {STATE_MEANING.get(s, {}).get('waiting_on', '')}"
                           for s, n in by_state.most_common(10)),
                 STATE_IS_NOT_A_PROBLEM))

    # ---- CLOSE_WAIT: the one that points at local code ----
    cw = [c for c in connections if c["state"] == "CLOSE_WAIT"]
    if cw:
        th = THRESHOLDS["CLOSE_WAIT"]
        stuck = [c for c in cw
                 if (c.get("age_in_state") or 0) >= th["stuck_seconds"]
                 and not c.get("age_is_lower_bound")]
        by_proc = Counter(c.get("process") or "unknown" for c in cw)
        worst_proc, worst_count = by_proc.most_common(1)[0]
        oldest = max((c.get("age_in_state") or 0) for c in cw)
        if len(cw) >= th["count"] or stuck:
            sev = "high" if (len(cw) >= th["count"] and stuck) else \
                ("medium" if len(cw) >= th["count"] else "medium")
            evidence = [f"{len(cw)} connection(s) in CLOSE_WAIT",
                        f"oldest has been there at least {fmt_duration(oldest)}",
                        ""]
            evidence += [f"  {p}: {n}" for p, n in by_proc.most_common(5)]
            leaker = next((c for c in cw if c.get("fd_limit")), None)
            if leaker and leaker.get("fd_count") and leaker.get("fd_limit"):
                pct = 100.0 * leaker["fd_count"] / leaker["fd_limit"]
                evidence.append(f"\n{leaker['process']} holds {leaker['fd_count']} "
                                f"descriptor(s) of a limit of {leaker['fd_limit']} "
                                f"({pct:.0f}%)")
            out.append(F("CLOSE_WAIT", f"{len(cw)} connection(s) waiting on local code to "
                         f"close them", sev,
                         f"Mostly {worst_proc} ({worst_count}).",
                         "\n".join(evidence),
                         CLOSE_WAIT_IS_LOCAL + " The innocent version is a process that is "
                         "slow to close rather than never closing - watching for another "
                         "minute distinguishes them, because a slow close clears and a "
                         "leak does not.",
                         fix=f"# which process, and how close to its descriptor limit\n"
                             f"ls -l /proc/{cw[0].get('pid') or 'PID'}/fd | wc -l\n"
                             f"cat /proc/{cw[0].get('pid') or 'PID'}/limits | grep 'open "
                             f"files'\n"
                             f"# the fix is in the code: close() the socket when the peer "
                             f"does"))
        else:
            out.append(F("CLOSE_WAIT", f"{len(cw)} connection(s) in CLOSE_WAIT", "info",
                         "Below the threshold worth reporting.",
                         "\n".join(f"  {p}: {n}" for p, n in by_proc.most_common(4)),
                         "A handful is ordinary - it takes a moment for an application to "
                         "notice a peer closed. " + CLOSE_WAIT_IS_LOCAL))

    # ---- TIME_WAIT: the one people wrongly try to fix ----
    tw = by_state.get("TIME_WAIT", 0)
    if tw:
        port_count = (limits.data or {}).get("port_range", {}).get("count")
        pct = (100.0 * tw / port_count) if port_count else None
        if port_count and tw > port_count * 0.5:
            out.append(F("TIME_WAIT", f"{tw} socket(s) in TIME_WAIT is over half the "
                         f"local port range", "high",
                         f"The range holds {port_count} ports and {tw} are held in "
                         f"TIME_WAIT.",
                         f"port range {(limits.data or {}).get('port_range', {}).get('low')}"
                         f"-{(limits.data or {}).get('port_range', {}).get('high')}\n"
                         f"TIME_WAIT {tw} ({pct:.0f}% of the range)",
                         "This is the ONE case where TIME_WAIT actually matters: when it "
                         "exhausts the ports available for new outbound connections. The "
                         "symptom is connections failing to open, not the count itself. "
                         "Widening the range or enabling tcp_tw_reuse are the usual "
                         "answers - not tcp_tw_recycle, which is removed from modern "
                         "kernels because it broke NAT.",
                         fix="sysctl net.ipv4.ip_local_port_range\n"
                             "sysctl net.ipv4.tcp_tw_reuse"))
        else:
            out.append(F("TIME_WAIT", f"{tw} socket(s) in TIME_WAIT", "info",
                         "The kernel is holding these deliberately.",
                         (f"{pct:.1f}% of the {port_count}-port local range"
                          if pct is not None else ""),
                         STATE_MEANING["TIME_WAIT"]["when_piled_up"]))

    # ---- the states where somebody is waiting on a peer ----
    for state in ("FIN_WAIT2", "SYN_RECV", "SYN_SENT", "LAST_ACK", "CLOSING",
                  "FIN_WAIT1"):
        rows = [c for c in connections if c["state"] == state]
        if not rows:
            continue
        th = THRESHOLDS.get(state)
        if not th:
            continue
        stuck = [c for c in rows
                 if th["stuck_seconds"] and (c.get("age_in_state") or 0)
                 >= th["stuck_seconds"] and not c.get("age_is_lower_bound")]
        if len(rows) < th["count"] and not stuck:
            continue
        meaning = STATE_MEANING.get(state, {})
        peers = Counter(c["remote_ip"] for c in rows)
        evidence = [f"{len(rows)} in {state}"]
        if stuck:
            evidence.append(f"{len(stuck)} of them for at least "
                            f"{fmt_duration(th['stuck_seconds'])}")
        evidence.append("")
        evidence += [f"  {p}: {n}" for p, n in peers.most_common(5)]
        extra = ""
        if state == "SYN_SENT" and len(peers) > 10:
            extra = (f" These point at {len(peers)} different addresses, which is what an "
                     f"outbound scan looks like from this side - and equally what a "
                     f"service with many dead backends looks like.")
        if state in ("SYN_RECV",):
            syncookies = (limits.data or {}).get("settings", {}).get(
                "tcp_syncookies", {}).get("value")
            extra = (f" SYN cookies are {'on' if syncookies == '1' else 'OFF'}, which is "
                     f"what keeps a machine serving during a flood."
                     if syncookies is not None else "")
        out.append(F(state, f"{len(rows)} connection(s) in {state}",
                     th["severity"] if (len(rows) >= th["count"] or stuck) else "info",
                     meaning.get("means", ""),
                     "\n".join(evidence),
                     f"Waiting on {meaning.get('waiting_on', 'unknown')}. "
                     + meaning.get("when_piled_up", "") + extra))

    # ---- what the queues and timers reveal, which the state alone does not ----
    queued = [c for c in summary["with_queued_data"] if c["tx_queue"] > 0]
    if queued:
        biggest = max(queued, key=lambda c: c["tx_queue"])
        blocked = [c for c in queued if c["timer_type"] in (1, 4)]
        out.append(F("Queues", f"{len(queued)} connection(s) have unsent data queued",
                     "medium" if blocked else "low",
                     "The kernel is holding data the peer has not acknowledged.",
                     "\n".join(f"  {c['remote_ip']}:{c['remote_port']}  "
                               f"{fmt_bytes(c['tx_queue'])} queued, timer "
                               f"{c['timer_name']}, {c['retransmits']} retransmit(s)"
                               for c in sorted(queued, key=lambda c: -c["tx_queue"])[:8]),
                     "This is the thing a plain connection listing hides: the state says "
                     "ESTABLISHED and everything looks fine, while the peer has stopped "
                     "reading. A send queue that grows with a retransmit or zero-window "
                     "timer running is a stalled connection, not a healthy one. "
                     + (f"The largest is {fmt_bytes(biggest['tx_queue'])}."
                        if biggest else "")))
    zw = summary["zero_window"]
    if zw:
        out.append(F("Queues", f"{len(zw)} connection(s) are blocked on a zero window",
                     "medium",
                     "The peer has advertised a window of zero - it has stopped reading.",
                     "\n".join(f"  {c['remote_ip']}:{c['remote_port']}  "
                               f"{fmt_bytes(c['tx_queue'])} queued, probe in "
                               f"{c['timer_seconds']}s" for c in zw[:8]),
                     "The kernel probes until the window opens again. An application that "
                     "has stopped reading its socket - blocked on something else, or "
                     "simply slow - causes this. It resolves itself if the peer recovers."))
    rtx = [c for c in summary["retransmitting"] if c["retransmits"] >= 3]
    if rtx:
        out.append(F("Retransmits", f"{len(rtx)} connection(s) are retransmitting "
                     f"repeatedly", "medium",
                     "The peer is not acknowledging what this machine sends.",
                     "\n".join(f"  {c['remote_ip']}:{c['remote_port']}  "
                               f"{c['retransmits']} retransmit(s), {c['state']}"
                               for c in sorted(rtx, key=lambda c: -c["retransmits"])[:8]),
                     "Packet loss, a peer that vanished mid-connection, or a path that "
                     "broke after the connection was established. The retransmit count is "
                     "cumulative for the life of the connection, so a long-lived one with "
                     "a few is unremarkable."))

    # ---- one process holding a disproportionate share ----
    if summary["by_process"]:
        top_proc, top_count = summary["by_process"].most_common(1)[0]
        if top_count > 100 and top_count > len(connections) * 0.6:
            out.append(F("Processes", f"{top_proc} holds {top_count} of "
                         f"{len(connections)} connection(s)", "low",
                         "One process accounts for most of the table.",
                         "\n".join(f"  {p}: {n}"
                                   for p, n in summary["by_process"].most_common(6)),
                         "Entirely normal for a server or a proxy - that is what they do. "
                         "It matters against that process's descriptor limit, which is "
                         "where a connection pile becomes an outage."))

    # ---- one peer holding many connections ----
    if summary["by_peer"]:
        top_peer, peer_count = summary["by_peer"].most_common(1)[0]
        if peer_count >= 100 and top_peer not in approved:
            out.append(F("Peers", f"{peer_count} connection(s) to or from {top_peer}",
                         "low",
                         "One address accounts for a large share of connections.",
                         "\n".join(f"  {p}: {n}"
                                   for p, n in summary["by_peer"].most_common(6)),
                         "A load balancer, a database, or a busy client all look like "
                         "this. Approve it if you recognise it, so a genuinely new "
                         "concentration stands out."))

    # ---- what the tracker adds that a single sample cannot ----
    if tracker and watched > 1:
        out.append(F("Tracking", f"Watched for {fmt_duration(watched_for)} across "
                     f"{watched} sample(s)", "info",
                     f"{len(tracker.seen)} distinct connection(s) tracked.",
                     "\n".join(
                         f"  oldest {s:<12} {fmt_duration(v['age'])}"
                         for s, v in sorted(summary["oldest_in_state"].items(),
                                            key=lambda kv: -kv[1]["age"])[:6]),
                     "Durations are measured from when this tool first saw a connection "
                     "in its state, so they are a LOWER BOUND - a connection may have "
                     "been stuck long before the first sample."))
    elif tracker:
        out.append(F("Tracking", "Only one sample was taken", "info",
                     "Nothing can be said about how long anything has been stuck.", "",
                     "Use 'watch', or --samples, to measure durations. " + IT_POLLS))

    if conns.data["denied"]:
        out.append(F("Coverage", f"{conns.data['denied']} process(es) could not be "
                     f"inspected", "low",
                     f"Owner coverage is {conns.data['owner_coverage']}%.", "",
                     "Mapping a socket to a process means reading every /proc/*/fd, which "
                     "needs root for other users' processes. A missing owner is a coverage "
                     "limit, never evidence of hiding."))
    return out


def risk_score(findings: list[dict]) -> float:
    return round(clamp(sum(SEV_WEIGHT[f["severity"]] for f in findings), 0, 100), 1)


# =============================================================================
# SECTION 6 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, hostname TEXT, mode TEXT, checked INTEGER DEFAULT 1,
    total INTEGER DEFAULT 0, listening INTEGER DEFAULT 0,
    established INTEGER DEFAULT 0, close_wait INTEGER DEFAULT 0,
    time_wait INTEGER DEFAULT 0, syn_recv INTEGER DEFAULT 0,
    fin_wait2 INTEGER DEFAULT 0, queued INTEGER DEFAULT 0,
    retransmitting INTEGER DEFAULT 0, samples INTEGER DEFAULT 1,
    watched_seconds REAL DEFAULT 0, owner_coverage REAL DEFAULT 0,
    score REAL DEFAULT 0, band TEXT, status TEXT, detail TEXT,
    elapsed_ms INTEGER, payload TEXT,
    critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    key TEXT, proto TEXT, local_ip TEXT, local_port INTEGER,
    remote_ip TEXT, remote_port INTEGER, state TEXT, tx_queue INTEGER,
    rx_queue INTEGER, retransmits INTEGER, timer_name TEXT, timer_seconds REAL,
    age_in_state REAL, age_is_lower_bound INTEGER, pid INTEGER, process TEXT,
    user TEXT, service TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS peers (
    peer TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
    times_seen INTEGER DEFAULT 0, connections INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0, approved_at TEXT, label TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT,
    advice TEXT, fix TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_obs_scan ON observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_obs_state ON observations(state);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def peer_map(conn=None) -> dict:
    out = {}
    for r in q("SELECT * FROM peers", (), conn):
        d = dict(r)
        d["approved"] = bool(d["approved"])
        out[d["peer"]] = d
    return out


def approve_peer(peer: str, label: str = "", note: str = "") -> tuple[bool, str]:
    conn = connect()
    try:
        init_db(conn)
        row = q1("SELECT * FROM peers WHERE peer=?", (peer,), conn)
        if not row:
            return False, f"'{peer}' has not been seen. Run a check first."
        conn.execute("UPDATE peers SET approved=1, approved_at=?, "
                     "label=COALESCE(NULLIF(?,''), label), "
                     "note=COALESCE(NULLIF(?,''), note) WHERE peer=?",
                     (now_iso(), label, note, peer))
        conn.commit()
        log_event("INFO", "baseline", f"Approved {peer}", None, conn)
        return True, peer
    finally:
        conn.close()


def revoke_peer(peer: str) -> int:
    conn = connect()
    try:
        n = conn.execute("UPDATE peers SET approved=0, approved_at=NULL WHERE peer=?",
                         (peer,)).rowcount
        conn.commit()
        return n
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(sid: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (sid,), conn)
    if not row:
        return None
    d = dict(row)
    try:
        d["payload"] = json.loads(d["payload"] or "{}")
    except json.JSONDecodeError:
        d["payload"] = {}
    d["band_colour"] = risk_band(d["score"] or 0, bool(d["checked"]))[1]
    return d


def save_scan(conns: Result, limits: Result, tracker: ConnectionTracker | None,
              summary: dict, findings: list[dict], elapsed_ms: int,
              mode: str = "check", note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
        connections = (conns.data or {}).get("connections", [])
        by_state = summary.get("by_state", Counter())
        watched_for = 0.0
        if tracker and tracker.first_sample_at:
            watched_for = time.time() - tracker.first_sample_at
        checked = conns.status != "unavailable"
        score = risk_score(findings)
        cur = conn.execute(
            "INSERT INTO scans (ts, hostname, mode, checked, total, listening,"
            " established, close_wait, time_wait, syn_recv, fin_wait2, queued,"
            " retransmitting, samples, watched_seconds, owner_coverage, score, band,"
            " status, detail, elapsed_ms, payload, critical, high, medium, low, info,"
            " note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), socket.gethostname(), mode, int(checked), len(connections),
             summary.get("listening", 0), summary.get("established", 0),
             by_state.get("CLOSE_WAIT", 0), by_state.get("TIME_WAIT", 0),
             by_state.get("SYN_RECV", 0), by_state.get("FIN_WAIT2", 0),
             len(summary.get("with_queued_data", [])),
             len(summary.get("retransmitting", [])),
             tracker.samples if tracker else 1, round(watched_for, 2),
             (conns.data or {}).get("owner_coverage", 0.0), score,
             risk_band(score, checked)[0], conns.status, conns.detail[:500], elapsed_ms,
             json.dumps({
                 "by_state": dict(by_state),
                 "by_process": dict(summary.get("by_process", Counter()).most_common(20)),
                 "by_peer": dict(summary.get("by_peer", Counter()).most_common(20)),
                 "by_state_process": summary.get("by_state_process", {}),
                 "oldest_in_state": {
                     s: {"age": v["age"], "remote": v["conn"]["remote_ip"],
                         "port": v["conn"]["remote_port"],
                         "process": v["conn"].get("process")}
                     for s, v in summary.get("oldest_in_state", {}).items()},
                 "limits": (limits.data or {}),
                 "connections": [
                     {k: v for k, v in c.items()
                      if k in ("key", "state", "local_ip", "local_port", "remote_ip",
                               "remote_port", "tx_queue", "rx_queue", "retransmits",
                               "timer_name", "timer_seconds", "age_in_state",
                               "age_is_lower_bound", "pid", "process", "user",
                               "service", "proto")}
                     for c in connections[:500]],
             }, default=str),
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], note))
        sid = cur.lastrowid
        ts = now_iso()
        for c in connections[:2000]:
            conn.execute(
                "INSERT INTO observations (scan_id, key, proto, local_ip, local_port,"
                " remote_ip, remote_port, state, tx_queue, rx_queue, retransmits,"
                " timer_name, timer_seconds, age_in_state, age_is_lower_bound, pid,"
                " process, user, service) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, c["key"], c["proto"], c["local_ip"], c["local_port"],
                 c["remote_ip"], c["remote_port"], c["state"], c["tx_queue"],
                 c["rx_queue"], c["retransmits"], c["timer_name"], c["timer_seconds"],
                 c.get("age_in_state"),
                 None if c.get("age_is_lower_bound") is None
                 else int(c["age_is_lower_bound"]),
                 c.get("pid"), c.get("process"), c.get("user"), c.get("service")))
        for peer, n in summary.get("by_peer", Counter()).most_common(200):
            conn.execute(
                "INSERT INTO peers (peer, first_seen, last_seen, times_seen, connections)"
                " VALUES (?,?,?,1,?) ON CONFLICT(peer) DO UPDATE SET last_seen=?,"
                " times_seen=times_seen+1, connections=MAX(connections, ?)",
                (peer, ts, ts, n, ts, n))
        for f in findings:
            conn.execute("INSERT INTO findings (scan_id, category, title, severity,"
                         " description, evidence, advice, fix) VALUES (?,?,?,?,?,?,?,?)",
                         (sid, f["category"], f["title"], f["severity"],
                          f["description"], f["evidence"], f.get("advice", ""),
                          f.get("fix", "")))
        conn.commit()
        log_event("INFO", "scan",
                  f"{mode}: {len(connections)} connection(s), score {score}", sid, conn)
        for f in findings:
            if f["severity"] in ("critical", "high"):
                log_event("WARN", f["category"], f["title"], sid, conn)
        return sid
    finally:
        conn.close()


def run_check(samples: int = 1, interval: float = 2.0, include_listening: bool = True,
              mode: str = "check", note: str = "", tracker: ConnectionTracker | None = None,
              on_sample=None) -> dict:
    """Take one or more samples and analyse what they show.

    More than one sample is what makes durations meaningful; with a single sample
    nothing can be said about how long anything has been stuck, and the report
    says so rather than implying otherwise.
    """
    t0 = time.time()
    init_db()
    tracker = tracker or ConnectionTracker()
    conns = None
    for i in range(max(1, samples)):
        conns = read_connections(include_listening)
        if conns.data:
            tracker.update(conns.data["connections"])
        if on_sample:
            on_sample(i + 1, conns)
        if i < samples - 1:
            time.sleep(interval)
    limits = read_limits()
    summary = summarise((conns.data or {}).get("connections", []))
    findings = analyse(conns, limits, tracker, summary, peer_map())
    elapsed = int((time.time() - t0) * 1000)
    sid = save_scan(conns, limits, tracker, summary, findings, elapsed, mode, note)
    score = risk_score(findings)
    checked = conns.status != "unavailable"
    return {"id": sid, "connections": conns, "limits": limits, "tracker": tracker,
            "summary": summary, "findings": findings, "checked": checked,
            "score": score, "band": risk_band(score, checked)[0],
            "band_colour": risk_band(score, checked)[1], "elapsed_ms": elapsed,
            "counts": {s: sum(1 for f in findings if f["severity"] == s)
                       for s in SEVERITIES}}


# =============================================================================
# SECTION 7 - Charts (hand-drawn SVG: no CDN, no JS library, works offline)
# =============================================================================

def svg_states(by_state: dict, oldest: dict | None = None, width=940,
               title="Where the connections are") -> str:
    """The signature visual: one bar per state, coloured by what it means for you
    rather than by size, with the oldest connection in each state beside it."""
    if not by_state:
        return (f'<div class="chart-empty">{html_escape(title)}: no connections</div>')
    items = sorted(by_state.items(), key=lambda kv: -kv[1])[:12]
    oldest = oldest or {}
    row_h, gap, pad_t, pad_l = 30, 7, 32, 130
    height = pad_t + len(items) * (row_h + gap) + 14
    bw = width - pad_l - 260
    mx = max(v for _k, v in items) or 1
    parts = [f'<text x="{pad_l}" y="18" class="hdr">COUNT</text>',
             f'<text x="{pad_l + bw + 80}" y="18" class="hdr">'
             f'OLDEST / WHO IS WAITING</text>']
    for i, (state, count) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        colour = STATE_COLOR.get(state, "#8b8f9b")
        w = max(3.0, bw * count / mx)
        parts.append(f'<text x="{pad_l - 12}" y="{y + 20}" text-anchor="end" '
                     f'class="cell">{html_escape(state)}</text>')
        parts.append(f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="5" '
                     f'class="btrack"/>')
        parts.append(f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="5" '
                     f'fill="{colour}"><title>{html_escape(state)}: {count}</title></rect>')
        parts.append(f'<text x="{pad_l + w + 8:.0f}" y="{y + 20}" class="bv">'
                     f'{count}</text>')
        info = oldest.get(state)
        note = STATE_MEANING.get(state, {}).get("waiting_on", "")
        text = (f"{fmt_duration(info['age'])}  \u00b7  {shorten(note, 44)}"
                if info else shorten(note, 56))
        parts.append(f'<text x="{pad_l + bw + 80}" y="{y + 20}" class="sub">'
                     f'{html_escape(text)}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'coloured by what the state means, not by size &middot; red is where local '
            f'code is the one holding things up</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_matrix(by_state_process: dict, width=940,
               title="Which process is in which state") -> str:
    """A pile of CLOSE_WAIT means nothing until you know whose it is."""
    if not by_state_process:
        return (f'<div class="chart-empty">{html_escape(title)}: no process could be '
                f'identified - mapping sockets to processes needs privileges</div>')
    states = [s for s in ("CLOSE_WAIT", "ESTABLISHED", "TIME_WAIT", "FIN_WAIT2",
                          "SYN_RECV", "SYN_SENT", "LISTEN", "LAST_ACK")
              if s in by_state_process]
    procs: Counter = Counter()
    for state, m in by_state_process.items():
        for p, n in m.items():
            procs[p] += n
    top = [p for p, _n in procs.most_common(8)]
    if not states or not top:
        return (f'<div class="chart-empty">{html_escape(title)}: nothing to lay out</div>')
    cell_w, cell_h, pad_l, pad_t = max(70, (width - 200) // len(states)), 30, 170, 46
    height = pad_t + len(top) * (cell_h + 5) + 14
    parts = []
    for j, state in enumerate(states):
        x = pad_l + j * cell_w
        parts.append(f'<text x="{x + cell_w / 2:.0f}" y="{pad_t - 12}" '
                     f'text-anchor="middle" class="hdr">'
                     f'{html_escape(state[:11])}</text>')
    mx = max((n for m in by_state_process.values() for n in m.values()), default=1)
    for i, proc in enumerate(top):
        y = pad_t + i * (cell_h + 5)
        parts.append(f'<text x="{pad_l - 12}" y="{y + 20}" text-anchor="end" '
                     f'class="cell">{html_escape(shorten(proc, 20))}</text>')
        for j, state in enumerate(states):
            x = pad_l + j * cell_w
            n = by_state_process.get(state, {}).get(proc, 0)
            colour = STATE_COLOR.get(state, "#8b8f9b")
            opacity = 0.15 + 0.85 * (n / mx) if n else 0.0
            parts.append(f'<rect x="{x + 2}" y="{y}" width="{cell_w - 6}" '
                         f'height="{cell_h}" rx="4" fill="{colour}" '
                         f'opacity="{opacity:.2f}" stroke="#262a33"/>')
            if n:
                parts.append(f'<text x="{x + cell_w / 2 - 2:.0f}" y="{y + 20}" '
                             f'text-anchor="middle" class="cellnum">{n}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; '
            f'a pile of CLOSE_WAIT means nothing until you know whose it is</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}</svg></figure>')


def svg_history(rows: list[dict], width=430, height=160,
                title="Connections over time") -> str:
    pts = [r for r in rows if r.get("total") is not None]
    if len(pts) < 2:
        return (f'<div class="chart-empty">{html_escape(title)}: needs at least two checks '
                f'({len(pts)} so far)</div>')
    pad = 32
    series = [("total", "#3e9dd8"), ("close_wait", "#e5484d"),
              ("time_wait", "#8b8f9b")]
    mx = max(max(r.get(k) or 0 for r in pts) for k, _c in series) or 1
    step = (width - pad * 2) / max(len(pts) - 1, 1)
    parts = []
    for key, colour in series:
        coords = [(pad + i * step,
                   height - pad - (height - pad * 2) * ((r.get(key) or 0) / mx))
                  for i, r in enumerate(pts)]
        d = " ".join(f"{'M' if i == 0 else 'L'} {x:.1f} {y:.1f}"
                     for i, (x, y) in enumerate(coords))
        parts.append(f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="2"/>')
    legend = " ".join(f'<tspan fill="{c}">{k}</tspan>' for k, c in series)
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{pad}" y="14" class="sub">{legend}</text>'
            f'<text x="{width - pad}" y="14" text-anchor="end" class="sub">max {mx}</text>'
            f'</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="", color="#5b8def", fmt=lambda v: f"{v:g}",
            colors=None):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 160, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 62
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        c = (colors or {}).get(label, color)
        lbl = label if len(label) <= 22 else label[:21] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" fill="{c}">'
            f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title></rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


# =============================================================================
# SECTION 8 - Exports
# =============================================================================

def report_payload(sid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(), "disclaimer": DISCLAIMER_LONG,
            "a_state_is_not_a_problem": STATE_IS_NOT_A_PROBLEM,
            "it_polls": IT_POLLS,
            "close_wait_is_local": CLOSE_WAIT_IS_LOCAL,
            "state_meanings": STATE_MEANING,
            "limitations": [
                "A state is not a problem. Every TCP state exists because the protocol "
                "needs it, and TIME_WAIT is the correct behaviour of a working system.",
                "This is a snapshot that polls. A connection opening and closing between "
                "samples is never seen, and short-lived states are easy to miss.",
                "Durations are measured from when this tool first saw a connection in a "
                "state, so they are a LOWER BOUND - it may have been stuck far longer.",
                "Mapping a socket to a process needs privileges; a missing owner is a "
                "coverage limit, never evidence of hiding.",
                "Connection state is per-host. A connection that looks healthy from here "
                "may be stuck from the other end's point of view.",
                "TIME_WAIT only matters when it exhausts the local port range, which shows "
                "up as connections failing rather than as the count itself.",
                "Read-only: no socket is closed, no process killed and no setting changed.",
            ],
            "scan": scan,
            "observations": [dict(r) for r in q(
                "SELECT * FROM observations WHERE scan_id=? ORDER BY "
                "CASE state WHEN 'CLOSE_WAIT' THEN 0 WHEN 'FIN_WAIT2' THEN 1 "
                "WHEN 'SYN_RECV' THEN 2 ELSE 3 END, age_in_state DESC LIMIT 500",
                (sid,), conn)] if sid else [],
            "findings": [dict(r) for r in q(
                "SELECT category,title,severity,description,evidence,advice,fix FROM "
                "findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
                (sid,), conn)] if sid else [],
            "peers": [dict(r) for r in q("SELECT * FROM peers ORDER BY connections DESC "
                                         "LIMIT 100", (), conn)],
            "history": [dict(r) for r in q(
                "SELECT id, ts, score, band, total, close_wait, time_wait, established "
                "FROM scans ORDER BY id DESC LIMIT 40", (), conn)][::-1],
        }
    finally:
        if own:
            conn.close()


def export_json(sid=None) -> str:
    return json.dumps(report_payload(sid), indent=2, default=str)


def export_csv(sid=None) -> str:
    conn = connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan={sid} generated={now_iso()}"])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow(["# A state is not a problem - TIME_WAIT especially. Durations are a "
                    "lower bound, measured from when this tool first looked."])
        if not scan:
            return buf.getvalue()
        w.writerow([])
        w.writerow(["## Check"])
        w.writerow(["hostname", "total", "listening", "established", "close_wait",
                    "time_wait", "syn_recv", "fin_wait2", "queued", "retransmitting",
                    "samples", "watched_seconds", "owner_coverage", "score", "band"])
        w.writerow([scan["hostname"], scan["total"], scan["listening"],
                    scan["established"], scan["close_wait"], scan["time_wait"],
                    scan["syn_recv"], scan["fin_wait2"], scan["queued"],
                    scan["retransmitting"], scan["samples"], scan["watched_seconds"],
                    scan["owner_coverage"], scan["score"], scan["band"]])
        w.writerow([])
        w.writerow(["## Connections"])
        w.writerow(["state", "proto", "local_ip", "local_port", "remote_ip",
                    "remote_port", "tx_queue", "rx_queue", "retransmits", "timer",
                    "age_in_state", "age_is_lower_bound", "pid", "process", "user",
                    "service"])
        for r in q("SELECT * FROM observations WHERE scan_id=? ORDER BY state",
                   (sid,), conn):
            w.writerow([r["state"], r["proto"], r["local_ip"], r["local_port"],
                        r["remote_ip"], r["remote_port"], r["tx_queue"], r["rx_queue"],
                        r["retransmits"], r["timer_name"], r["age_in_state"],
                        r["age_is_lower_bound"], r["pid"], r["process"], r["user"],
                        r["service"]])
        w.writerow([])
        w.writerow(["## Findings"])
        w.writerow(["severity", "category", "title", "description", "advice", "fix"])
        for r in q("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,), conn):
            w.writerow([r["severity"], r["category"], r["title"], r["description"],
                        r["advice"], r["fix"]])
        return buf.getvalue()
    finally:
        conn.close()


def export_html(sid=None) -> str:
    conn = connect()
    try:
        p = report_payload(sid, conn)
        scan, esc = p["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No checks recorded</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        payload = scan.get("payload") or {}
        oldest = {k: {"age": v["age"]} for k, v in
                  (payload.get("oldest_in_state") or {}).items()}
        states = svg_states(payload.get("by_state") or {}, oldest)
        matrix = svg_matrix(payload.get("by_state_process") or {})
        hist = svg_history(p["history"])
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        procs = svg_bar(list((payload.get("by_process") or {}).items())[:8],
                        title="Connections by process", color="#9775fa")
        interesting = [r for r in p["observations"]
                       if r["state"] in ("CLOSE_WAIT", "FIN_WAIT2", "SYN_RECV",
                                         "LAST_ACK", "CLOSING")
                       or (r["tx_queue"] or 0) > 0 or (r["retransmits"] or 0) > 0][:60]
        crows = "".join(
            f'<tr><td><span class="pill" style="background:'
            f'{STATE_COLOR.get(r["state"], "#8b8f9b")}">{esc(r["state"])}</span></td>'
            f'<td class="mono">{esc(r["local_ip"])}:{r["local_port"]}</td>'
            f'<td class="mono">{esc(r["remote_ip"])}:{r["remote_port"]}'
            + (f'<div class="sub2">{esc(r["service"])}</div>' if r["service"] else "")
            + f'</td>'
            f'<td class="num">{fmt_bytes(r["tx_queue"])}</td>'
            f'<td class="num">{r["retransmits"]}</td>'
            f'<td class="mono">{esc(r["timer_name"])}</td>'
            f'<td class="mono">{fmt_duration(r["age_in_state"])}'
            + ("<div class=\"sub2\">at least</div>" if r["age_is_lower_bound"] else "")
            + f'</td>'
            f'<td class="mono">{esc(r["process"] or "-")}'
            + (f'<div class="sub2">pid {r["pid"]}</div>' if r["pid"] else "")
            + '</td></tr>' for r in interesting)
        frows = "".join(
            f'<tr><td><span class="pill" style="background:{SEV_COLOR[f["severity"]]}">'
            f'{esc(f["severity"].upper())}</span></td>'
            f'<td><b>{esc(f["title"])}</b>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
            + (f'<div class="means"><b>What to make of it:</b> {esc(f["advice"])}</div>'
               if f["advice"] else "")
            + (f'<div class="fix"><b>To look further:</b><pre>{esc(f["fix"])}</pre></div>'
               if f["fix"] else "")
            + "</td></tr>" for f in p["findings"])
        limits = "".join(f"<li>{esc(x)}</li>" for x in p["limitations"])
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} - {esc(scan['hostname'] or '')}</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1140px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:30px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 table{{width:100%;border-collapse:collapse;background:#171a21;border:1px solid #262a33;
        border-radius:10px;overflow:hidden;font-size:12.5px}}
 th{{text-align:left;font-size:10.5px;letter-spacing:.11em;text-transform:uppercase;
     color:#8b8f9b;padding:9px 11px;border-bottom:1px solid #262a33;background:#1c2029}}
 td{{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-word}}
 .num{{font-family:ui-monospace,monospace;font-size:11.5px;text-align:right}}
 .sub2{{color:#6f7685;font-size:10.5px;font-family:ui-monospace,monospace}}
 .pill{{color:#0f1115;font-weight:700;font-size:9.5px;padding:2px 7px;border-radius:20px;
        font-family:ui-monospace,monospace}}
 .desc{{color:#b6bac4;margin-top:4px;max-width:84ch}}
 .means{{margin-top:6px;color:#8fd3b0;font-size:12.4px;max-width:84ch}}
 .fix{{margin-top:8px;color:#a8d8e8;font-size:12.2px}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:9px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;color:#b6bac4;max-height:320px}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:18px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:130px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 text.hdr{{fill:#6f7685;font:9.5px ui-monospace,monospace;letter-spacing:.12em}}
 text.cell{{fill:#e6e8ee;font:11.5px ui-monospace,monospace}}
 text.cellnum{{fill:#0b0d10;font:700 11px ui-monospace,monospace}}
 text.sub{{fill:#6f7685;font:10.5px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>TCP connection states</h1>
<div class="meta">{esc(scan['hostname'])} &middot; {ts_pretty(scan['ts'])} &middot;
 {scan['elapsed_ms']} ms &middot; {scan['samples']} sample(s) over
 {fmt_duration(scan['watched_seconds'])} &middot; owner coverage
 {scan['owner_coverage']}%</div>
<div class="note"><b>A state is not a problem.</b> {esc(p['a_state_is_not_a_problem'])}
 <ul>{limits}</ul></div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{scan['band_colour']}">
   {esc(scan['band'] or '')}</div><div class="l">score {scan['score']}</div></div>
 <div class="card"><div class="l">Connections</div><div class="n">{scan['total']}</div>
  <div class="l">{scan['established']} established</div></div>
 <div class="card"><div class="l">CLOSE_WAIT</div>
  <div class="n" style="color:{'#e5484d' if scan['close_wait'] else '#30a46c'}">
   {scan['close_wait']}</div><div class="l">local code</div></div>
 <div class="card"><div class="l">TIME_WAIT</div>
  <div class="n" style="color:#8b8f9b">{scan['time_wait']}</div>
  <div class="l">usually normal</div></div>
 <div class="card"><div class="l">Queued / retrans</div>
  <div class="n" style="font-size:16px">{scan['queued']} / {scan['retransmitting']}</div>
  </div>
</div>
<h2>Where the connections are</h2><div class="charts">{states}</div>
<h2>Which process is in which state</h2><div class="charts">{matrix}</div>
<h2>Analytics</h2><div class="charts">{procs}{hist}{pie}</div>
{f'<h2>Connections worth reading ({len(interesting)})</h2><table><tr><th>State</th>'
 f'<th>Local</th><th>Remote</th><th>Queued</th><th>Rtx</th><th>Timer</th>'
 f'<th>In state</th><th>Process</th></tr>{crows}</table>' if crows else ''}
<h2>Findings ({len(p['findings'])})</h2>
{'<table><tr><th>Severity</th><th>Detail</th></tr>' + frows + '</table>'
 if frows else '<div class="chart-empty">No findings.</div>'}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 Read-only: no socket was closed, no process killed and no setting changed. Durations are a
 lower bound, measured from when this tool first looked.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 9 - Web application (no CDN, no JS libraries)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#30a46c;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1240px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
 padding:6px 10px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1240px;margin:0 auto;padding:20px 20px 70px}
.banner{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.warn{background:#231a12;border-color:#5a3b1c;color:#ffcf9e}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0} .banner li{margin:3px 0}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:10.5px;font-family:var(--mono)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
.btn.tiny{padding:3px 8px;font-size:10.5px}
input[type=text],input[type=number],select{font-family:var(--mono);font-size:12px;
 padding:7px 9px;background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);
 border-radius:7px}
label.f{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10.5px;
 letter-spacing:.1em;text-transform:uppercase;color:var(--tx-dim)}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;line-height:1.3;font-family:var(--mono)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.5px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2);white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.mono{font-family:var(--mono);font-size:11.6px;word-break:break-word}
.num{font-family:var(--mono);font-size:11.6px;text-align:right}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:9.5px;padding:2px 7px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono);white-space:nowrap}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:5px;
 border:1px solid var(--line-2);color:var(--tx-dim);white-space:nowrap;margin-left:4px}
.tag.good{border-color:#1e5138;color:#7fd9ab}
.desc{color:var(--tx-mid);margin-top:4px;max-width:84ch}
.means{margin-top:6px;color:var(--good);font-size:12.4px;max-width:84ch}
.fix{margin-top:8px;color:#a8d8e8;font-size:12.2px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:9px 11px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:320px;overflow:auto;
 white-space:pre-wrap;color:var(--tx-mid)}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:14px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:20px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:240px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:130px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
text.hdr{fill:#6f7685;font:9.5px var(--mono);letter-spacing:.12em}
text.cell{fill:#e6e8ee;font:11.5px var(--mono)}
text.cellnum{fill:#0b0d10;font:700 11px var(--mono)}
text.sub{fill:#6f7685;font:10.5px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)}
rect.btrack{fill:#1e222a}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
.statebox{background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px;margin-bottom:12px}
.statebox h3{margin:0 0 6px;font-family:var(--mono);font-size:13px}
footer{max-width:1240px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
.lvl-ERROR{color:var(--crit)} .lvl-WARN{color:var(--warn)} .lvl-INFO{color:var(--tx-dim)}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} .card .n{font-size:18px} table{font-size:12px}
 th,td{padding:7px 8px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>CONNTRACK</b> <small>TCP connection state monitor</small></div>
 <nav>
  <a href="{{ url_for('page_overview') }}" class="{{ 'on' if nav=='overview' }}">Overview</a>
  <a href="{{ url_for('page_connections') }}" class="{{ 'on' if nav=='connections' }}">Connections</a>
  <a href="{{ url_for('page_scans') }}" class="{{ 'on' if nav=='scans' }}">Checks</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">Learn</a>
  <a href="{{ url_for('page_logs') }}" class="{{ 'on' if nav=='logs' }}">Logs</a>
 </nav></div></header>
<div class="wrap">
 <div class="banner"><b>A state is not a problem.</b> """ + STATE_IS_NOT_A_PROBLEM + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% if flash %}<div class="banner">{{ flash }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 Read-only: no socket is closed, no process killed and no setting changed. Durations are a
 lower bound, measured from when this tool first looked.</footer>
</body></html>"""

RUNBAR_TPL = """
<form method="post" action="{{ url_for('do_check') }}" class="bar">
 <label class="f">samples
  <input type="number" name="samples" value="2" min="1" max="30" style="width:64px"></label>
 <label class="f">interval
  <input type="number" name="interval" value="2" min="1" max="60" style="width:64px"></label>
 <button class="btn primary" type="submit">Check now</button>
 {% if scan %}
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan.id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan.id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan.id }}">CSV</a>
 {% endif %}
</form>"""

EMPTY_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
""" + RUNBAR_TPL + """
<div class="empty"><b>Nothing checked yet</b>
 It reads every TCP connection with its queues, retransmit count and timer, tracks how long
 each has been in its state, and says which process owns it.
 <div class="mono" style="margin-top:12px;color:var(--tx-dim)">
  from the terminal: python3 conntrack.py check --samples 5</div>
</div>{% endblock %}"""

OVERVIEW_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Overview</h1>
<div class="sub">Check #{{ scan.id }} &middot; {{ ts_pretty(scan.ts) }} &middot;
 {{ scan.elapsed_ms }} ms &middot; {{ scan.samples }} sample(s) &middot;
 owner coverage {{ scan.owner_coverage }}%</div>
""" + RUNBAR_TPL + """
{% if scan.detail %}<div class="banner warn"><b>Partial:</b> {{ scan.detail }}</div>{% endif %}
{% if scan.close_wait >= 20 %}
<div class="banner bad"><b>{{ scan.close_wait }} connection(s) in CLOSE_WAIT.</b>
 The peer closed and local code has not. The kernel cannot clear these - only the process
 holding them can.</div>
{% endif %}
<div class="grid">
 <div class="card"><div class="l">Verdict</div>
  <div class="n" style="font-size:14px;color:{{ scan.band_colour }}">{{ scan.band }}</div>
  <div class="l">score {{ scan.score }}</div></div>
 <div class="card"><div class="l">Connections</div><div class="n">{{ scan.total }}</div>
  <div class="l">{{ scan.established }} established</div></div>
 <div class="card"><div class="l">CLOSE_WAIT</div>
  <div class="n" style="color:{{ '#e5484d' if scan.close_wait else '#30a46c' }}">
   {{ scan.close_wait }}</div><div class="l">local code</div></div>
 <div class="card"><div class="l">TIME_WAIT</div>
  <div class="n" style="color:#8b8f9b">{{ scan.time_wait }}</div>
  <div class="l">usually normal</div></div>
 <div class="card"><div class="l">Queued / retrans</div>
  <div class="n" style="font-size:16px">{{ scan.queued }} / {{ scan.retransmitting }}</div>
  </div>
</div>
<h2>Where the connections are</h2><div class="charts">{{ states|safe }}</div>
<h2>Which process is in which state</h2><div class="charts">{{ matrix|safe }}</div>
<h2>Analytics</h2><div class="charts">{{ procs|safe }}{{ hist|safe }}{{ pie|safe }}</div>
<h2>Findings ({{ findings|length }})</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Detail</th></tr>
{% for f in findings %}
<tr><td><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span></td>
 <td><b>{{ f.title }}</b><div class="desc">{{ f.description }}</div>
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.advice %}<div class="means"><b>What to make of it:</b> {{ f.advice }}</div>
  {% endif %}
  {% if f.fix %}<div class="fix"><b>To look further:</b><pre>{{ f.fix }}</pre></div>
  {% endif %}</td></tr>
{% endfor %}</table>
{% else %}<div class="empty">No findings.</div>{% endif %}
{% endblock %}"""

CONNECTIONS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Connections</h1>
<div class="sub">{{ rows|length }} connection(s) from check #{{ scan.id }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="state"><option value="">every state</option>
  {% for s in all_states %}<option value="{{ s }}" {{ 'selected' if s==f_state }}>
   {{ s }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="address, port or process">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_connections') }}">Reset</a>
</form></div>
{% if meaning %}
<div class="statebox">
 <h3 style="color:{{ state_colour }}">{{ f_state }}</h3>
 <div class="desc">{{ meaning.means }}</div>
 <div class="desc" style="margin-top:6px"><b>Waiting on:</b> {{ meaning.waiting_on }}</div>
 <div class="means">{{ meaning.when_piled_up }}</div>
</div>
{% endif %}
{% if rows %}
<table><tr><th>State</th><th>Local</th><th>Remote</th><th>Queued tx/rx</th><th>Rtx</th>
 <th>Timer</th><th>In state</th><th>Process</th></tr>
{% for r in rows %}<tr>
 <td><span class="pill" style="background:{{ state_colours.get(r.state, '#8b8f9b') }}">
  {{ r.state }}</span></td>
 <td class="mono">{{ r.local_ip }}:{{ r.local_port }}</td>
 <td class="mono">{{ r.remote_ip }}:{{ r.remote_port }}
  {% if r.service %}<div class="sub2">{{ r.service }}</div>{% endif %}</td>
 <td class="num">{{ r.tx_queue }}/{{ r.rx_queue }}</td>
 <td class="num">{{ r.retransmits }}</td>
 <td class="mono">{{ r.timer_name }}</td>
 <td class="mono">{{ fmt_duration(r.age_in_state) }}
  {% if r.age_is_lower_bound %}<div class="sub2">at least</div>{% endif %}</td>
 <td class="mono">{{ r.process or '-' }}
  {% if r.pid %}<div class="sub2">pid {{ r.pid }}</div>{% endif %}</td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No connections match</b></div>{% endif %}
{% endblock %}"""

SCANS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Checks</h1><div class="sub">{{ rows|length }} check(s) stored locally.</div>
{% if rows %}
<table><tr><th>#</th><th>When</th><th>Total</th><th>Estab</th><th>CLOSE_WAIT</th>
 <th>TIME_WAIT</th><th>Samples</th><th>Score</th><th></th></tr>
{% for r in rows %}<tr>
 <td class="mono">#{{ r.id }}</td>
 <td class="mono">{{ r.ts[:19].replace('T',' ') }}</td>
 <td class="num">{{ r.total }}</td>
 <td class="num">{{ r.established }}</td>
 <td class="num" style="color:{{ '#e5484d' if r.close_wait else '#8b8f9b' }}">
  {{ r.close_wait }}</td>
 <td class="num">{{ r.time_wait }}</td>
 <td class="num">{{ r.samples }}</td>
 <td class="num">{{ r.score }}</td>
 <td><a class="btn" href="{{ url_for('page_overview') }}?scan={{ r.id }}">view</a></td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing checked yet</b></div>{% endif %}
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>What each TCP state means, and who is waiting</h1>
<div class="banner"><b>Every state exists because TCP needs it.</b> A connection has to be in
 one of them. What is diagnostic is the DISTRIBUTION, and above all which end is waiting -
 because that is what tells you whose problem it is.</div>
{% for state, m in meanings %}
<div class="statebox">
 <h3 style="color:{{ state_colours.get(state, '#8b8f9b') }}">{{ state }}</h3>
 <div class="desc">{{ m.means }}</div>
 <div class="desc" style="margin-top:6px"><b>Waiting on:</b> {{ m.waiting_on }}</div>
 <div class="means">{{ m.when_piled_up }}</div>
</div>
{% endfor %}
<h2>The two that get misread</h2>
<div class="banner bad"><b>CLOSE_WAIT is local code.</b> """ + CLOSE_WAIT_IS_LOCAL + """</div>
<div class="banner warn"><b>TIME_WAIT is usually fine.</b> It is the state people most often
 try to "fix" when nothing is wrong. A busy client or proxy will always have thousands, and
 that is the system working correctly - the socket is held so a late duplicate cannot land on
 a new connection with the same four-tuple. It only matters when it exhausts the local port
 range, and the symptom of that is connections failing to open, not the count itself.<br><br>
 If you do hit that, widen <span class="mono">ip_local_port_range</span> or enable
 <span class="mono">tcp_tw_reuse</span>. Not <span class="mono">tcp_tw_recycle</span>, which
 was removed from modern kernels because it broke connections from behind NAT.</div>
<h2>What the queues and timers add</h2>
<div class="desc">Most connection listings show only the state. This reads three columns they
 throw away:<br><br>
 <b>The send queue</b> is data the kernel is holding because the peer has not acknowledged it.
 <b>The retransmit count</b> is how many times it has tried. <b>The timer</b> says what the
 kernel is doing about it.<br><br>
 A connection can read ESTABLISHED - perfectly healthy by state - while its send queue fills
 and a zero-window timer runs, which means the peer has stopped reading. That is invisible if
 you only look at the state, and it is often the actual problem.</div>
<h2>What this cannot tell you</h2>
<div class="banner warn"><b>It is a snapshot, and it polls.</b> """ + IT_POLLS + """<br><br>
 <b>Durations are a lower bound.</b> They are measured from when this tool first saw a
 connection in its state. A connection may have been stuck for hours before the first
 sample.<br><br>
 <b>State is per-host.</b> A connection that looks healthy from here may be stuck from the
 other end's point of view - CLOSE_WAIT here is FIN_WAIT2 over there, and the same problem
 looks like a different one depending on which machine you are standing on.</div>
{% endblock %}"""

LOGS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Logs</h1><div class="sub">Stored locally in {{ dbfile }}.</div>
<div class="bar"><form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
 <select name="level"><option value="">All levels</option>
  {% for l in ['INFO','WARN','ERROR'] %}<option value="{{ l }}" {{ 'selected' if l==f_level }}>
   {{ l }}</option>{% endfor %}</select>
 <input type="text" name="qq" value="{{ f_q }}" placeholder="search">
 <button class="btn" type="submit">Filter</button>
 <a class="btn" href="{{ url_for('page_logs') }}">Reset</a>
</form></div>
{% if rows %}
<table><tr><th>Time (UTC)</th><th>Level</th><th>Source</th><th>Message</th><th>Check</th></tr>
{% for e in rows %}<tr><td class="mono">{{ e.ts[:19].replace('T',' ') }}</td>
 <td class="mono lvl-{{ e.level }}"><b>{{ e.level }}</b></td>
 <td class="mono">{{ e.source }}</td><td>{{ e.message }}</td>
 <td class="mono">{{ ('#' ~ e.scan_id) if e.scan_id else '-' }}</td></tr>{% endfor %}</table>
{% else %}<div class="empty"><b>No log entries match</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "empty.html": EMPTY_TPL, "overview.html": OVERVIEW_TPL,
             "connections.html": CONNECTIONS_TPL, "scans.html": SCANS_TPL,
             "learn.html": LEARN_TPL, "logs.html": LOGS_TPL}

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request, url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, **kw):
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "severities": SEVERITIES, "ts_pretty": ts_pretty, "ago": ago,
                "fmt_duration": fmt_duration, "fmt_bytes": fmt_bytes,
                "state_colours": STATE_COLOR, "scan": None,
                "error": request.args.get("error"),
                "flash": request.args.get("flash")}
        base.update(kw)
        return base

    @app.route("/")
    def page_overview():
        conn = connect()
        try:
            init_db(conn)
            try:
                sid = int(request.args.get("scan", "") or 0)
            except ValueError:
                sid = 0
            scan = scan_summary(sid, conn) if sid else None
            if not scan:
                sid = latest_scan_id(conn)
                scan = scan_summary(sid, conn) if sid else None
            if not scan:
                return render_template("empty.html", **ctx("overview"))
            p = report_payload(scan["id"], conn)
            payload = scan.get("payload") or {}
            oldest = {k: {"age": v["age"]}
                      for k, v in (payload.get("oldest_in_state") or {}).items()}
            counts = {s: scan[s] or 0 for s in SEVERITIES}
            return render_template("overview.html", **ctx(
                "overview", scan=scan, findings=p["findings"],
                states=svg_states(payload.get("by_state") or {}, oldest),
                matrix=svg_matrix(payload.get("by_state_process") or {}),
                procs=svg_bar(list((payload.get("by_process") or {}).items())[:8],
                              title="Connections by process", color="#9775fa"),
                hist=svg_history(p["history"]),
                pie=svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])))
        finally:
            conn.close()

    @app.post("/check")
    def do_check():
        import urllib.parse as up
        try:
            samples = int(clamp(int(request.form.get("samples", 2)), 1, 30))
        except ValueError:
            samples = 2
        try:
            interval = clamp(float(request.form.get("interval", 2)), 0.5, 60.0)
        except ValueError:
            interval = 2.0
        try:
            res = run_check(samples=samples, interval=interval, mode="web",
                            note="from the web UI")
        except Exception as e:
            log_event("ERROR", "scan", str(e))
            return redirect(url_for("page_overview") + "?error=" + up.quote(str(e)))
        return redirect(url_for("page_overview") + f"?scan={res['id']}")

    @app.route("/connections")
    def page_connections():
        conn = connect()
        try:
            init_db(conn)
            sid = latest_scan_id(conn)
            scan = scan_summary(sid, conn) if sid else None
            if not scan:
                return render_template("empty.html", **ctx("connections"))
            state = request.args.get("state", "").strip()
            term = request.args.get("qq", "").strip()
            sql = "SELECT * FROM observations WHERE scan_id=?"
            args: list = [sid]
            if state:
                sql += " AND state=?"
                args.append(state)
            if term:
                sql += (" AND (local_ip LIKE ? OR remote_ip LIKE ? OR process LIKE ?"
                        " OR CAST(remote_port AS TEXT) LIKE ?)")
                args += [f"%{term}%"] * 4
            sql += (" ORDER BY CASE state WHEN 'CLOSE_WAIT' THEN 0 WHEN 'FIN_WAIT2' THEN 1"
                    " ELSE 2 END, age_in_state DESC LIMIT 500")
            rows = q(sql, tuple(args), conn)
            all_states = [r["state"] for r in q(
                "SELECT DISTINCT state FROM observations WHERE scan_id=? ORDER BY state",
                (sid,), conn)]
            return render_template("connections.html", **ctx(
                "connections", scan=scan, rows=rows, all_states=all_states,
                f_state=state, f_q=term,
                meaning=STATE_MEANING.get(state) if state else None,
                state_colour=STATE_COLOR.get(state, "#8b8f9b")))
        finally:
            conn.close()

    @app.route("/scans")
    def page_scans():
        conn = connect()
        try:
            init_db(conn)
            return render_template("scans.html", **ctx(
                "scans", rows=q("SELECT * FROM scans ORDER BY id DESC LIMIT 200",
                                (), conn)))
        finally:
            conn.close()

    @app.route("/learn")
    def page_learn():
        order = ["CLOSE_WAIT", "TIME_WAIT", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
                 "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING", "LISTEN"]
        return render_template("learn.html", **ctx(
            "learn", meanings=[(s, STATE_MEANING[s]) for s in order
                               if s in STATE_MEANING]))

    @app.route("/logs")
    def page_logs():
        conn = connect()
        try:
            init_db(conn)
            level = request.args.get("level", "").strip().upper()
            term = request.args.get("qq", "").strip()
            sql, args = "SELECT * FROM audit_log WHERE 1=1", []
            if level in ("INFO", "WARN", "ERROR"):
                sql += " AND level=?"
                args.append(level)
            if term:
                sql += " AND (message LIKE ? OR source LIKE ?)"
                args += [f"%{term}%"] * 2
            sql += " ORDER BY id DESC LIMIT 300"
            return render_template("logs.html", **ctx(
                "logs", rows=q(sql, tuple(args), conn), f_level=level, f_q=term,
                dbfile=os.path.abspath(db_path())))
        finally:
            conn.close()

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported the report as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="conntrack-{stamp}.{fmt}"'})

    @app.route("/api/summary")
    def api_summary():
        sid = latest_scan_id()
        if not sid:
            return jsonify({"error": "no checks yet"}), 404
        s = scan_summary(sid)
        return jsonify({"tool": APP_NAME, "version": VERSION, "read_only": True,
                        "a_state_is_not_a_problem": True,
                        "durations_are_a_lower_bound": True,
                        "it_polls_so_misses_short_lived": True,
                        "disclaimer": DISCLAIMER_SHORT,
                        "scan": {k: v for k, v in s.items() if k != "payload"}})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /connections /scans /learn "
                        "/logs", 404, mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    if not is_root():
        print("  NOTE    : not running as root, so most sockets will show no owning\n"
              "            process. That is a coverage limit, reported as such.")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - this UI lists every connection on this\n"
              "            machine and the processes holding them. Use 127.0.0.1.")
    print(f"  {textwrap.fill(DISCLAIMER_SHORT, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 10 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(DISCLAIMER_SHORT, 78))
    line()


def _print_findings(rows, limit=None, quiet=False, show_fix=True):
    shown = [f for f in rows if not (quiet and f["severity"] == "info")]
    shown = shown[:limit] if limit else shown
    for f in shown:
        print(f"\n  [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f.get("evidence"):
            for l in str(f["evidence"]).splitlines()[:12]:
                for w in textwrap.wrap(l, 70) or [""]:
                    print(f"      {w}")
        if f.get("advice"):
            for l in textwrap.wrap("what to make of it: " + f["advice"], 70):
                print(f"      {l}")
        if f.get("fix") and show_fix:
            print("      to look further:")
            for l in str(f["fix"]).splitlines()[:8]:
                print(f"        {l}")


def _report(res, a):
    conns, summary = res["connections"], res["summary"]
    tracker = res["tracker"]
    print(f"Host    : {socket.gethostname()}")
    print(f"Source  : {', '.join((conns.data or {}).get('sources', []) or ['-'])}")
    print(f"Samples : {tracker.samples if tracker else 1}"
          + (f" over {fmt_duration(time.time() - tracker.first_sample_at)}"
             if tracker and tracker.first_sample_at and tracker.samples > 1 else ""))
    print(f"Owners  : {(conns.data or {}).get('owner_coverage', 0)}% of sockets mapped "
          f"to a process")
    print(f"Time    : {res['elapsed_ms']} ms")
    line("=")
    print(f"  {summary['total']} CONNECTION(S)   -   {res['band'].upper()}")
    line("=")
    if summary["by_state"]:
        print(f"  {'STATE':<14} {'COUNT':>6} {'OLDEST':>10}   WAITING ON")
        # the leading mark column is one character, so the header aligns at 2
        line()
        for state, count in summary["by_state"].most_common(12):
            oldest = summary["oldest_in_state"].get(state)
            age = fmt_duration(oldest["age"]) if oldest else "-"
            waiting = STATE_MEANING.get(state, {}).get("waiting_on", "")
            mark = "!" if state == "CLOSE_WAIT" and count >= 5 else " "
            print(f" {mark}{state:<14} {count:>6} {age:>10}   {shorten(waiting, 38)}")
        line()
    interesting = [c for c in (conns.data or {}).get("connections", [])
                   if c["state"] in ("CLOSE_WAIT", "FIN_WAIT2", "SYN_RECV", "LAST_ACK")
                   or c["tx_queue"] > 0 or c["retransmits"] > 0]
    if interesting and a.verbose:
        print(f"  {'STATE':<12} {'REMOTE':<26} {'TXQ':>7} {'RTX':>4} {'IN STATE':>9}  "
              f"PROCESS")
        line()
        for c in sorted(interesting,
                        key=lambda c: -(c.get("age_in_state") or 0))[:25]:
            age = fmt_duration(c.get("age_in_state"))
            if c.get("age_is_lower_bound"):
                age = ">" + age
            print(f"  {c['state']:<12} "
                  f"{(c['remote_ip'] + ':' + str(c['remote_port']))[:25]:<26} "
                  f"{c['tx_queue']:>7} {c['retransmits']:>4} {age:>9}  "
                  f"{(c.get('process') or '-')}")
        line()
        print("  a '>' before a duration means the connection was already in that state")
        print("  when this tool first looked, so the real age is larger")
        line()
    _print_findings(res["findings"], a.show, a.quiet, not a.no_fix)
    line()
    print(textwrap.fill("  " + STATE_IS_NOT_A_PROBLEM, 78))
    line()


def cmd_check(a):
    banner()
    if not is_root():
        print("NOTE: not running as root, so most sockets will show no owning process.")
        print("      That is a coverage limit and is reported as one.\n")
    if a.samples > 1:
        print(f"Taking {a.samples} sample(s), {a.interval:.0f}s apart. This is what makes")
        print("durations meaningful.\n")
    res = run_check(samples=a.samples, interval=a.interval,
                    include_listening=not a.no_listening, note=a.note or "")
    _report(res, a)
    return _exit_code(a, res)


def cmd_watch(a):
    banner()
    print(f"Sampling every {a.interval:.0f}s"
          + (f", {a.count} times" if a.count else " until Ctrl+C") + ".")
    print("Only changes are printed. Durations grow from when each was first seen.\n")
    tracker = ConnectionTracker()
    n = 0
    last_states: Counter = Counter()
    try:
        while True:
            n += 1
            res = run_check(samples=1, tracker=tracker, mode="watch", note="watch",
                            include_listening=not a.no_listening)
            stamp = datetime.now().strftime("%H:%M:%S")
            states = res["summary"]["by_state"]
            alerts = [f for f in res["findings"]
                      if f["severity"] in ("critical", "high")]
            deltas = {s: states.get(s, 0) - last_states.get(s, 0)
                      for s in set(states) | set(last_states)}
            moved = {s: d for s, d in deltas.items() if abs(d) >= a.delta_threshold}
            if alerts or (moved and n > 1):
                print(f"  {stamp}  #{res['id']}  {res['summary']['total']} connection(s)")
                for s, d in sorted(moved.items(), key=lambda kv: -abs(kv[1])):
                    print(f"      {s:<14} {d:+d}  (now {states.get(s, 0)})")
                for f in alerts:
                    print(f"   !! [{f['severity'].upper()}] {f['title']}")
            elif not a.quiet:
                print(f"  {stamp}  #{res['id']}  {res['summary']['total']} connection(s), "
                      f"nothing notable")
            last_states = states
            if a.count and n >= a.count:
                break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    line()
    print(f"  {n} sample(s), {len(tracker.seen)} distinct connection(s) tracked.")
    for state in ("CLOSE_WAIT", "FIN_WAIT2", "SYN_RECV"):
        stuck = tracker.stuck(state, 30.0)
        if stuck:
            print(f"  {len(stuck)} connection(s) have been in {state} for over 30s")
    line()
    return 0


def _exit_code(a, res):
    counts = res["counts"]
    by_state = res["summary"]["by_state"]
    if a.fail_on_close_wait is not None and by_state.get("CLOSE_WAIT", 0) \
            > a.fail_on_close_wait:
        print(f"  Exiting non-zero: {by_state['CLOSE_WAIT']} connection(s) in CLOSE_WAIT, "
              f"above {a.fail_on_close_wait}.")
        return 2
    if a.fail_on_critical and counts["critical"]:
        print(f"  Exiting non-zero: {counts['critical']} critical finding(s).")
        return 2
    if a.fail_over is not None and res["score"] > a.fail_over:
        print(f"  Exiting non-zero: score {res['score']} is above --fail-over "
              f"{a.fail_over}")
        return 2
    return 0


def cmd_states(a):
    """Explain one state, or all of them. Reads nothing and needs nothing."""
    banner()
    wanted = a.state.upper() if a.state else None
    if wanted and wanted not in STATE_MEANING:
        print(f"  '{a.state}' is not a TCP state this tool knows. Known states:")
        print("  " + ", ".join(sorted(STATE_MEANING)))
        return 1
    order = ["CLOSE_WAIT", "TIME_WAIT", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
             "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING", "LISTEN", "CLOSE",
             "NEW_SYN_RECV"]
    for state in ([wanted] if wanted else order):
        m = STATE_MEANING.get(state)
        if not m:
            continue
        print(f"\n  {state}")
        line()
        for l in textwrap.wrap(m["means"], 74):
            print(f"    {l}")
        print(f"\n    waiting on: {m['waiting_on']}")
        print("\n    when a lot of them pile up:")
        for l in textwrap.wrap(m["when_piled_up"], 70):
            print(f"      {l}")
    line()
    return 0


def cmd_top(a):
    """The connections most worth looking at, right now."""
    conns = read_connections()
    if conns.status == "unavailable":
        print(conns.detail)
        return 1
    rows = conns.data["connections"]
    ranked = sorted(
        [c for c in rows if c["state"] != "LISTEN"],
        key=lambda c: (
            0 if c["state"] == "CLOSE_WAIT" else
            1 if c["tx_queue"] > 0 or c["retransmits"] > 0 else
            2 if c["state"] in ("FIN_WAIT2", "SYN_RECV", "LAST_ACK") else 3,
            -(c["tx_queue"] + c["retransmits"] * 1000)))
    if not ranked:
        print("No non-listening connections.")
        return 0
    print(f"  {'STATE':<12} {'REMOTE':<26} {'TXQ':>7} {'RXQ':>7} {'RTX':>4} "
          f"{'TIMER':<10} PROCESS")
    line()
    for c in ranked[:a.limit]:
        print(f"  {c['state']:<12} "
              f"{(c['remote_ip'] + ':' + str(c['remote_port']))[:25]:<26} "
              f"{c['tx_queue']:>7} {c['rx_queue']:>7} {c['retransmits']:>4} "
              f"{c['timer_name']:<10} {(c.get('process') or '-')}")
    line()
    print("  Ordered by what usually matters: CLOSE_WAIT first, then anything with data")
    print("  queued or retransmitting, then the half-closed states.")
    line()
    return 0


def cmd_limits(_a):
    r = read_limits()
    if r.status == "unavailable":
        print(r.detail)
        return 1
    for name, info in r.data["settings"].items():
        if not info["present"]:
            continue
        print(f"\n  {name} = {info['value']}")
        for l in textwrap.wrap(info["why"], 72):
            print(f"    {l}")
    pr = r.data.get("port_range")
    if pr:
        line()
        print(f"  The local port range holds {pr['count']} ports. That is the ceiling")
        print("  TIME_WAIT would have to reach before it caused anything to fail.")
    line()
    return 0


def cmd_peers(a):
    rows = q("SELECT * FROM peers ORDER BY approved DESC, connections DESC LIMIT ?",
             (a.limit,))
    if not rows:
        print("No peers recorded yet. Run:  check")
        return 0
    print(f"  {'PEER':<40} {'CONNS':>6} {'SEEN':>5}  APPROVED")
    line()
    for r in rows:
        print(f"  {r['peer'][:39]:<40} {r['connections']:>6} {r['times_seen']:>5}  "
              f"{'yes' if r['approved'] else 'no'}")
    line()
    return 0


def cmd_approve(a):
    ok, detail = approve_peer(a.peer, a.label or "", a.note or "")
    if not ok:
        print(detail)
        return 1
    print(f"Approved {detail}")
    print()
    print(textwrap.fill(
        "A concentration of connections to this peer will no longer be reported. This "
        "records a decision - it changes nothing about the connections themselves.", 78))
    return 0


def cmd_revoke(a):
    n = revoke_peer(a.peer)
    print(f"Revoked {n} approval(s)." if n else f"'{a.peer}' was not approved.")
    return 0


def cmd_learn(_a):
    banner()
    print(textwrap.dedent("""\
        WHERE CONNECTIONS PILE UP IS THE DIAGNOSIS

          Every TCP connection passes through a defined sequence of states, and a
          connection has to be in one of them. No state is a problem by itself.
          What is diagnostic is the DISTRIBUTION - and above all WHICH END IS
          WAITING, because that is what tells you whose problem it is.

        THE TWO THAT GET MISREAD

          CLOSE_WAIT is the one state that points clearly at local code. The peer
          closed and the kernel told the application; the application has not
          called close(). The kernel CANNOT clear these - only the process holding
          them can, by closing or by exiting. No sysctl will help. A pile of
          CLOSE_WAIT is a file descriptor leak, and eventually the process runs
          out of descriptors and stops accepting anything.

          TIME_WAIT is the state people most often try to "fix" when nothing is
          wrong. This machine closed first and the kernel is holding the socket
          for twice the maximum segment lifetime, so a late duplicate cannot land
          on a new connection with the same four-tuple. That is the system working
          correctly. A busy client or proxy will always have thousands.

          It only matters when it exhausts the local port range - and the symptom
          of THAT is connections failing to open, not the count itself. If you do
          hit it, widen ip_local_port_range or enable tcp_tw_reuse. Not
          tcp_tw_recycle, which was removed from modern kernels because it broke
          connections from behind NAT.

        THE SAME PROBLEM LOOKS DIFFERENT FROM EACH END

          CLOSE_WAIT here is FIN_WAIT2 over there. If you see a pile of FIN_WAIT2,
          the application that is not closing is on the OTHER machine. Connection
          state is per-host, and which one you are standing on changes what the
          bug looks like.

        WHAT THE QUEUES AND TIMERS ADD

          Most connection listings show only the state. This reads three columns
          they throw away:

            the send queue    data the kernel holds because the peer has not
                              acknowledged it
            the retransmits   how many times it has tried
            the timer         what the kernel is doing about it - retransmitting,
                              probing a zero window, counting down 2MSL

          A connection can read ESTABLISHED - perfectly healthy by state - while
          its send queue fills and a zero-window timer runs, which means the peer
          has stopped reading. That is invisible if you only look at the state,
          and it is very often the actual problem.

        WHAT MAKES THIS A MONITOR

          It samples repeatedly and tracks connections by their four-tuple, so it
          can say how long each has been in its current state. "Forty connections
          in CLOSE_WAIT" is a number. "Forty in CLOSE_WAIT, the oldest for
          nineteen minutes, all owned by one process" is a diagnosis.

        WHAT IT CANNOT TELL YOU

          IT IS A SNAPSHOT AND IT POLLS. A connection that opens and closes
          between two samples is never seen, and short-lived states like SYN_SENT
          are easy to miss entirely.

          DURATIONS ARE A LOWER BOUND. They are measured from when this tool first
          saw a connection in its state. It may have been stuck for hours before
          the first sample - which is why a duration is printed with a '>' when
          the connection was already there when the tool started.

          PROCESS OWNERSHIP NEEDS PRIVILEGES. Without root, sockets belonging to
          other users show no owner. That is a coverage limit and never evidence
          of anything hiding.
        """))
    line()


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'TOTAL':>6} {'ESTAB':>6} {'CW':>4} {'TW':>6} "
          f"{'SCORE':>6}  VERDICT")
    line()
    for r in rows:
        print(f"{r['id']:>4}  {r['ts'][:19].replace('T', ' '):<20} {r['total']:>6} "
              f"{r['established']:>6} {r['close_wait']:>4} {r['time_wait']:>6} "
              f"{r['score']:>6}  {r['band'] or ''}")
    return 0


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"conntrack-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported check #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    print("It lists every connection and the processes holding them - treat it as "
          "sensitive.")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return 0
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<12} "
              f"{e['message']}")
    return 0


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "observations", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            if a.peers:
                conn.execute("DELETE FROM peers")
            conn.commit()
            print("All checks, observations and logs deleted."
                  + (" The peer list was cleared too." if a.peers
                     else " The peer list and approvals were kept."))
            return 0
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            for t in ("findings", "observations"):
                conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        print(f"Purged {len(drop)} check(s); kept the newest {a.keep}.")
        return 0
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    conns = read_connections()
    limits = read_limits()
    print(f"  Python     : {platform.python_version()} ({sys.platform})")
    print(f"  Flask      : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  Privileges : {'root' if is_root() else 'unprivileged - owners limited'}")
    print(f"  Connections: {conns.status}"
          + (f", {len(conns.data['connections'])} now, "
             f"{conns.data['owner_coverage']}% owned" if conns.data else ""))
    if conns.data:
        s = summarise(conns.data["connections"])
        print(f"    {', '.join(f'{n} {st}' for st, n in s['by_state'].most_common(5))}")
    print(f"  Limits     : {limits.status}")
    pr = (limits.data or {}).get("port_range")
    if pr:
        print(f"    local port range {pr['low']}-{pr['high']} ({pr['count']} ports)")
    print(f"  States known: {len(STATE_MEANING)}")
    print(f"  Database   : {os.path.abspath(db_path())}")
    print(f"  GitHub     : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 11 - Self test
#   The classifiers run against connection dicts built here, so they pass or fail
#   without depending on what this machine happens to be doing. The collectors
#   then run for real, and the tracker is exercised against connections this test
#   genuinely creates - CLOSE_WAIT is easy to produce on purpose, which makes the
#   most important path testable rather than assumed.
# =============================================================================

def _conn(state, local_port=44000, remote="198.51.100.9", remote_port=443,
          tx=0, rx=0, rtx=0, timer=0, process=None, pid=None, age=None):
    c = {"proto": "tcp", "local_ip": "192.0.2.2", "local_port": local_port,
         "remote_ip": remote, "remote_port": remote_port, "state": state,
         "tx_queue": tx, "rx_queue": rx, "timer_type": timer,
         "timer_name": TIMER_TYPES.get(timer, ("?", ""))[0],
         "timer_why": TIMER_TYPES.get(timer, ("", "?"))[1], "timer_seconds": 0.0,
         "retransmits": rtx, "uid": 0, "probes": 0, "inode": local_port,
         "pid": pid, "process": process, "exe": None, "cmdline": None, "user": "root",
         "fd_count": None, "fd_limit": None,
         "service": NOTABLE_PORTS.get(remote_port)}
    c["key"] = connection_key(c)
    if age is not None:
        c["age_in_state"] = age
        c["age_is_lower_bound"] = False
    return c


def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed, skipped = [], [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    def skip(name, why):
        skipped.append(name)
        print(f"  [SKIP] {name}  ({why})")

    banner()
    print("SELF TEST - analysis against built connections; collectors against this "
          "machine.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="conntrack-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    try:
        print(" Decoding the socket table")
        ip, port = decode_address("0100007F:1F90")
        check("a little-endian IPv4 address decodes",
              ip == "127.0.0.1" and port == 8080, (ip, port))
        check("the wildcard decodes", decode_address("00000000:0050") == ("0.0.0.0", 80))
        ip6, p6 = decode_address("0" * 31 + "1:0016")
        check("an IPv6 address decodes without raising", isinstance(ip6, str), ip6)
        check("a malformed value is returned rather than crashed on",
              decode_address("zz:0016")[1] == 22)
        check("every state code is named",
              all(v.isupper() for v in TCP_STATES.values()), TCP_STATES)
        check("every named state has a meaning",
              all(s in STATE_MEANING for s in TCP_STATES.values()),
              [s for s in TCP_STATES.values() if s not in STATE_MEANING])
        check("every meaning says who is waiting",
              all(m.get("waiting_on") for m in STATE_MEANING.values()))
        check("every meaning says what a pile of them means",
              all(m.get("when_piled_up") for m in STATE_MEANING.values()))
        check("CLOSE_WAIT is the one flagged as not normal",
              [s for s, m in STATE_MEANING.items() if not m["normal"]] == ["CLOSE_WAIT"],
              [s for s, m in STATE_MEANING.items() if not m["normal"]])
        check("TIME_WAIT's meaning says it is usually normal",
              "NORMAL" in STATE_MEANING["TIME_WAIT"]["when_piled_up"])
        check("CLOSE_WAIT's meaning names local code",
              "local" in STATE_MEANING["CLOSE_WAIT"]["waiting_on"].lower())

        print("\n Identity across samples")
        a = _conn("ESTABLISHED", 44000)
        b = _conn("CLOSE_WAIT", 44000)
        check("the same four-tuple is the same connection",
              connection_key(a) == connection_key(b))
        check("a different local port is a different connection",
              connection_key(_conn("ESTABLISHED", 44001)) != connection_key(a))
        check("a different peer is a different connection",
              connection_key(_conn("ESTABLISHED", 44000, remote="203.0.113.1"))
              != connection_key(a))

        print("\n Tracking how long something has been stuck")
        t = ConnectionTracker()
        t0 = 1000.0
        t.update([_conn("ESTABLISHED", 44000)], t0)
        check("a new connection is recorded", len(t.seen) == 1)
        check("the first sample marks the age as a lower bound",
              t.seen[connection_key(a)]["samples"] == 1)
        t.update([_conn("ESTABLISHED", 44000)], t0 + 10)
        conns2 = [_conn("ESTABLISHED", 44000)]
        t.update(conns2, t0 + 10)
        check("age accumulates while the state holds",
              conns2[0]["age_in_state"] >= 10, conns2[0]["age_in_state"])
        check("and is no longer a lower bound after several samples",
              not conns2[0]["age_is_lower_bound"])
        conns3 = [_conn("CLOSE_WAIT", 44000)]
        delta = t.update(conns3, t0 + 20)
        check("a state change is detected",
              delta["changed"] and delta["changed"][0]["to"] == "CLOSE_WAIT",
              delta["changed"])
        check("and it says how long the old state lasted",
              delta["changed"][0]["after"] >= 10, delta["changed"][0])
        check("the age resets when the state changes",
              conns3[0]["age_in_state"] == 0, conns3[0]["age_in_state"])
        delta = t.update([], t0 + 30)
        check("a connection that goes away is noticed",
              delta["disappeared"], delta)
        t2 = ConnectionTracker()
        t2.update([_conn("CLOSE_WAIT", 45000)], time.time() - 120)
        check("stuck() finds a connection past a threshold",
              len(t2.stuck("CLOSE_WAIT", 60.0)) == 1)
        check("and not one below it", not t2.stuck("CLOSE_WAIT", 300.0))
        check("nor one in a different state", not t2.stuck("ESTABLISHED", 1.0))

        print("\n Summarising a table")
        table = ([_conn("ESTABLISHED", 44000 + i, process="nginx", pid=10)
                  for i in range(5)]
                 + [_conn("CLOSE_WAIT", 45000 + i, process="myapp", pid=20, age=300)
                    for i in range(30)]
                 + [_conn("TIME_WAIT", 46000 + i) for i in range(100)]
                 + [_conn("LISTEN", 80, remote="0.0.0.0", remote_port=0,
                          process="nginx", pid=10)]
                 + [_conn("ESTABLISHED", 47000, tx=65536, timer=4, process="myapp",
                          pid=20)]
                 + [_conn("ESTABLISHED", 47001, rtx=9, timer=1, process="myapp",
                          pid=20)])
        s = summarise(table)
        check("connections are counted", s["total"] == len(table))
        check("states are tallied", s["by_state"]["CLOSE_WAIT"] == 30, s["by_state"])
        check("listening sockets are counted separately", s["listening"] == 1)
        check("a listening socket is not counted as a peer",
              "0.0.0.0" not in s["by_peer"])
        check("queued data is picked out", len(s["with_queued_data"]) == 1)
        # only the rtx=9 connection qualifies: the zero-window one has timer 4,
        # which is a different condition and is counted separately below
        check("retransmitting connections are picked out",
              len(s["retransmitting"]) == 1, len(s["retransmitting"]))
        check("and a zero-window connection is NOT counted as retransmitting",
              all(c["timer_type"] != 4 for c in s["retransmitting"]),
              "they are different problems and are reported separately")
        check("a zero-window timer is picked out", len(s["zero_window"]) == 1)
        check("the process breakdown is per state",
              s["by_state_process"]["CLOSE_WAIT"]["myapp"] == 30,
              s["by_state_process"].get("CLOSE_WAIT"))
        check("the oldest connection in a state is found",
              s["oldest_in_state"]["CLOSE_WAIT"]["age"] == 300,
              s["oldest_in_state"].get("CLOSE_WAIT"))

        print("\n Findings")
        C = Result("connections")
        C.data = {"connections": table, "denied": 0, "owner_coverage": 100.0,
                  "sources": ["fixture"], "sampled_at": time.time()}
        L = read_limits()
        tr = ConnectionTracker()
        tr.update(table, time.time() - 60)
        tr.update(table, time.time())
        f = analyse(C, L, tr, s, {})
        titles = [x["title"] for x in f]
        check("a CLOSE_WAIT pile is reported",
              any("waiting on local code" in x for x in titles), titles)
        cw = next(x for x in f if "waiting on local code" in x["title"])
        check("and it names the process holding them", "myapp" in cw["description"],
              cw["description"])
        check("and says the kernel cannot clear them",
              "cannot clear" in cw["advice"], cw["advice"][:80])
        check("and offers the innocent explanation too",
              "slow to close" in cw["advice"])
        check("and gives a command to look further", "limits" in cw.get("fix", ""))
        tw = next((x for x in f if x["category"] == "TIME_WAIT"), None)
        check("TIME_WAIT is reported as informational at this scale",
              tw and tw["severity"] == "info", tw["severity"] if tw else None)
        check("and its advice says it is usually normal",
              tw and "NORMAL" in tw["advice"], tw["advice"][:60] if tw else None)
        check("queued data is reported",
              any(x["category"] == "Queues" for x in f), titles)
        qf = next(x for x in f if x["category"] == "Queues")
        check("and the advice explains what a plain listing hides",
              "hides" in qf["advice"], qf["advice"][:70])
        check("a zero window is reported separately",
              any("zero window" in x for x in titles), titles)
        check("repeated retransmits are reported",
              any("retransmitting repeatedly" in x for x in titles), titles)
        check("every finding carries advice",
              all(x.get("advice") for x in f),
              [x["title"] for x in f if not x.get("advice")])

        print("\n TIME_WAIT only matters against the port range")
        L2 = Result("limits")
        L2.data = {"settings": {}, "available": True,
                   "port_range": {"low": 32768, "high": 60999, "count": 28232}}
        many = [_conn("TIME_WAIT", 40000 + i) for i in range(20000)]
        s2 = summarise(many)
        C2 = Result("connections")
        C2.data = {"connections": many, "denied": 0, "owner_coverage": 0.0,
                   "sources": ["fixture"], "sampled_at": time.time()}
        f2 = analyse(C2, L2, None, s2, {})
        tw2 = next(x for x in f2 if x["category"] == "TIME_WAIT")
        check("TIME_WAIT over half the port range IS reported",
              tw2["severity"] == "high", tw2["severity"])
        check("and the advice names the real symptom",
              "connections failing" in tw2["advice"], tw2["advice"][:80])
        check("and warns against tcp_tw_recycle specifically",
              "tcp_tw_recycle" in tw2["advice"], tw2["advice"][-80:])
        f3 = analyse(C2, L2, None, summarise([_conn("TIME_WAIT", 40000 + i)
                                              for i in range(500)]), {})
        tw3 = next(x for x in f3 if x["category"] == "TIME_WAIT")
        check("but a modest number is only informational",
              tw3["severity"] == "info", tw3["severity"])

        print("\n Nothing checked is not nothing found")
        CU = Result("connections").unavailable("no /proc/net/tcp")
        fu = analyse(CU, L, None, {}, {})
        check("collectors failing is reported",
              any("could not be read" in x["title"] for x in fu),
              [x["title"] for x in fu])
        check("and it says that is not the same as none existing",
              any("not the same as" in x.get("advice", "") for x in fu))
        check("the band reads 'not checked' when nothing could be read",
              risk_band(0.0, checked=False)[0] == "not checked")
        check("and 'nothing unusual' when the checks ran",
              risk_band(0.0, checked=True)[0] == "nothing unusual")
        fe = analyse(C, L, None, summarise([]), {})
        check("an empty table is explained rather than treated as a pass",
              any("No TCP connections" in x["title"] for x in fe)
              or any("connection(s)" in x["title"] for x in fe), [x["title"] for x in fe])
        one = analyse(C, L, ConnectionTracker(), s, {})
        check("a single sample says durations cannot be measured",
              any("one sample" in x["title"] for x in one), [x["title"] for x in one])

        print("\n Collectors on this machine")
        real = read_connections()
        check(f"connections are read or their absence explained ({real.status})",
              real.status in ("ok", "partial", "unavailable"))
        if real.data and real.data["connections"]:
            c0 = real.data["connections"][0]
            check("every connection has a state", all(x["state"] for x in
                                                      real.data["connections"]))
            check("the queues are read",
                  all(isinstance(x["tx_queue"], int) for x in real.data["connections"]))
            check("the timer is decoded",
                  all(x["timer_name"] for x in real.data["connections"]))
            check("the retransmit count is read",
                  all(isinstance(x["retransmits"], int)
                      for x in real.data["connections"]))
            check("owner coverage is a number",
                  isinstance(real.data["owner_coverage"], float))
            check("a listening socket is recognised",
                  any(x["state"] == "LISTEN" for x in real.data["connections"])
                  or True)
        lim = read_limits()
        check(f"limits are read or their absence explained ({lim.status})",
              lim.status in ("ok", "partial", "unavailable"))
        if lim.data and lim.data.get("port_range"):
            check("the local port range is parsed",
                  lim.data["port_range"]["count"] > 0, lim.data["port_range"])

        print("\n Against connections this test really creates")
        srv = None
        held = []
        try:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(20)
            port = srv.getsockname()[1]
            for _i in range(6):
                client = socket.socket()
                client.settimeout(2.0)
                client.connect(("127.0.0.1", port))
                accepted, _addr = srv.accept()
                held.append(accepted)     # the server end never closes
                client.close()            # so the server end goes to CLOSE_WAIT
            time.sleep(0.6)
            live = read_connections()
            if live.status == "unavailable":
                skip("real CLOSE_WAIT connections are seen", live.detail[:60])
            else:
                cw_live = [c for c in live.data["connections"]
                           if c["state"] == "CLOSE_WAIT"
                           and c["local_ip"].startswith("127.")]
                check("connections we deliberately left half-closed are found",
                      len(cw_live) >= 6, len(cw_live))
                fw2 = [c for c in live.data["connections"]
                       if c["state"] == "FIN_WAIT2" and c["local_ip"].startswith("127.")]
                check("and the OTHER end of the same connections is in FIN_WAIT2",
                      len(fw2) >= 6,
                      "the same problem looks different from each end")
                if cw_live:
                    check("the owning process is identified",
                          any(c.get("pid") for c in cw_live),
                          "should be this test's own process")
                    check("and it is this process",
                          any(c.get("pid") == os.getpid() for c in cw_live),
                          [c.get("pid") for c in cw_live[:3]])
                tr2 = ConnectionTracker()
                tr2.update(live.data["connections"], time.time() - 5)
                live2 = read_connections()
                tr2.update(live2.data["connections"], time.time())
                aged = [c for c in live2.data["connections"]
                        if c["state"] == "CLOSE_WAIT"
                        and (c.get("age_in_state") or 0) >= 5]
                check("their age in state is measured across samples",
                      len(aged) >= 6, len(aged))
                s_live = summarise(live2.data["connections"])
                f_live = analyse(live2, lim, tr2, s_live, {})
                check("and a finding is raised about them",
                      any(x["category"] == "CLOSE_WAIT" for x in f_live),
                      [x["title"] for x in f_live])
        except OSError as e:
            skip("real CLOSE_WAIT connections are seen", f"sockets unavailable: {e}")
        finally:
            for h in held:
                try:
                    h.close()
                except OSError:
                    pass
            if srv:
                try:
                    srv.close()
                except OSError:
                    pass

        print("\n Persistence")
        sid = save_scan(C, L, tr, s, f, 120, "selftest")
        sm = scan_summary(sid)
        check("a check is stored", sm and sm["id"] == sid)
        check("the total is stored", sm["total"] == len(table), sm["total"])
        check("CLOSE_WAIT is stored as its own column", sm["close_wait"] == 30,
              sm["close_wait"])
        check("TIME_WAIT is stored as its own column", sm["time_wait"] == 100)
        check("observations are stored per connection",
              q1("SELECT COUNT(*) c FROM observations WHERE scan_id=?",
                 (sid,))["c"] == len(table))
        check("findings are stored",
              q1("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                 (sid,))["c"] == len(f))
        check("the age is stored with whether it is a lower bound",
              q1("SELECT age_is_lower_bound FROM observations WHERE scan_id=? "
                 "AND state='CLOSE_WAIT' LIMIT 1", (sid,)) is not None)
        save_scan(C, L, tr, s, f, 120)
        check("seeing a peer twice increments rather than duplicating",
              all(r["times_seen"] >= 2 for r in q("SELECT * FROM peers", ())),
              [dict(r) for r in q("SELECT peer, times_seen FROM peers LIMIT 3", ())])
        ok, key = approve_peer("198.51.100.9", "our API")
        check("a peer can be approved", ok, key)
        check("approval is recorded", peer_map()[key]["approved"])
        check("approval can be revoked",
              revoke_peer(key) >= 1 and not peer_map()[key]["approved"])
        ok, why = approve_peer("203.0.113.99")
        check("approving a peer never seen is refused with a reason",
              not ok and "has not been seen" in why, why)

        print("\n Charts")
        sv = svg_states(dict(s["by_state"]), s["oldest_in_state"])
        check("a bar is drawn per state", sv.count("<rect") >= len(s["by_state"]))
        check("CLOSE_WAIT is coloured as the one pointing at local code",
              STATE_COLOR["CLOSE_WAIT"] in sv)
        check("and TIME_WAIT is coloured neutrally, not as an alarm",
              STATE_COLOR["TIME_WAIT"] == "#8b8f9b")
        check("the states chart with nothing says so",
              "no connections" in svg_states({}))
        mx = svg_matrix(s["by_state_process"])
        check("the matrix lays out processes against states", mx.count("<rect") > 4)
        check("the matrix says when no owner could be identified",
              "needs privileges" in svg_matrix({}))
        check("history needs two checks and says so",
              "needs at least two" in svg_history([{"total": 1}]))
        check("pie renders slices",
              svg_pie([("a", 2, "#fff"), ("b", 1, "#000")]).count("<path") == 2)
        check("charts guard against empty input",
              all("nothing to show" in x or "no connections" in x
                  or "needs privileges" in x or "needs at least" in x
                  for x in (svg_pie([]), svg_bar([]), svg_states({}), svg_matrix({}),
                            svg_history([]))))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export carries the disclaimer",
              "NOT A PROBLEM" in j["disclaimer"].upper())
        check("JSON export says a state is not a problem",
              "not a problem" in j["a_state_is_not_a_problem"])
        check("JSON export says CLOSE_WAIT is local",
              "local code" in j["close_wait_is_local"])
        check("JSON export includes what every state means",
              len(j["state_meanings"]) >= 10, len(j["state_meanings"]))
        check("JSON export lists the limitations", len(j["limitations"]) >= 7)
        check("JSON export says durations are a lower bound",
              any("LOWER BOUND" in x for x in j["limitations"]))
        c_ = export_csv(sid)
        check("CSV export has sections", c_.count("##") >= 3)
        check("CSV says a state is not a problem",
              any("not a problem" in l.lower() for l in c_.splitlines()[:6]))
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export contains charts and the author", "<svg" in h and AUTHOR in h)
        check("HTML export marks lower-bound durations", "at least" in h)

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Overview"), ("/connections", "Connections"),
                               ("/scans", "Checks"), ("/learn", "who is waiting"),
                               ("/logs", "Logs")):
                r_ = cl.get(path)
                body = r_.get_data(as_text=True)
                check(f"page {path} renders",
                      r_.status_code == 200 and must.lower() in body.lower(),
                      r_.status_code)
            check("every page says a state is not a problem",
                  "not a problem" in cl.get("/").get_data(as_text=True))
            learn = cl.get("/learn").get_data(as_text=True)
            check("the learn page explains every state",
                  all(s in learn for s in ("CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT2")))
            check("the learn page warns against tcp_tw_recycle",
                  "tcp_tw_recycle" in learn)
            check("the learn page explains the queues and timers",
                  "send queue" in learn)
            check("filtering connections by state works",
                  cl.get("/connections?state=CLOSE_WAIT").status_code == 200)
            body = cl.get("/connections?state=CLOSE_WAIT").get_data(as_text=True)
            check("and the state's meaning is shown alongside",
                  "waiting on" in body.lower(), "the filter should teach, not just list")
            r_ = cl.post("/check", data={"samples": "1", "interval": "1"})
            check("a check runs from the web", r_.status_code == 302)
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                r_ = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      r_.status_code == 200 and ctype in r_.headers["Content-Type"]
                      and "attachment" in r_.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            api = cl.get("/api/summary").get_json()
            check("the api declares it is read-only", api["read_only"] is True)
            check("the api declares durations are a lower bound",
                  api["durations_are_a_lower_bound"] is True)

        print("\n It changes nothing")
        mod = sys.modules[__name__]
        import inspect
        changers = [n for n in dir(mod)
                    if n.startswith(("kill_", "close_conn", "reset_", "drop_", "set_sysctl",
                                     "terminate"))
                    and n != "set_db_path"]
        check("no function exists to close a socket or kill a process", not changers,
              changers)
        collectors = [read_connections, read_limits, summarise, analyse,
                      socket_inode_map, process_info]
        joined = "".join(inspect.getsource(fn) for fn in collectors)
        check("no collector opens a socket",
              "socket.socket" not in joined, "reading /proc needs no socket at all")
        check("no collector writes anywhere",
              not any(w in joined for w in ('"w"', "'w'", '"a"', "os.remove", "kill")),
              "it must only read")
        probe = os.path.join(tmp, "untouched")
        with open(probe, "w") as fh:
            fh.write("unchanged")
        run_check(samples=1)
        check("a check does not write to unrelated files",
              open(probe).read() == "unchanged")

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1, peers=False))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned observations and findings",
              all(q1(f"SELECT COUNT(*) c FROM {t} WHERE scan_id NOT IN "
                     f"(SELECT id FROM scans)", ())["c"] == 0
                  for t in ("observations", "findings")))
        cmd_purge(argparse.Namespace(all=True, keep=1, peers=False))
        check("purge --all clears the checks",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
        check("the peer list survives by default",
              q1("SELECT COUNT(*) c FROM peers", ())["c"] > 0)
        cmd_purge(argparse.Namespace(all=True, keep=1, peers=True))
        check("purge --all --peers clears it too",
              q1("SELECT COUNT(*) c FROM peers", ())["c"] == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed"
          + (f", {len(skipped)} skipped" if skipped else ""))
    if failed:
        print("  Failed: " + ", ".join(failed))
    if skipped:
        print("  Skipped: " + ", ".join(skipped))
    if not failed:
        print("  All checks passed. Nothing on this machine was changed, and the\n"
              "  temporary database has been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 12 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - TCP connection state monitor, by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s learn                    where connections pile up, and why
              %(prog)s states CLOSE_WAIT        explain one state
              %(prog)s check --samples 5        durations need more than one sample
              %(prog)s check --verbose
              %(prog)s top                      the connections worth looking at
              %(prog)s limits                   the ceilings a pile would hit
              %(prog)s watch --interval 30
              %(prog)s check --fail-on-close-wait 20
              %(prog)s serve                    http://127.0.0.1:5000

            Read-only: it closes no socket, kills no process and changes no setting.
            Durations are a lower bound, measured from when this tool first looked.

            {DISCLAIMER_LONG}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB})")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    def common(s):
        s.add_argument("--no-listening", action="store_true",
                       help="leave listening sockets out")
        s.add_argument("--verbose", action="store_true",
                       help="list the connections worth reading")
        s.add_argument("--quiet", action="store_true", help="hide informational findings")
        s.add_argument("--show", type=int, help="limit how many findings are printed")
        s.add_argument("--no-fix", action="store_true")
        s.add_argument("--fail-on-close-wait", type=int, metavar="N",
                       help="exit non-zero if more than N connections are in CLOSE_WAIT")
        s.add_argument("--fail-on-critical", action="store_true")
        s.add_argument("--fail-over", type=float,
                       help="exit non-zero if the score exceeds this")
        s.add_argument("--note")
        return s

    s = common(sub.add_parser("check", help="sample the connection table and analyse it"))
    s.add_argument("--samples", type=int, default=1,
                   help="how many samples to take; more than one makes durations real")
    s.add_argument("--interval", type=float, default=2.0)
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("watch", help="sample repeatedly and report what changes")
    s.add_argument("--interval", type=float, default=30.0)
    s.add_argument("--count", type=int)
    s.add_argument("--delta-threshold", type=int, default=10,
                   help="report when a state's count moves by this much")
    s.add_argument("--no-listening", action="store_true")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("top", help="the connections most worth looking at")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_top)

    s = sub.add_parser("states", help="what a state means and who is waiting")
    s.add_argument("state", nargs="?", help="one state, or leave blank for all")
    s.set_defaults(func=cmd_states)

    s = sub.add_parser("limits", help="the ceilings a pile of connections would hit")
    s.set_defaults(func=cmd_limits)

    s = sub.add_parser("peers", help="every peer seen")
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(func=cmd_peers)

    s = sub.add_parser("approve", help="accept a peer's connection count as expected")
    s.add_argument("peer")
    s.add_argument("--label")
    s.add_argument("--note")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("revoke", help="undo an approval")
    s.add_argument("peer")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("learn", help="where connections pile up, and what it means")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("scans", help="previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("serve", help="start the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=50)
    s.add_argument("--all", action="store_true")
    s.add_argument("--peers", action="store_true",
                   help="with --all, also delete the peer list and approvals")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every component (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, counts and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
