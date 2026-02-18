#!/usr/bin/env python3
"""
Debian 13 Daily System Audit Script
Performs a comprehensive audit of a Debian-based system and generates
a detailed HTML and text report.
"""

import os
import sys
import subprocess
import socket
import datetime
import platform
import re
import json
import stat
import pwd
import grp
import shutil
from pathlib import Path
from collections import defaultdict


# ─── Configuration ────────────────────────────────────────────────────────────

REPORT_DIR = "/var/log/audit_reports"
DISK_WARN_THRESHOLD = 80       # % used before warning
DISK_CRIT_THRESHOLD = 95       # % used before critical
MEM_WARN_THRESHOLD = 85        # % used before warning
LOAD_WARN_MULTIPLIER = 2.0     # load avg > N * cpu_count → warning
FAILED_LOGIN_THRESHOLD = 5     # failed logins before flagging
MAX_LOG_LINES = 50             # max log lines to include in report
WORLD_WRITABLE_DIRS = [        # directories to scan for world-writable files
    "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
]
CRITICAL_SERVICES = [          # services that should be running
    "ssh", "cron", "rsyslog",
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def run(cmd, timeout=30):
    """Run a shell command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out: {cmd}", 1
    except Exception as e:
        return "", str(e), 1


def read_file(path):
    """Read a file and return its content or empty string on error."""
    try:
        return Path(path).read_text(errors="replace")
    except Exception:
        return ""


def bytes_to_human(n):
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ─── Audit Sections ───────────────────────────────────────────────────────────

class AuditReport:
    def __init__(self):
        self.timestamp = datetime.datetime.now()
        self.hostname = socket.gethostname()
        self.sections = []          # list of Section dicts
        self.findings = []          # list of (severity, message) tuples
        self.score = 100            # starts at 100, deducted per finding

    def add_section(self, title, data, raw=None):
        self.sections.append({"title": title, "data": data, "raw": raw})

    def finding(self, severity, message, deduct=0):
        """Record a finding. severity: 'INFO', 'WARN', 'CRIT'."""
        self.findings.append((severity, message))
        self.score = max(0, self.score - deduct)

    # ── 1. System Info ────────────────────────────────────────────────────────

    def collect_system_info(self):
        uptime_raw, _, _ = run("uptime -p")
        uptime_since, _, _ = run("uptime -s")
        kernel, _, _ = run("uname -r")
        arch, _, _ = run("uname -m")
        os_release = {}
        for line in read_file("/etc/os-release").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                os_release[k.strip()] = v.strip().strip('"')

        cpu_model, _, _ = run(
            "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2"
        )
        cpu_count_str, _, _ = run("nproc")
        cpu_count = int(cpu_count_str) if cpu_count_str.isdigit() else 1

        data = {
            "Hostname": self.hostname,
            "OS": os_release.get("PRETTY_NAME", platform.platform()),
            "Kernel": kernel,
            "Architecture": arch,
            "CPU": cpu_model.strip() or "Unknown",
            "CPU cores": cpu_count,
            "Uptime": uptime_raw,
            "Running since": uptime_since,
            "Audit timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.add_section("System Information", data)
        return cpu_count

    # ── 2. CPU & Load ─────────────────────────────────────────────────────────

    def collect_cpu_load(self, cpu_count):
        load_raw = read_file("/proc/loadavg").split()
        load1 = float(load_raw[0]) if load_raw else 0.0
        load5 = float(load_raw[1]) if len(load_raw) > 1 else 0.0
        load15 = float(load_raw[2]) if len(load_raw) > 2 else 0.0

        cpu_usage, _, _ = run(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'"
        )

        data = {
            "Load avg (1m)": f"{load1:.2f}",
            "Load avg (5m)": f"{load5:.2f}",
            "Load avg (15m)": f"{load15:.2f}",
            "CPU cores": cpu_count,
            "CPU usage %": cpu_usage or "N/A",
        }

        if load1 > LOAD_WARN_MULTIPLIER * cpu_count:
            self.finding("WARN",
                f"High 1-min load average: {load1:.2f} (cores: {cpu_count})", deduct=5)
        if load5 > LOAD_WARN_MULTIPLIER * cpu_count:
            self.finding("WARN",
                f"High 5-min load average: {load5:.2f}", deduct=3)

        self.add_section("CPU & Load", data)

    # ── 3. Memory ─────────────────────────────────────────────────────────────

    def collect_memory(self):
        mem = {}
        for line in read_file("/proc/meminfo").splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                mem[k.strip()] = v.strip()

        def kb(key):
            val = mem.get(key, "0 kB")
            return int(val.split()[0]) * 1024

        total = kb("MemTotal")
        available = kb("MemAvailable")
        free = kb("MemFree")
        buffers = kb("Buffers")
        cached = kb("Cached")
        swap_total = kb("SwapTotal")
        swap_free = kb("SwapFree")

        used = total - available
        pct = (used / total * 100) if total else 0
        swap_used = swap_total - swap_free
        swap_pct = (swap_used / swap_total * 100) if swap_total else 0

        data = {
            "Total RAM": bytes_to_human(total),
            "Used RAM": bytes_to_human(used),
            "Available RAM": bytes_to_human(available),
            "RAM usage %": f"{pct:.1f}%",
            "Buffers": bytes_to_human(buffers),
            "Cached": bytes_to_human(cached),
            "Swap total": bytes_to_human(swap_total),
            "Swap used": bytes_to_human(swap_used),
            "Swap usage %": f"{swap_pct:.1f}%" if swap_total else "N/A",
        }

        if pct > MEM_WARN_THRESHOLD:
            self.finding("WARN", f"High RAM usage: {pct:.1f}%", deduct=5)
        if swap_pct > 50:
            self.finding("WARN", f"High swap usage: {swap_pct:.1f}%", deduct=3)

        self.add_section("Memory", data)

    # ── 4. Disk Usage ─────────────────────────────────────────────────────────

    def collect_disk(self):
        out, _, _ = run("df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs")
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            pct_str = parts[4].rstrip("%")
            pct = int(pct_str) if pct_str.isdigit() else 0
            row = {
                "Filesystem": parts[0],
                "Size": parts[1],
                "Used": parts[2],
                "Avail": parts[3],
                "Use%": parts[4],
                "Mounted on": parts[5],
            }
            rows.append(row)
            if pct >= DISK_CRIT_THRESHOLD:
                self.finding("CRIT",
                    f"Disk CRITICAL: {parts[5]} ({parts[0]}) at {parts[4]}", deduct=20)
            elif pct >= DISK_WARN_THRESHOLD:
                self.finding("WARN",
                    f"Disk WARNING: {parts[5]} ({parts[0]}) at {parts[4]}", deduct=8)

        inode_out, _, _ = run("df -i --output=source,ipcent,target -x tmpfs -x devtmpfs")
        for line in inode_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                pct_str = parts[1].rstrip("%")
                if pct_str.isdigit() and int(pct_str) >= DISK_WARN_THRESHOLD:
                    self.finding("WARN",
                        f"Inode usage high: {parts[2]} at {parts[1]}", deduct=5)

        self.add_section("Disk Usage", rows, raw=out)

    # ── 5. Network ────────────────────────────────────────────────────────────

    def collect_network(self):
        ip_out, _, _ = run("ip -o addr show")
        interfaces = []
        for line in ip_out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                interfaces.append({"Interface": parts[1], "Address": parts[3]})

        ss_out, _, _ = run("ss -tlnp")
        open_ports = []
        for line in ss_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                open_ports.append({
                    "State": parts[0],
                    "Local Address": parts[3],
                    "Process": parts[6] if len(parts) > 6 else "",
                })

        route_out, _, _ = run("ip route show")
        dns_out = read_file("/etc/resolv.conf")

        data = {
            "Interfaces": interfaces,
            "Listening ports": open_ports,
            "Routes": route_out,
            "DNS config": dns_out[:500],
        }
        self.add_section("Network", data, raw=ip_out)

    # ── 6. Running Services ───────────────────────────────────────────────────

    def collect_services(self):
        svc_out, _, _ = run(
            "systemctl list-units --type=service --state=running --no-pager --no-legend"
        )
        failed_out, _, _ = run(
            "systemctl list-units --type=service --state=failed --no-pager --no-legend"
        )

        running = [line.split()[0] for line in svc_out.splitlines() if line.split()]
        failed = [line.split()[0] for line in failed_out.splitlines() if line.split()]

        for svc in failed:
            self.finding("CRIT", f"Service FAILED: {svc}", deduct=10)

        for svc in CRITICAL_SERVICES:
            full_name = svc if svc.endswith(".service") else svc + ".service"
            if not any(full_name in r for r in running):
                self.finding("WARN", f"Critical service not running: {svc}", deduct=10)

        data = {
            "Running services count": len(running),
            "Failed services": failed or ["none"],
            "Critical services checked": CRITICAL_SERVICES,
        }
        self.add_section("Services", data, raw=svc_out)

    # ── 7. Security: Users & Authentication ───────────────────────────────────

    def collect_users(self):
        # Sudoers
        sudo_out, _, _ = run("getent group sudo wheel")
        # Users with UID 0
        uid0_users = []
        shadow_lines = read_file("/etc/shadow").splitlines()
        passwd_lines = read_file("/etc/passwd").splitlines()

        locked_users = set()
        for line in shadow_lines:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].startswith(("!", "*")):
                locked_users.add(parts[0])

        system_users = []
        human_users = []
        for line in passwd_lines:
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uname, uid_str, shell = parts[0], parts[2], parts[6]
            uid = int(uid_str) if uid_str.isdigit() else -1
            if uid == 0:
                uid0_users.append(uname)
            if uid >= 1000 and not uname.endswith("nobody"):
                human_users.append({
                    "User": uname,
                    "UID": uid,
                    "Shell": shell.strip(),
                    "Locked": uname in locked_users,
                })

        if len(uid0_users) > 1:
            self.finding("CRIT",
                f"Multiple UID-0 accounts: {uid0_users}", deduct=15)

        # Empty passwords
        empty_pwd_users = []
        for line in shadow_lines:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty_pwd_users.append(parts[0])
        if empty_pwd_users:
            self.finding("CRIT",
                f"Accounts with empty passwords: {empty_pwd_users}", deduct=20)

        # Failed logins (last 24h)
        failed_login_out, _, _ = run(
            "journalctl -u ssh --since '24 hours ago' --no-pager 2>/dev/null | "
            "grep -c 'Failed password' || echo 0"
        )
        failed_count = int(failed_login_out) if failed_login_out.isdigit() else 0
        if failed_count >= FAILED_LOGIN_THRESHOLD:
            self.finding("WARN",
                f"High number of SSH failed logins in 24h: {failed_count}", deduct=5)

        # Last logins
        lastlog_out, _, _ = run("lastlog -b 0 2>/dev/null | head -20")

        data = {
            "UID-0 accounts": uid0_users,
            "Human accounts": human_users,
            "Sudo group members": sudo_out,
            "Empty password accounts": empty_pwd_users or ["none"],
            "SSH failed logins (24h)": failed_count,
        }
        self.add_section("Users & Authentication", data, raw=lastlog_out)

    # ── 8. Security: File System ──────────────────────────────────────────────

    def collect_filesystem_security(self):
        # SUID/SGID files
        suid_out, _, _ = run(
            "find /usr /bin /sbin /etc -xdev -perm /6000 -type f 2>/dev/null | head -30"
        )
        suid_files = [f for f in suid_out.splitlines() if f]

        # World-writable files in critical dirs
        ww_out, _, _ = run(
            "find " + " ".join(WORLD_WRITABLE_DIRS) +
            " -xdev -perm -o+w -type f 2>/dev/null | head -20"
        )
        ww_files = [f for f in ww_out.splitlines() if f]

        if ww_files:
            self.finding("CRIT",
                f"World-writable files in critical dirs: {ww_files[:5]}", deduct=15)

        # /etc/crontab and cron.d
        crontab = read_file("/etc/crontab")
        crond_files = []
        crond_path = Path("/etc/cron.d")
        if crond_path.is_dir():
            for f in crond_path.iterdir():
                crond_files.append(str(f))

        # Check /tmp for executables
        tmp_exec_out, _, _ = run(
            "find /tmp -xdev -type f -perm /0111 2>/dev/null | head -10"
        )
        tmp_exec = [f for f in tmp_exec_out.splitlines() if f]
        if tmp_exec:
            self.finding("WARN",
                f"Executable files in /tmp: {tmp_exec[:5]}", deduct=8)

        # Unowned files
        unowned_out, _, _ = run(
            "find /etc /usr /bin /sbin -xdev -nouser -o -nogroup 2>/dev/null | head -10"
        )
        unowned = [f for f in unowned_out.splitlines() if f]
        if unowned:
            self.finding("WARN", f"Unowned files found: {unowned[:5]}", deduct=5)

        data = {
            "SUID/SGID files found": len(suid_files),
            "SUID/SGID files (sample)": suid_files[:10],
            "World-writable in critical dirs": ww_files or ["none"],
            "Executable files in /tmp": tmp_exec or ["none"],
            "Unowned files": unowned or ["none"],
            "Cron files in /etc/cron.d": crond_files,
        }
        self.add_section("Filesystem Security", data)

    # ── 9. Package Updates ────────────────────────────────────────────────────

    def collect_packages(self):
        # Update the package lists quietly
        run("apt-get update -qq 2>/dev/null", timeout=60)

        upgradable_out, _, _ = run(
            "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | head -50"
        )
        upgradable = [l for l in upgradable_out.splitlines() if l]

        security_out, _, _ = run(
            "apt list --upgradable 2>/dev/null | grep -i security | wc -l"
        )
        security_count = int(security_out.strip()) if security_out.strip().isdigit() else 0

        # Held packages
        held_out, _, _ = run("apt-mark showhold 2>/dev/null")
        held = [p for p in held_out.splitlines() if p]

        # Installed package count
        installed_count_out, _, _ = run("dpkg -l | grep '^ii' | wc -l")
        installed_count = installed_count_out.strip()

        # Last upgrade time
        last_upgrade_out, _, _ = run(
            "ls -lt /var/lib/dpkg/info/*.list 2>/dev/null | head -1 | awk '{print $6, $7, $8}'"
        )

        if security_count > 0:
            self.finding("CRIT",
                f"{security_count} security update(s) available", deduct=10)
        elif upgradable:
            self.finding("WARN",
                f"{len(upgradable)} package update(s) available", deduct=3)

        if held:
            self.finding("INFO", f"Held packages (won't auto-update): {held}")

        data = {
            "Installed packages": installed_count,
            "Upgradable packages": len(upgradable),
            "Security updates": security_count,
            "Held packages": held or ["none"],
            "Last package activity": last_upgrade_out or "Unknown",
            "Upgradable list (first 20)": upgradable[:20] or ["none"],
        }
        self.add_section("Package Updates", data)

    # ── 10. Logs & Errors ─────────────────────────────────────────────────────

    def collect_logs(self):
        # kernel errors
        kern_err_out, _, _ = run(
            "journalctl -k -p err --since '24 hours ago' --no-pager 2>/dev/null | tail -20"
        )
        # system critical
        sys_crit_out, _, _ = run(
            "journalctl -p crit --since '24 hours ago' --no-pager 2>/dev/null | tail -20"
        )
        # OOM
        oom_out, _, _ = run(
            "journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -i 'oom\\|killed process' | tail -10"
        )
        if oom_out:
            self.finding("CRIT", "OOM killer events detected in last 24h", deduct=10)

        # Segfaults
        seg_out, _, _ = run(
            "journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -ic 'segfault' || echo 0"
        )
        seg_count = int(seg_out.strip()) if seg_out.strip().isdigit() else 0
        if seg_count > 0:
            self.finding("WARN", f"{seg_count} segfault(s) in logs (last 24h)", deduct=5)

        data = {
            "Kernel errors (24h, last 20)": kern_err_out or "none",
            "System critical events (24h)": sys_crit_out or "none",
            "OOM events": oom_out or "none",
            "Segfaults count (24h)": seg_count,
        }
        self.add_section("System Logs", data)

    # ── 11. Firewall ──────────────────────────────────────────────────────────

    def collect_firewall(self):
        # iptables
        ipt_out, _, rc_ipt = run("iptables -L -n --line-numbers 2>/dev/null | head -40")
        # nftables
        nft_out, _, rc_nft = run("nft list ruleset 2>/dev/null | head -40")
        # ufw
        ufw_out, _, rc_ufw = run("ufw status verbose 2>/dev/null")

        firewall_active = False
        if rc_ipt == 0 and ipt_out and "Chain INPUT" in ipt_out:
            # Check if there are actual rules (not just empty chains)
            rule_count = sum(
                1 for l in ipt_out.splitlines()
                if l and not l.startswith("Chain") and not l.startswith("target") and l.strip()
            )
            if rule_count > 3:
                firewall_active = True
        if "Status: active" in ufw_out:
            firewall_active = True
        if nft_out and "table" in nft_out:
            firewall_active = True

        if not firewall_active:
            self.finding("WARN", "No active firewall rules detected", deduct=10)

        data = {
            "UFW status": ufw_out or "Not installed / inactive",
            "iptables rules (sample)": ipt_out or "none",
            "nftables ruleset (sample)": nft_out or "none",
        }
        self.add_section("Firewall", data)

    # ── 12. SSH Configuration ─────────────────────────────────────────────────

    def collect_ssh(self):
        sshd_conf = read_file("/etc/ssh/sshd_config")
        checks = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "no",
            "Protocol": "2",
            "X11Forwarding": "no",
        }
        results = {}
        for key, recommended in checks.items():
            pattern = re.compile(rf"^\s*{key}\s+(\S+)", re.MULTILINE | re.IGNORECASE)
            match = pattern.search(sshd_conf)
            actual = match.group(1) if match else "not set"
            safe = actual.lower() == recommended.lower()
            results[key] = {"value": actual, "recommended": recommended, "ok": safe}
            if not safe:
                self.finding("WARN",
                    f"SSH: {key} is '{actual}', recommended: '{recommended}'", deduct=5)

        data = {
            "SSH configuration checks": results,
            "Config file": "/etc/ssh/sshd_config",
        }
        self.add_section("SSH Configuration", data)

    # ── 13. Cron Jobs ─────────────────────────────────────────────────────────

    def collect_cron(self):
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
        ]
        jobs = {}
        for loc in cron_locations:
            p = Path(loc)
            if p.is_file():
                jobs[loc] = read_file(loc)[:500]
            elif p.is_dir():
                entries = [str(f) for f in p.iterdir()]
                jobs[loc] = entries

        # Systemd timers
        timers_out, _, _ = run(
            "systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -20"
        )
        data = {
            "Cron locations": jobs,
            "Systemd timers (first 20)": timers_out or "none",
        }
        self.add_section("Cron & Timers", data)

    # ── 14. Top Processes ─────────────────────────────────────────────────────

    def collect_processes(self):
        ps_out, _, _ = run(
            "ps aux --sort=-%mem | head -15"
        )
        zombie_out, _, _ = run(
            "ps aux | awk '$8 == \"Z\"' | wc -l"
        )
        zombie_count = int(zombie_out.strip()) if zombie_out.strip().isdigit() else 0
        if zombie_count > 5:
            self.finding("WARN", f"{zombie_count} zombie processes detected", deduct=3)

        data = {
            "Top 15 by memory": ps_out,
            "Zombie processes": zombie_count,
        }
        self.add_section("Processes", data, raw=ps_out)

    # ── 15. Hardware Health ───────────────────────────────────────────────────

    def collect_hardware(self):
        # CPU temperature (if sensors available)
        temp_out, _, _ = run("sensors 2>/dev/null | head -20")
        # S.M.A.R.T. status (if smartmontools installed)
        smart_devs_out, _, _ = run(
            "ls /dev/sd? /dev/nvme? 2>/dev/null | head -5"
        )
        smart_results = {}
        for dev in smart_devs_out.splitlines():
            smart_out, _, rc = run(f"smartctl -H {dev} 2>/dev/null | grep -E 'SMART overall|result'")
            smart_results[dev] = smart_out or "smartctl not available"

        # dmesg hardware errors
        dmesg_err_out, _, _ = run(
            "dmesg --level=err,crit 2>/dev/null | tail -10"
        )
        if dmesg_err_out:
            self.finding("WARN", "Hardware errors found in dmesg", deduct=5)

        data = {
            "CPU temperature": temp_out or "sensors not installed",
            "SMART disk health": smart_results or {"status": "smartctl not available"},
            "dmesg hardware errors": dmesg_err_out or "none",
        }
        self.add_section("Hardware Health", data)

    # ── Run All Collectors ────────────────────────────────────────────────────

    def run_all(self):
        print("[*] Collecting system information...")
        cpu_count = self.collect_system_info()
        print("[*] Collecting CPU/load data...")
        self.collect_cpu_load(cpu_count)
        print("[*] Collecting memory data...")
        self.collect_memory()
        print("[*] Collecting disk data...")
        self.collect_disk()
        print("[*] Collecting network data...")
        self.collect_network()
        print("[*] Collecting service data...")
        self.collect_services()
        print("[*] Collecting user/auth data...")
        self.collect_users()
        print("[*] Collecting filesystem security data...")
        self.collect_filesystem_security()
        print("[*] Checking for package updates...")
        self.collect_packages()
        print("[*] Collecting log data...")
        self.collect_logs()
        print("[*] Collecting firewall data...")
        self.collect_firewall()
        print("[*] Collecting SSH config...")
        self.collect_ssh()
        print("[*] Collecting cron/timer data...")
        self.collect_cron()
        print("[*] Collecting process data...")
        self.collect_processes()
        print("[*] Collecting hardware health data...")
        self.collect_hardware()


# ─── Report Renderers ─────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRIT": "#e74c3c",
    "WARN": "#f39c12",
    "INFO": "#3498db",
}

SEVERITY_EMOJI = {
    "CRIT": "CRITICAL",
    "WARN": "WARNING",
    "INFO": "INFO",
}


def _score_badge(score):
    if score >= 80:
        color = "#27ae60"
    elif score >= 50:
        color = "#f39c12"
    else:
        color = "#e74c3c"
    return color


def render_value(v, indent=0):
    """Render a value as HTML."""
    pad = "  " * indent
    if isinstance(v, dict):
        rows = "".join(
            f"<tr><td class='k'>{k}</td><td>{render_value(val, indent+1)}</td></tr>"
            for k, val in v.items()
        )
        return f"<table class='inner'>{rows}</table>"
    elif isinstance(v, list):
        if not v:
            return "<em>empty</em>"
        if all(isinstance(i, dict) for i in v):
            if not v:
                return "<em>empty</em>"
            headers = list(v[0].keys())
            head = "".join(f"<th>{h}</th>" for h in headers)
            body = "".join(
                "<tr>" + "".join(f"<td>{render_value(row.get(h, ''))}</td>" for h in headers) + "</tr>"
                for row in v
            )
            return f"<table class='list'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        return "<ul>" + "".join(f"<li>{render_value(i)}</li>" for i in v) + "</ul>"
    elif isinstance(v, bool):
        icon = "✔" if v else "✘"
        cls = "ok" if v else "fail"
        return f"<span class='{cls}'>{icon}</span>"
    else:
        text = str(v)
        if "\n" in text:
            return f"<pre>{text}</pre>"
        return text


def render_html(report):
    score = report.score
    color = _score_badge(score)
    ts = report.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    findings_html = ""
    if report.findings:
        def _finding_li(sev, msg):
            color = SEVERITY_COLOR.get(sev, "#333")
            label = SEVERITY_EMOJI.get(sev, sev)
            return f"<li style='color:{color}'><strong>[{label}]</strong> {msg}</li>"
        items = "".join(_finding_li(sev, msg) for sev, msg in report.findings)
        findings_html = f"<ul class='findings'>{items}</ul>"
    else:
        findings_html = "<p class='ok'>No issues found.</p>"

    sections_html = ""
    for sec in report.sections:
        body = render_value(sec["data"])
        sections_html += f"""
        <details open>
          <summary><h2>{sec['title']}</h2></summary>
          <div class='sec-body'>{body}</div>
        </details>
        """

    return f"""<!DOCTYPE html>
<html lang='pl'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>Audit Report – {report.hostname} – {ts}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',sans-serif;background:#f4f6f9;color:#2c3e50;font-size:14px}}
    header{{background:#2c3e50;color:#fff;padding:20px 30px;display:flex;justify-content:space-between;align-items:center}}
    header h1{{font-size:1.4em}}
    header .meta{{font-size:.85em;opacity:.8}}
    .score-badge{{display:inline-block;background:{color};color:#fff;
      border-radius:50%;width:72px;height:72px;line-height:72px;
      text-align:center;font-size:1.5em;font-weight:bold;margin-left:20px}}
    main{{max-width:1100px;margin:20px auto;padding:0 15px}}
    .findings-box{{background:#fff;border-left:4px solid #e74c3c;padding:15px;
      margin-bottom:20px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
    .findings-box h2{{margin-bottom:10px;color:#e74c3c}}
    ul.findings{{list-style:none;padding:0}}
    ul.findings li{{padding:4px 0;border-bottom:1px solid #f0f0f0}}
    details{{background:#fff;border-radius:6px;margin-bottom:12px;
      box-shadow:0 1px 3px rgba(0,0,0,.1);overflow:hidden}}
    summary{{cursor:pointer;padding:12px 16px;background:#34495e;color:#fff;
      user-select:none;list-style:none}}
    summary h2{{display:inline;font-size:1em;font-weight:600}}
    summary::-webkit-details-marker{{display:none}}
    .sec-body{{padding:14px 16px;overflow-x:auto}}
    table{{border-collapse:collapse;width:100%;margin:6px 0}}
    table.inner{{width:auto}}
    th{{background:#ecf0f1;text-align:left;padding:6px 10px;font-weight:600;
       border-bottom:2px solid #bdc3c7}}
    td{{padding:5px 10px;border-bottom:1px solid #ecf0f1;vertical-align:top}}
    td.k{{font-weight:600;color:#555;white-space:nowrap;min-width:180px}}
    tr:hover td{{background:#f9f9f9}}
    pre{{background:#2c3e50;color:#ecf0f1;padding:10px;border-radius:4px;
       overflow-x:auto;font-size:.82em;white-space:pre-wrap}}
    .ok{{color:#27ae60;font-weight:bold}}
    .fail{{color:#e74c3c;font-weight:bold}}
    ul{{padding-left:1.2em;margin:4px 0}}
    li{{margin:2px 0}}
    footer{{text-align:center;padding:20px;color:#7f8c8d;font-size:.8em}}
  </style>
</head>
<body>
<header>
  <div>
    <h1>Debian Daily Audit Report</h1>
    <div class='meta'>Host: <strong>{report.hostname}</strong> &nbsp;|&nbsp; {ts}</div>
  </div>
  <div style='display:flex;align-items:center'>
    <div>Security Score</div>
    <div class='score-badge'>{score}</div>
  </div>
</header>
<main>
  <div class='findings-box'>
    <h2>Findings ({len(report.findings)})</h2>
    {findings_html}
  </div>
  {sections_html}
</main>
<footer>Generated by debian_audit.py &mdash; {ts}</footer>
</body>
</html>"""


def render_text(report):
    lines = []
    sep = "=" * 72
    thin = "-" * 72

    lines.append(sep)
    lines.append(f"  DEBIAN DAILY AUDIT REPORT")
    lines.append(f"  Host : {report.hostname}")
    lines.append(f"  Date : {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Score: {report.score}/100")
    lines.append(sep)
    lines.append("")

    lines.append("FINDINGS:")
    lines.append(thin)
    if report.findings:
        for sev, msg in report.findings:
            lines.append(f"  [{sev:4s}]  {msg}")
    else:
        lines.append("  No issues found.")
    lines.append("")

    def flat(v, depth=0):
        pad = "  " * depth
        if isinstance(v, dict):
            result = []
            for k, val in v.items():
                inner = flat(val, depth + 1)
                if "\n" in inner:
                    result.append(f"{pad}{k}:")
                    result.append(inner)
                else:
                    result.append(f"{pad}{k}: {inner}")
            return "\n".join(result)
        elif isinstance(v, list):
            if not v:
                return f"{pad}(empty)"
            if all(isinstance(i, dict) for i in v):
                parts = []
                for item in v:
                    parts.append(", ".join(f"{k}={val}" for k, val in item.items()))
                return ("\n" + pad).join(parts)
            return ("\n" + pad + "- ").join([""] + [str(i) for i in v])
        elif isinstance(v, bool):
            return "OK" if v else "FAIL"
        else:
            text = str(v)
            if "\n" in text:
                indented = "\n".join(pad + "  " + l for l in text.splitlines())
                return "\n" + indented
            return text

    for sec in report.sections:
        lines.append(sep)
        lines.append(f"  {sec['title'].upper()}")
        lines.append(sep)
        lines.append(flat(sec["data"], depth=1))
        lines.append("")

    lines.append(sep)
    lines.append(f"  END OF REPORT  |  Score: {report.score}/100")
    lines.append(sep)
    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Debian 13 Daily System Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 debian_audit.py
  sudo python3 debian_audit.py --format text
  sudo python3 debian_audit.py --output /tmp/audit
  sudo python3 debian_audit.py --format both --output /var/log/audits
        """,
    )
    parser.add_argument(
        "--format",
        choices=["html", "text", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--output",
        default=REPORT_DIR,
        help=f"Output directory (default: {REPORT_DIR})",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Also print text report to stdout",
    )
    args = parser.parse_args()

    # Prepare output directory
    out_dir = Path(args.output)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        out_dir = Path("/tmp/audit_reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"[!] Cannot write to {args.output}, using {out_dir}")

    # Run audit
    report = AuditReport()
    report.run_all()

    # Generate filenames
    ts_str = report.timestamp.strftime("%Y%m%d_%H%M%S")
    base_name = f"audit_{report.hostname}_{ts_str}"

    saved = []

    if args.format in ("html", "both"):
        html_path = out_dir / f"{base_name}.html"
        html_path.write_text(render_html(report), encoding="utf-8")
        saved.append(str(html_path))

    if args.format in ("text", "both"):
        txt_path = out_dir / f"{base_name}.txt"
        text_report = render_text(report)
        txt_path.write_text(text_report, encoding="utf-8")
        saved.append(str(txt_path))
        if args.stdout:
            print(text_report)

    # Summary
    print("\n" + "=" * 60)
    print(f"  AUDIT COMPLETE  |  Security Score: {report.score}/100")
    print("=" * 60)
    crits = [m for s, m in report.findings if s == "CRIT"]
    warns = [m for s, m in report.findings if s == "WARN"]
    infos = [m for s, m in report.findings if s == "INFO"]
    print(f"  Critical findings : {len(crits)}")
    print(f"  Warnings          : {len(warns)}")
    print(f"  Informational     : {len(infos)}")
    print("=" * 60)
    print("  Reports saved:")
    for p in saved:
        print(f"    {p}")
    print("=" * 60)

    # Exit with error code if critical findings exist
    sys.exit(1 if crits else 0)


if __name__ == "__main__":
    main()
