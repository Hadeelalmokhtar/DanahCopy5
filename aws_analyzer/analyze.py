"""
AWS EC2 eBPF Analyzer
Watches for new packages and runs full kernel-level analysis.
Results saved locally — GitHub Actions copies them via SSH.
"""

import os
import re
import sys
import time
import json
import glob
import subprocess
import threading
import tempfile
import tarfile

REPO_DIR    = "/home/ubuntu/DanahCopy5"
WATCH_FILE  = ".ebpf_pending"
DECOY_DIR   = "decoy_logs/decoy_runs"
FLAG_DIR    = "decoy_logs"

PRIVATE_RANGES = [
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "::1", "fe80"
]

def is_private_ip(ip):
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

# ── opensnoop parser ──────────────────────────────────────────

def parse_opensnoop(path, pid_filter=None):
    counts = {
        "root_dir_access": 0, "etc_dir_access":  0,
        "tmp_dir_access":  0, "home_dir_access": 0,
        "ssh_dir_access":  0, "other_dir_access": 0,
    }
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 6: continue
                if parts[0] == "TIME(s)": continue
                try:
                    pid      = parts[1]
                    path_val = parts[-1]
                except:
                    continue
                if pid_filter and pid != str(pid_filter): continue
                if "/root/"  in path_val: counts["root_dir_access"]  += 1
                elif "/etc/" in path_val: counts["etc_dir_access"]   += 1
                elif "/tmp/" in path_val: counts["tmp_dir_access"]   += 1
                elif "/home/"in path_val: counts["home_dir_access"]  += 1
                elif "/.ssh/"in path_val: counts["ssh_dir_access"]   += 1
                else:                     counts["other_dir_access"] += 1
    except Exception as e:
        print(f"[opensnoop] parse error: {e}")
    return {
        **counts,
        "ebpf_accessed_root": counts["root_dir_access"] > 0,
        "ebpf_accessed_ssh":  counts["ssh_dir_access"]  > 0,
        "ebpf_accessed_etc":  counts["etc_dir_access"]  > 5,
    }


# ── strace full output parser ─────────────────────────────────

def parse_strace_full(path):
    """
    Parses strace -f -e trace=network,process,file output.
    Extracts:
    - syscall counts (security, network, process, file)
    - remote IPs and ports
    - C2 port detection
    """
    security_calls = {"setuid","setgid","chmod","capset","setreuid","ptrace","capget"}
    network_calls  = {"socket","connect","accept","listen","sendto","recvfrom","bind","recvmsg","sendmsg"}
    process_calls  = {"fork","vfork","clone","clone3","execve","kill","exit","exit_group"}
    file_calls     = {"open","openat","read","write","close","unlink","rename","newfstatat"}
    suspicious_ports = {6667, 4444, 1337, 8080, 9001}

    counts = {
        "ebpf_security_ops": 0,
        "ebpf_network_ops":  0,
        "ebpf_process_ops":  0,
        "ebpf_file_ops":     0,
    }

    remote_ips   = set()
    remote_ports = set()
    c2_suspected = False

    # Regex to extract syscall name from strace line
    syscall_re  = re.compile(r'^\d+\s+(\w+)\(')
    # Regex to extract connect() IP and port
    connect_re  = re.compile(r'connect\(.*sin_port=htons\((\d+)\).*inet_addr\("([^"]+)"\)')

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line: continue

                # Count syscalls
                m = syscall_re.match(line)
                if m:
                    name = m.group(1).lower()
                    if name in security_calls: counts["ebpf_security_ops"] += 1
                    if name in network_calls:  counts["ebpf_network_ops"]  += 1
                    if name in process_calls:  counts["ebpf_process_ops"]  += 1
                    if name in file_calls:     counts["ebpf_file_ops"]     += 1

                # Extract IPs and ports from connect() calls
                cm = connect_re.search(line)
                if cm:
                    port = int(cm.group(1))
                    ip   = cm.group(2)
                    if port > 0:
                        remote_ports.add(port)
                        if port in suspicious_ports:
                            c2_suspected = True
                    if ip and not is_private_ip(ip):
                        remote_ips.add(ip)

    except Exception as e:
        print(f"[strace] parse error: {e}")

    return {
        **counts,
        "ebpf_privilege_escalation": counts["ebpf_security_ops"] > 0,
        "ebpf_network_activity":     counts["ebpf_network_ops"]  > 0,
        "ebpf_spawned_process":      counts["ebpf_process_ops"]  > 2,
        "ebpf_remote_ips_count":     len(remote_ips),
        "ebpf_remote_ips":           "|".join(sorted(remote_ips)),
        "ebpf_remote_ports":         "|".join(str(p) for p in sorted(remote_ports)),
        "ebpf_c2_port_suspected":    c2_suspected,
    }


def extract_patterns(opensnoop_path, pid_filter=None):
    syscall_sequence = []
    try:
        with open(opensnoop_path) as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    if pid_filter and str(obj.get("PID", obj.get("pid", ""))) != str(pid_filter):
                        continue
                    sc = obj.get("syscall", "")
                    if sc:
                        syscall_sequence.append(sc.lower())
                except Exception:
                    pass
    except Exception:
        pass

    def has_sequence(seq):
        it = iter(syscall_sequence)
        return all(s in it for s in seq)

    enoent_count = sum(1 for s in syscall_sequence if "enoent" in s)
    return {
        "pattern_c2_communication":     has_sequence(["socket", "bind", "listen", "accept", "execve"]),
        "pattern_process_injection":    has_sequence(["mmap", "fork", "ptrace", "execve"]),
        "pattern_malicious_probing":    enoent_count > 50,
        "pattern_privilege_escalation": has_sequence(["ioctl", "setresuid", "setresgid", "execve"]),
        "pattern_file_locking":         has_sequence(["openat", "fstat", "fcntl"]),
    }


# ── Package Analysis ─────────────────────────────────────────

def analyze_package(pkg_name, run_number="0"):
    print(f"\n[analyzer] Starting analysis for: {pkg_name} (run={run_number})")

    pkg_path = os.path.join(REPO_DIR, pkg_name)
    if not os.path.exists(pkg_path):
        print(f"[analyzer] Package not found: {pkg_path}")
        return

    opensnoop_out = "/tmp/ebpf_opensnoop.txt"
    strace_out    = "/tmp/ebpf_strace_full.txt"

    for f in [opensnoop_out, strace_out]:
        if os.path.exists(f):
            os.remove(f)

    print("[analyzer] Starting eBPF monitors...")
    f_open = open(opensnoop_out, "w")

    mon_open = subprocess.Popen(
        ["sudo", "opensnoop-bpfcc", "-T"],
        stdout=f_open,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    print("[analyzer] Running package under strace...")
    sandbox_start = time.time()
    proc = None
    pkg_pid = None

    try:
        if pkg_name.endswith(".tgz") or pkg_name.endswith(".tar.gz"):
            tmp_dir = tempfile.mkdtemp()
            with tarfile.open(pkg_path) as tar:
                tar.extractall(tmp_dir)

            js_files = glob.glob(f"{tmp_dir}/**/index.js", recursive=True)
            py_files = glob.glob(f"{tmp_dir}/**/*.py",     recursive=True)

            if js_files:
                proc = subprocess.Popen(
                    ["strace", "-f", "-e", "trace=network,process,file",
                     "-o", strace_out, "node", js_files[0]],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            elif py_files:
                proc = subprocess.Popen(
                    ["strace", "-f", "-e", "trace=network,process,file",
                     "-o", strace_out, "python3", py_files[0]],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

        if proc:
            pkg_pid = proc.pid
            print(f"[analyzer] Package PID: {pkg_pid}")
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()

    except Exception as e:
        print(f"[analyzer] Error running package: {e}")

    sandbox_end = time.time()
    print(f"[analyzer] Done. Duration: {int(sandbox_end - sandbox_start)}s")

    subprocess.run(["sudo", "kill", str(mon_open.pid)], capture_output=True)
    f_open.flush()
    f_open.close()
    time.sleep(2)

    print("[analyzer] Parsing results...")
    opensnoop_features = parse_opensnoop(opensnoop_out, None)
    strace_features    = parse_strace_full(strace_out)
    pattern_features   = extract_patterns(opensnoop_out, None)

    all_features = {
        **opensnoop_features,
        **strace_features,
        **pattern_features,
    }

    print(f"[analyzer] Features: {all_features}")

    pkg_stem = pkg_name.replace(".tgz", "").replace(".tar.gz", "")
    log_dir  = os.path.join(REPO_DIR, DECOY_DIR)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{pkg_stem}_run{run_number}_ebpf.json")

    with open(log_path, "w") as f:
        json.dump({
            "package":          pkg_name,
            "analysis_type":    "aws_ebpf",
            "run_timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sandbox_start":    sandbox_start,
            "sandbox_end":      sandbox_end,
            "package_pid":      pkg_pid,
            "ebpf_features":    all_features,
            "dynamic_features": {k: str(v) for k, v in all_features.items()},
        }, f, indent=2)

    print(f"[analyzer] Results saved at {log_path}")
    print(f"[analyzer] Done ✅ {pkg_name}")


# ── Main Watch Loop ──────────────────────────────────────────

def main():
    print("[watcher] AWS EC2 Analyzer started")
    os.chdir(REPO_DIR)

    while True:
        print(f"[watcher] Waiting... {time.strftime('%H:%M:%S')}")
        pending = os.path.join(REPO_DIR, WATCH_FILE)
        if os.path.exists(pending):
            with open(pending) as f:
                content = f.read().strip()
            if ":" in content:
                pkg_name, run_number = content.split(":", 1)
            else:
                pkg_name, run_number = content, "0"
            if pkg_name:
                print(f"[watcher] New package detected: {pkg_name} (run={run_number})")
                os.remove(pending)
                analyze_package(pkg_name, run_number)
        time.sleep(5)


if __name__ == "__main__":
    main()
