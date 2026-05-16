"""
AWS EC2 eBPF Analyzer
Watches GitHub repo for new packages and runs full eBPF analysis.
Pushes results back to GitHub.
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


# ── eBPF Feature Extraction ──────────────────────────────────

def parse_opensnoop(path, pid_filter=None):
    counts = {
        "root_dir_access": 0, "etc_dir_access":  0,
        "tmp_dir_access":  0, "home_dir_access": 0,
        "ssh_dir_access":  0, "other_dir_access": 0,
    }
    try:
        with open(path) as f:
            for line in f:
                # Format: TIME(s) PID COMM FD ERR PATH
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                if parts[0] == "TIME(s)":
                    continue  # skip header
                try:
                    pid  = parts[1]
                    path_val = parts[-1]  # last column is PATH
                except:
                    continue

                if pid_filter and pid != str(pid_filter):
                    continue

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


def parse_tcpconnect(path, pid_filter=None):
    suspicious_ports = {6667, 4444, 1337, 8080, 9001}
    remote_ips   = set()
    remote_ports = set()
    c2_suspected = False

    try:
        with open(path) as f:
            for line in f:
                # Format: TIME(s) PID COMM IP SADDR DADDR DPORT
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                if parts[0] == "TIME(s)":
                    continue  # skip header
                try:
                    pid  = parts[1]
                    ip   = parts[-2]   # DADDR
                    port = int(parts[-1])  # DPORT
                except:
                    continue

                if pid_filter and pid != str(pid_filter):
                    continue

                if ip:   remote_ips.add(ip)
                if port: remote_ports.add(port)
                if port in suspicious_ports:
                    c2_suspected = True

    except Exception as e:
        print(f"[tcpconnect] parse error: {e}")

    return {
        "ebpf_remote_ips_count":  len(remote_ips),
        "ebpf_remote_ports":      "|".join(str(p) for p in remote_ports),
        "ebpf_c2_port_suspected": c2_suspected,
        "ebpf_remote_ips":        "|".join(remote_ips),
    }


def parse_syscount(path, pid_filter=None):
    security_calls = {"setuid","setgid","chmod","capset","setreuid","ptrace","capget"}
    network_calls  = {"socket","connect","accept","listen","sendto","recvfrom","bind"}
    process_calls  = {"fork","vfork","clone","execve","kill","exit","exit_group"}
    file_calls     = {"open","openat","read","write","close","unlink","rename"}

    counts = {
        "ebpf_security_ops": 0,
        "ebpf_network_ops":  0,
        "ebpf_process_ops":  0,
        "ebpf_file_ops":     0,
    }

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if line.startswith("Tracing"): continue
                if line.startswith("Detaching"): continue
                if line.startswith("SYSCALL"): continue
                if line.startswith("["): continue
                parts = line.split()
                if len(parts) < 2: continue
                try:
                    name = parts[0].lower()
                    cnt  = int(parts[-1])
                except:
                    continue
                if name in security_calls: counts["ebpf_security_ops"] += cnt
                if name in network_calls:  counts["ebpf_network_ops"]  += cnt
                if name in process_calls:  counts["ebpf_process_ops"]  += cnt
                if name in file_calls:     counts["ebpf_file_ops"]     += cnt
    except Exception as e:
        print(f"[syscount] parse error: {e}")

    return {
        **counts,
        "ebpf_privilege_escalation": counts["ebpf_security_ops"] > 0,
        "ebpf_network_activity":     counts["ebpf_network_ops"]  > 0,
        "ebpf_spawned_process":      counts["ebpf_process_ops"]  > 2,
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
    print(f"\n[analyzer] Starting eBPF analysis for: {pkg_name}")

    pkg_path = os.path.join(REPO_DIR, pkg_name)
    if not os.path.exists(pkg_path):
        print(f"[analyzer] Package not found: {pkg_path}")
        return

    opensnoop_out  = "/tmp/ebpf_opensnoop.txt"
    tcpconnect_out = "/tmp/ebpf_tcpconnect.txt"
    syscount_out   = "/tmp/ebpf_syscount.txt"

    # Clear old output files
    for f in [opensnoop_out, tcpconnect_out, syscount_out]:
        if os.path.exists(f):
            os.remove(f)

    # Start eBPF monitors
    print("[analyzer] Starting eBPF monitors...")
    f_open = open(opensnoop_out, "w")
    f_tcp  = open(tcpconnect_out, "w")
    f_sys  = open(syscount_out, "w")

    mon_open = subprocess.Popen(
        ["sudo", "opensnoop-bpfcc", "-T"],
        stdout=f_open,
        stderr=subprocess.DEVNULL
    )
    mon_tcp = subprocess.Popen(
        ["sudo", "tcpconnect-bpfcc", "-t"],
        stdout=f_tcp,
        stderr=subprocess.DEVNULL
    )
    mon_sys = subprocess.Popen(
        ["sudo", "syscount-bpfcc", "-c", "1000"],
        stdout=f_sys,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # let monitors initialize

    # Extract and run package
    print("[analyzer] Running package...")
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
                    ["node", js_files[0]],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            elif py_files:
                proc = subprocess.Popen(
                    ["python3", py_files[0]],
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

    # Stop monitors
    for p in [mon_open, mon_tcp]:
        subprocess.run(["sudo", "kill", str(p.pid)], capture_output=True)
    subprocess.run(["sudo", "kill", "-SIGINT", str(mon_sys.pid)], capture_output=True)
    mon_sys.wait(timeout=10)
    f_open.flush()
    f_tcp.flush()
    f_sys.flush()
    f_open.close()
    f_tcp.close()
    f_sys.close()
    time.sleep(2)

    # Parse results
    print("[analyzer] Parsing eBPF results...")
    pid_str = str(pkg_pid) if pkg_pid else None

    opensnoop_features  = parse_opensnoop(opensnoop_out,   None)
    tcpconnect_features = parse_tcpconnect(tcpconnect_out, None)
    syscount_features   = parse_syscount(syscount_out,     None)
    pattern_features    = extract_patterns(opensnoop_out,  None)

    all_features = {
        **opensnoop_features,
        **tcpconnect_features,
        **syscount_features,
        **pattern_features,
    }

    print(f"[analyzer] Features: {all_features}")

    # Save to decoy log
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

    # Write done flag
    flag_path = os.path.join(REPO_DIR, FLAG_DIR, f"ebpf_done_{pkg_name}.flag")
    with open(flag_path, "w") as f:
        f.write(run_number)

    # Push results to GitHub
    print("[analyzer] Pushing results to GitHub...")
    os.chdir(REPO_DIR)
    subprocess.run(["git", "pull", "--rebase", "origin", "main"])
    subprocess.run(["git", "add", "decoy_logs/"])
    subprocess.run(["git", "commit", "-m", f"eBPF analysis results: {pkg_name}"])
    subprocess.run(["git", "push", "origin", "main"])

    print(f"[analyzer] Done ✅ {pkg_name}")


# ── Main Watch Loop ──────────────────────────────────────────

def main():
    print("[watcher] AWS EC2 eBPF Analyzer started")
    os.chdir(REPO_DIR)

    while True:
        # Pull latest from GitHub
        subprocess.run(["git", "config", "pull.rebase", "true"], capture_output=True)
        subprocess.run(["git", "pull", "origin", "main"], capture_output=True)

        # Check for pending package
        pending = os.path.join(REPO_DIR, WATCH_FILE)
        if os.path.exists(pending):
            with open(pending) as f:
                content = f.read().strip()

            # New format: "pkgname.tgz:RUN_NUMBER"
            if ":" in content:
                pkg_name, run_number = content.split(":", 1)
            else:
                pkg_name, run_number = content, "0"

            if pkg_name:
                print(f"[watcher] New package detected: {pkg_name} (run={run_number})")

                # Remove pending file and commit
                os.remove(pending)
                subprocess.run(["git", "add", WATCH_FILE])
                subprocess.run(["git", "commit", "-m", f"Start eBPF analysis: {pkg_name}"])
                subprocess.run(["git", "push", "origin", "main"])

                # Run analysis
                analyze_package(pkg_name, run_number)

        time.sleep(30)  # check every 30 seconds


if __name__ == "__main__":
    main()
