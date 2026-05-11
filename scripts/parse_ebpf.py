"""
parse_ebpf.py — Parses eBPF tool output and merges into decoy log.
Usage: python3 scripts/parse_ebpf.py <opensnoop.json> <tcpconnect.json> 
                                      <syscount.json> <decoy_log.json> [container_pid]
Based on DySec paper (Mehedi et al., 2025)
"""

import json, sys, os, re

# ── OpensnoopTraces — directory access ──
def parse_opensnoop(path: str, pid_filter: str = None) -> dict:
    counts = {
        "root_dir_access": 0, "etc_dir_access":  0,
        "tmp_dir_access":  0, "home_dir_access": 0,
        "ssh_dir_access":  0, "other_dir_access": 0,
    }
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Filter by container PID if provided
                    if pid_filter and str(obj.get("PID", obj.get("pid", ""))) != str(pid_filter):
                        continue
                    fname = obj.get("filename", obj.get("FILE", ""))
                except:
                    fname = line

                if "/root/"  in fname: counts["root_dir_access"]  += 1
                elif "/etc/" in fname: counts["etc_dir_access"]   += 1
                elif "/tmp/" in fname: counts["tmp_dir_access"]   += 1
                elif "/home/"in fname: counts["home_dir_access"]  += 1
                elif "/.ssh/"in fname: counts["ssh_dir_access"]   += 1
                else:                  counts["other_dir_access"] += 1
    except Exception as e:
        print(f"[parse_ebpf] opensnoop parse error: {e}")

    return {
        **counts,
        "ebpf_accessed_root": counts["root_dir_access"] > 0,
        "ebpf_accessed_ssh":  counts["ssh_dir_access"]  > 0,
        "ebpf_accessed_etc":  counts["etc_dir_access"]  > 5,
    }

# ── TCPTraces — network connections ──
def parse_tcpconnect(path: str, pid_filter: str = None) -> dict:
    suspicious_ports = {6667, 4444, 1337, 8080, 9001}
    remote_ips   = set()
    remote_ports = set()
    c2_suspected = False

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj  = json.loads(line)
                    # Filter by container PID if provided
                    if pid_filter and str(obj.get("PID", obj.get("pid", ""))) != str(pid_filter):
                        continue
                    ip   = obj.get("daddr", obj.get("RADDR", ""))
                    port = int(obj.get("dport", obj.get("RPORT", 0)))
                except:
                    # Plain text format: PID COMM LADDR RADDR RPORT
                    parts = line.split()
                    # Filter by PID in plain text format
                    if pid_filter and parts and parts[0] != str(pid_filter):
                        continue
                    ip    = parts[3] if len(parts) > 3 else ""
                    try:
                        port = int(parts[4]) if len(parts) > 4 else 0
                    except:
                        port = 0

                if ip:
                    remote_ips.add(ip)
                if port:
                    remote_ports.add(port)
                if port in suspicious_ports:
                    c2_suspected = True
    except Exception as e:
        print(f"[parse_ebpf] tcpconnect parse error: {e}")

    return {
        "ebpf_remote_ips_count":  len(remote_ips),
        "ebpf_remote_ports":      "|".join(str(p) for p in remote_ports),
        "ebpf_c2_port_suspected": c2_suspected,
        "ebpf_remote_ips":        "|".join(remote_ips),
    }

# ── SystemCallTraces — syscall categorization ──
def parse_syscount(path: str, pid_filter: str = None) -> dict:
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
                if not line:
                    continue
                try:
                    obj  = json.loads(line)
                    # Filter by container PID if provided
                    if pid_filter and str(obj.get("PID", obj.get("pid", ""))) != str(pid_filter):
                        continue
                    name = obj.get("syscall", "").lower()
                    cnt  = int(obj.get("count", 1))
                except:
                    parts = line.split()
                    # Filter by PID in plain text format
                    if pid_filter and parts and parts[0] != str(pid_filter):
                        continue
                    name  = parts[0].lower() if parts else ""
                    try:
                        cnt = int(parts[1]) if len(parts) > 1 else 1
                    except:
                        cnt = 1

                if name in security_calls: counts["ebpf_security_ops"] += cnt
                if name in network_calls:  counts["ebpf_network_ops"]  += cnt
                if name in process_calls:  counts["ebpf_process_ops"]  += cnt
                if name in file_calls:     counts["ebpf_file_ops"]     += cnt
    except Exception as e:
        print(f"[parse_ebpf] syscount parse error: {e}")

    return {
        **counts,
        "ebpf_privilege_escalation": counts["ebpf_security_ops"] > 0,
        "ebpf_network_activity":     counts["ebpf_network_ops"]  > 0,
        "ebpf_spawned_process":      counts["ebpf_process_ops"]  > 2,
    }

# ── PatternTraces — DySec syscall sequences ──
def extract_patterns(opensnoop_path: str, syscount_path: str, pid_filter: str = None) -> dict:
    """
    Detect DySec-style behavioral patterns.
    Based on Table VI from DySec paper.
    """
    syscall_sequence = []
    try:
        with open(opensnoop_path) as f:
            for line in f:
                try:
                    obj = json.loads(line.strip())
                    # Filter by PID
                    if pid_filter and str(obj.get("PID", obj.get("pid", ""))) != str(pid_filter):
                        continue
                    sc = obj.get("syscall", "")
                    if sc:
                        syscall_sequence.append(sc.lower())
                except:
                    pass
    except:
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

# ── MAIN ──
def main():
    if len(sys.argv) < 5:
        print("Usage: parse_ebpf.py <opensnoop> <tcpconnect> <syscount> <decoy_log> [container_pid]")
        sys.exit(1)

    opensnoop_path  = sys.argv[1]
    tcpconnect_path = sys.argv[2]
    syscount_path   = sys.argv[3]
    decoy_path      = sys.argv[4]
    pid_filter      = sys.argv[5] if len(sys.argv) > 5 else None

    if pid_filter:
        print(f"[parse_ebpf] Filtering by container PID: {pid_filter}")
    else:
        print(f"[parse_ebpf] No PID filter — using all events")

    # Parse all eBPF outputs
    opensnoop_features  = parse_opensnoop(opensnoop_path, pid_filter)
    tcpconnect_features = parse_tcpconnect(tcpconnect_path, pid_filter)
    syscount_features   = parse_syscount(syscount_path, pid_filter)
    pattern_features    = extract_patterns(opensnoop_path, syscount_path, pid_filter)

    # Combine all features
    all_features = {
        **opensnoop_features,
        **tcpconnect_features,
        **syscount_features,
        **pattern_features,
    }

    print(f"[parse_ebpf] Features extracted: {all_features}")

    # Load decoy log
    try:
        with open(decoy_path) as f:
            log = json.load(f)
    except Exception as e:
        print(f"[parse_ebpf] Could not read decoy log: {e}")
        sys.exit(1)

    # Merge into dynamic_features
    if "dynamic_features" not in log:
        log["dynamic_features"] = {}
    log["dynamic_features"].update({
        k: str(v) for k, v in all_features.items()
    })
    log["ebpf_features"] = all_features

    # Save back
    with open(decoy_path, "w") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    print(f"[parse_ebpf] Merged into {os.path.basename(decoy_path)}")

if __name__ == "__main__":
    main()
