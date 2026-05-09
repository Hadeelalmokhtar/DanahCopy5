"""
merge_falco.py — Merges Falco alert output into the existing decoy log.
Usage: python3 scripts/merge_falco.py <falco_events.json> <decoy_log.json>

Extracts 4 boolean features from Falco alerts and stores them
directly in dynamic_features of the decoy log.
"""

import json
import sys
import os
import re


# Replace this entire function:
def parse_falco_alerts(falco_path: str) -> list:
    """Read Falco output — handles JSON array, NDJSON, and journalctl -o json formats."""
    alerts = []
    try:
        with open(falco_path) as f:
            raw = f.read().strip()

        if raw.startswith("["):
            # Native Falco file_output — JSON array
            data = json.loads(raw)
            alerts = data if isinstance(data, list) else data.get("alerts", [])

        else:
            # NDJSON — one JSON object per line
            # Covers both native Falco NDJSON and journalctl -o json
            for line in raw.split("\n"):
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                # Native Falco NDJSON — has top-level "rule" and "output"
                if "rule" in obj:
                    alerts.append(obj)

                # journalctl -o json — alert text is inside "MESSAGE" field
                elif "MESSAGE" in obj:
                    msg = obj["MESSAGE"]
                    if not msg:
                        continue

                    # MESSAGE contains another JSON string — unwrap it to get rule and output
                    try:
                        inner = json.loads(msg)
                        
                        alerts.append({
                            "rule":   inner.get("rule", ""),
                            "output": inner.get("output", msg),
                        })
                        continue
                        
                    except Exception:
                        pass

                    # Fallback — treat raw MESSAGE as output
                    if not any(kw in msg for kw in ["rule=", "Notice", "Warning", "Error"]):
                        continue
                    rule_match = re.search(r'rule=([^\s,]+)', msg)

                    alerts.append({
                        "rule":   rule_match.group(1) if rule_match else "",
                        "output": msg,
                    })

    except Exception as e:
        print(f"[merge_falco] Could not parse {falco_path}: {e}")

    return alerts

def extract_falco_features(alerts: list) -> dict:
    """Extract 4 boolean features from Falco alert list."""
    features = {
        "falco_privilege_escalation":    "False",
        "falco_write_binary_dir":        "False",
        "falco_ptrace_detected":         "False",
        "falco_package_install_runtime": "False",
    }

    for alert in alerts:
        rule   = str(alert.get("rule",   "")).lower()
        output = str(alert.get("output", "")).lower()
        combined = rule + " " + output

        if any(kw in combined for kw in [
            "privilege", "setuid", "chmod 777", "escalat", "sudo", "cap_sys"
        ]):
            features["falco_privilege_escalation"] = "True"

        if any(kw in combined for kw in [
            "write_binary", "binary dir", "/bin/", "/usr/bin/", "/sbin/",
            "write below binary"
        ]):
            features["falco_write_binary_dir"] = "True"

        if any(kw in combined for kw in [
            "ptrace", "proc/mem", "process inject", "memory scraping"
        ]):
            features["falco_ptrace_detected"] = "True"

        if any(kw in combined for kw in [
            "package install", "pip install", "npm install",
            "apt-get", "yum install", "apk add", "package manager"
        ]):
            features["falco_package_install_runtime"] = "True"

    return features


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/merge_falco.py <falco_events.json> <decoy_log.json>")
        sys.exit(1)

    falco_path = sys.argv[1]
    decoy_path = sys.argv[2]

    # Parse Falco alerts
    alerts = parse_falco_alerts(falco_path)
    print(f"[merge_falco] Parsed {len(alerts)} Falco alerts")

    # Extract features
    features = extract_falco_features(alerts)
    print(f"[merge_falco] Features: {features}")

    # Load decoy log
    try:
        with open(decoy_path) as f:
            log = json.load(f)
    except Exception as e:
        print(f"[merge_falco] Could not read decoy log: {e}")
        sys.exit(1)

    # Merge Falco data into decoy log
    log["falco_alerts"]      = alerts
    log["falco_alert_count"] = len(alerts)

    # Update dynamic_features
    if "dynamic_features" not in log:
        log["dynamic_features"] = {}

    log["dynamic_features"].update(features)

    # Save back
    with open(decoy_path, "w") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    print(f"[merge_falco] Merged into {os.path.basename(decoy_path)}")
    print(f"  falco_privilege_escalation:    {features['falco_privilege_escalation']}")
    print(f"  falco_write_binary_dir:        {features['falco_write_binary_dir']}")
    print(f"  falco_ptrace_detected:         {features['falco_ptrace_detected']}")
    print(f"  falco_package_install_runtime: {features['falco_package_install_runtime']}")


if __name__ == "__main__":
    main()
