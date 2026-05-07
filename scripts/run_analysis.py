import sys
import os
import json
import joblib
import time
import tarfile
import tempfile
import re
import subprocess
from datetime import datetime

try:
    import yara
except Exception:
    yara = None

# ======================================
# IMPORT SAP EXTRACTORS
# ======================================
from scripts.sap_feature_engine.pypi_feature_extractor import PyPI_Feature_Extractor
from scripts.sap_feature_engine.npm_feature_extractor import NPM_Feature_Extractor
from scripts.package_adapter import PackageAdapter

# ======================================
# PATHS
# ======================================
model_path     = "ml/malicious_model.pkl"
preprocess_path = "ml/preprocess.pkl"

# ======================================
# INPUT
# ======================================
if len(sys.argv) < 2:
    print("Usage: python -m scripts.run_analysis <file_or_folder>")
    sys.exit(1)

original_input = sys.argv[1]

# ======================================
# HANDLE COMPRESSED PACKAGES
# ======================================
def extract_package_if_needed(path):
    if path.endswith(".tgz") or path.endswith(".tar.gz"):
        temp_dir = tempfile.mkdtemp()
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(temp_dir)
        return temp_dir
    return path

file_path = extract_package_if_needed(original_input)

# ======================================
# BUILD PACKAGE STRUCTURE
# ======================================
adapter = PackageAdapter()

if os.path.isfile(file_path):
    package_root = adapter.build_from_single_file(file_path)
else:
    package_root = file_path

# ======================================
# SELECT CORRECT EXTRACTOR
# ======================================
def contains_package_json(path):
    for root, _, files in os.walk(path):
        if "package.json" in files:
            return True
    return False

if contains_package_json(file_path):
    extractor = NPM_Feature_Extractor()
    repo_name = "NPM"
else:
    extractor = PyPI_Feature_Extractor()
    repo_name = "PyPI"

# ======================================
# FEATURE EXTRACTION
# ======================================
try:
    features = extractor.extract_features(package_root)
    features["Package Repository"] = repo_name
except Exception as e:
    print(f"Feature extraction failed: {e}")
    print("Flagging package as malicious due to extraction failure.")

    os.makedirs("decoy_logs", exist_ok=True)
    os.makedirs("decoy_logs/ml_logs", exist_ok=True)

    run_id   = str(int(time.time()))
    pkg_name = os.path.basename(original_input).replace(".tar.gz", "").replace(".tgz", "").replace(".tar", "")
    log_name = f"{pkg_name}_{run_id}"

    error_log = {
        "run_id":           run_id,
        "package":          str(original_input),
        "risk_probability": 1.0,
        "prediction":       1,
        "timestamp":        str(datetime.utcnow().isoformat()),
        "top_shap":         [],
        "features":         {},
        "error":            str(e)
    }

    with open(f"decoy_logs/ml_logs/{log_name}.json", "w") as f:
        json.dump(error_log, f, indent=4)

    # Update latest.json for dashboard display
    with open("decoy_logs/latest.json", "w") as f:
        json.dump(error_log, f, indent=4)

    print(f"Saved error log: decoy_logs/ml_logs/{log_name}.json")
    sys.exit(1)

# ======================================
# YARA STATIC ANALYSIS
# ======================================

YARA_RULES = r"""
rule Credential_Theft_Indicators {
    meta:
        description = "Detects credential access patterns"
        severity = "high"
    strings:
        $passwd  = "/etc/passwd"
        $shadow  = "/etc/shadow"
        $ssh1    = ".ssh/id_rsa"
        $ssh2    = "authorized_keys"
        $aws1    = ".aws/credentials"
        $env     = ".env"
        $token   = "Authorization: Bearer"
        $privkey = "BEGIN PRIVATE KEY"
    condition:
        any of them
}

rule Exfiltration_Indicators {
    meta:
        description = "Detects data exfiltration patterns"
        severity = "high"
    strings:
        $collect       = "/collect"
        $exfil         = "/exfil"
        $requests_post = "requests.post("
        $axios_post    = "axios.post("
        $fetch_post    = "method: \"POST\""
        $c2_connect    = "socket.connect("
    condition:
        any of them
}

rule Shell_Execution_Indicators {
    meta:
        description = "Detects shell execution"
        severity = "critical"
    strings:
        $bash   = "/bin/bash"
        $sh     = "/bin/sh"
        $execve = "execve("
        $popen  = "popen("
        $system = "os.system("
        $child  = "child_process.exec("
        $spawn  = "spawnSync("
    condition:
        any of them
}

rule Command_Execution_Indicators {
    meta:
        description = "Detects dynamic code execution"
        severity = "high"
    strings:
        $py_exec     = "exec("
        $py_eval     = "eval("
        $py_compile  = "compile("
        $import_dyn  = "__import__("
        $js_execfile = "execFile("
        $js_execsync = "execSync("
        $js_eval     = "global.eval("
    condition:
        any of them
}

rule Obfuscation_Indicators {
    meta:
        description = "Detects obfuscation"
        severity = "medium"
    strings:
        $b64decode = "base64.b64decode("
        $atob      = "atob("
        $fromchar  = "String.fromCharCode("
        $unescape  = "unescape("
        $b64_exec  = "exec(base64"
    condition:
        any of them
}

rule Persistence_Indicators {
    meta:
        description = "Detects persistence mechanisms"
        severity = "medium"
    strings:
        $cron      = "crontab"
        $bashrc    = ".bashrc"
        $profile   = ".profile"
        $systemctl = "systemctl enable"
        $initd     = "/etc/init.d"
    condition:
        any of them
}

rule Install_Hook_Indicators {
    meta:
        description = "Detects install hooks"
        severity = "critical"
    strings:
        $preinstall   = "\"preinstall\""
        $postinstall  = "\"postinstall\""
        $prepare_hook = "\"prepare\""
        $cmdclass     = "cmdclass"
        $post_install = "post_install"
    condition:
        any of them
}

rule Suspicious_Imports_Indicators {
    meta:
        description = "Detects suspicious imports"
        severity = "medium"
    strings:
        $socket_py     = "import socket"
        $subprocess_py = "import subprocess"
        $ctypes        = "import ctypes"
        $pty           = "import pty"
        $require_net   = "require('net')"
        $require_child = "require('child_process')"
    condition:
        any of them
}
"""

_yara_compiled = None

def get_yara_rules():
    global _yara_compiled
    if yara is None:
        return None
    if _yara_compiled is None:
        try:
            _yara_compiled = yara.compile(source=YARA_RULES)
        except Exception as e:
            print(f"[yara] Rule compile failed: {e}")
    return _yara_compiled


def run_yara_on_package(package_dir):
    """
    Runs YARA on all .py and .js files in package_dir.
    Returns dict with per-rule boolean results.
    """
    result = {
        "yara_credential_theft_indicators":  "False",
        "yara_exfiltration_indicators":      "False",
        "yara_shell_execution_indicators":   "False",
        "yara_command_execution_indicators": "False",
        "yara_obfuscation_indicators":       "False",
        "yara_persistence_indicators":       "False",
        "yara_install_hook_indicators":      "False",
        "yara_suspicious_imports_indicators":"False",
    }

    rules = get_yara_rules()
    if not rules:
        print("[yara] Not available — skipping")
        return result

    rule_to_key = {
        "Credential_Theft_Indicators":  "yara_credential_theft_indicators",
        "Exfiltration_Indicators":      "yara_exfiltration_indicators",
        "Shell_Execution_Indicators":   "yara_shell_execution_indicators",
        "Command_Execution_Indicators": "yara_command_execution_indicators",
        "Obfuscation_Indicators":       "yara_obfuscation_indicators",
        "Persistence_Indicators":       "yara_persistence_indicators",
        "Install_Hook_Indicators":      "yara_install_hook_indicators",
        "Suspicious_Imports_Indicators":"yara_suspicious_imports_indicators",
    }

    for root, _, files in os.walk(package_dir):
        for fname in files:
            if not (fname.endswith(".py") or fname.endswith(".js")):
                continue
            fpath = os.path.join(root, fname)
            try:
                matches = rules.match(fpath)
                for m in matches:
                    key = rule_to_key.get(m.rule)
                    if key:
                        result[key] = "True"
            except Exception:
                continue

    matched = [k for k, v in result.items() if v == "True"]
    print(f"[yara] Matched rules: {matched if matched else 'none'}")
    return result


# ======================================
# SEMGREP STATIC ANALYSIS
# ======================================

def run_semgrep_on_package(package_dir):
    """
    Runs semgrep on the package directory.
    Returns 4 boolean features.
    """
    result = {
        "semgrep_has_exec_call":       "False",
        "semgrep_has_subprocess":      "False",
        "semgrep_has_network_request": "False",
        "semgrep_has_secret_access":   "False",
    }

    check = subprocess.run(
        ["semgrep", "--version"],
        capture_output=True, text=True
    )
    if check.returncode != 0:
        print("[semgrep] Not available — skipping")
        return result

    try:
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", "auto",
             "--timeout", "30", package_dir],
            capture_output=True, text=True, timeout=120
        )
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return result

        for finding in data.get("results", []):
            rule_id = finding.get("check_id", "").lower()
            message = finding.get("extra", {}).get("message", "").lower()
            combined = rule_id + " " + message

            if any(kw in combined for kw in ["exec","eval","compile","dangerous-eval","code-execution"]):
                result["semgrep_has_exec_call"] = "True"
            if any(kw in combined for kw in ["subprocess","os.system","os.popen","child_process","shell","spawn","popen"]):
                result["semgrep_has_subprocess"] = "True"
            if any(kw in combined for kw in ["socket","requests","urllib","fetch","axios","http","network","outbound","dns","connect"]):
                result["semgrep_has_network_request"] = "True"
            if any(kw in combined for kw in ["secret","credential","password","token","api-key","private-key","environ","hardcoded","sensitive"]):
                result["semgrep_has_secret_access"] = "True"

    except subprocess.TimeoutExpired:
        print("[semgrep] Timeout")
    except Exception as e:
        print(f"[semgrep] Error: {e}")

    print(f"[semgrep] Results: {result}")
    return result


# ======================================
# LOAD MODEL
# ======================================
preprocess = joblib.load(preprocess_path)
model      = joblib.load(model_path)

# Pass original features to model — do NOT reorder before this
X = preprocess.transform(features)

pred  = int(model.predict(X)[0])
proba = float(model.predict_proba(X)[0][1]) if hasattr(model, "predict_proba") else 0.0

print("Prediction:", pred)
print("Malicious Probability:", proba)

# ======================================
# DEBUG: PRINT FEATURES
# ======================================
print("\n=== FEATURES ===")
try:
    print(features.to_dict())
except Exception:
    print(features)

# ======================================
# DEBUG: SHAP EXPLANATION
# ======================================
top_shap = []

try:
    import shap

    explainer    = shap.Explainer(model)
    shap_values  = explainer(X)
    feature_names = preprocess.get_feature_names_out()
    shap_dict    = dict(zip(feature_names, shap_values.values[0]))
    top_shap     = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:10]

    print("\n=== TOP SHAP FEATURES ===")
    for k, v in top_shap:
        print(f"{k}: {v}")

except Exception as e:
    print("SHAP error:", e)

# ======================================
# SERIALIZE FEATURES SAFELY
# Reorder only for saving to log — AFTER prediction, model not affected
# ======================================
DATASET_COLUMN_ORDER = [
    "Package Repository", "Package Name",
    "Number of Words in source code", "Number of lines in source code",
    "plus ratio mean", "plus ratio max", "plus ratio std", "plus ratio q3",
    "eq ratio mean", "eq ratio max", "eq ratio std", "eq ratio q3",
    "bracket ratio mean", "bracket ratio max", "bracket ratio std", "bracket ratio q3",
    "Number of base64 chunks in source code", "Number of IP adress in source code",
    "Number of sospicious token in source code",
    "Number of Words in metadata", "Number of lines in metadata",
    "Number of base64 chunks in metadata", "Number of IP adress in metadata",
    "Number of sospicious token in metadata",
    ".bat", ".bz2", ".c", ".cert", ".conf", ".cpp", ".crt", ".css", ".csv",
    ".deb", ".erb", ".gemspec", ".gif", ".gz", ".h", ".html", ".ico", ".ini",
    ".jar", ".java", ".jpg", ".js", ".json", ".key", ".m4v", ".markdown", ".md",
    ".pdf", ".pem", ".png", ".ps", ".py", ".rb", ".rpm", ".rst", ".sh", ".svg",
    ".toml", ".ttf", ".txt", ".xml", ".yaml", ".yml", ".eot", ".exe", ".jpeg",
    ".properties", ".sql", ".swf", ".tar", ".woff", ".woff2", ".aac", ".bmp",
    ".cfg", ".dcm", ".dll", ".doc", ".flac", ".flv", ".ipynb", ".m4a", ".mid",
    ".mkv", ".mp3", ".mp4", ".mpg", ".ogg", ".otf", ".pickle", ".pkl", ".psd",
    ".pxd", ".pxi", ".pyc", ".pyx", ".r", ".rtf", ".so", ".sqlite", ".tif",
    ".tp", ".wav", ".webp", ".whl", ".xcf", ".xz", ".zip", ".mov", ".wasm", ".webm",
    "presence of installation script",
    "shannon mean ID source code", "shannon std ID source code",
    "shannon max ID source code", "shannon q3 ID source code",
    "shannon mean string source code", "shannon std string source code",
    "shannon max string source code", "shannon q3 string source code",
    "homogeneous identifiers in source code", "homogeneous strings in source code",
    "heteregeneous identifiers in source code", "heterogeneous strings in source code",
    "URLs in source code",
    "shannon mean ID metadata", "shannon std ID metadata",
    "shannon max ID metadata", "shannon q3 ID metadata",
    "shannon mean string metadata", "shannon std string metadata",
    "shannon max string metadata", "shannon q3 string metadata",
    "homogeneous identifiers in metadata", "homogeneous strings in metadata",
    "heterogeneous strings in metadata", "URLs in metadata",
    "heteregeneous identifiers in metadata",
]

try:
    raw = features.to_dict()
    raw.pop("repository", None)
    features_dict = {col: raw[col] for col in DATASET_COLUMN_ORDER if col in raw}
except Exception:
    features_dict = {}

# ======================================
# SAVE LOG
# ======================================
os.makedirs("decoy_logs", exist_ok=True)
os.makedirs("decoy_logs/ml_logs", exist_ok=True)

run_id   = str(int(time.time()))
pkg_name = os.path.basename(original_input).replace(".tar.gz", "").replace(".tgz", "").replace(".tar", "")
log_name = f"{pkg_name}_{run_id}"

ml_log = {
    "run_id":           str(run_id),
    "package":          str(original_input),
    "risk_probability": float(proba),
    "prediction":       int(pred),
    "timestamp":        str(datetime.utcnow().isoformat()),
    "top_shap":         [(str(k), float(v)) for k, v in top_shap],
    "features":         features_dict
}

with open(f"decoy_logs/ml_logs/{log_name}.json", "w") as f:
    json.dump(ml_log, f, indent=4)

# Update latest.json for dashboard display
with open("decoy_logs/latest.json", "w") as f:
    json.dump(ml_log, f, indent=4)


print(f"Saved ML log: decoy_logs/ml_logs/{log_name}.json")

# ======================================
# YARA + SEMGREP STATIC ANALYSIS
# ======================================
print("\n=== RUNNING YARA + SEMGREP STATIC ANALYSIS ===")
yara_results   = run_yara_on_package(file_path)
semgrep_results = run_semgrep_on_package(file_path)

# Append static analysis results to ML log
static_analysis_results = {**yara_results, **semgrep_results}

with open(f"decoy_logs/ml_logs/{log_name}.json") as f:
    ml_log_data = json.load(f)
ml_log_data["static_analysis"] = static_analysis_results
with open(f"decoy_logs/ml_logs/{log_name}.json", "w") as f:
    json.dump(ml_log_data, f, indent=4)

print(f"Static analysis saved to ML log: {static_analysis_results}")

# exit code: 1 = malicious → triggers decoy, 0 = benign → releases
sys.exit(1 if pred == 1 else 0)
