import os 
import re
import csv
import sqlite3
import json
import subprocess
import tempfile
from urllib.parse import urlparse
from pathlib import Path
import yaml
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from openai import OpenAI
import time
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Tuple


GITHUB_TOKEN = ""  # Replace with the actual Github token
PROXIES = None
RETRY_MAX = 3
RETRY_BACKOFF = 1
CPG_CACHE_DIR = "./joern/cpg_cache"
DATASET_OUTPUT_PATH = "./datasets/IoTRAGuard.json"
CODEGUARDER_OUTPUT_PATH = "./datasets/CodeGuarder.json"
SIGNATURE_SCRIPT_PATH = "./joern_query/extract_function_signatures.scala"
CALLCHAIN_SCRIPT_PATH = "./joern_query/build_reverse_callchain.scala"
LOG_DIR="./data/logs"
FUNCTION_CHANGE_LOG = os.path.join(LOG_DIR, "function_changes.log")
LLM_RAW_LOG_DIR = os.path.join(LOG_DIR, "llm_raw_outputs")


DEBUG = True
INFO = True
WARN = True
ERROR = True

csv.field_size_limit(10 * 1024 * 1024)

CONFIG = "./config/extractor.yaml"
PROJECTS_CONFIG = "./config/projects.yaml"
CSV_FILE = "./data/cve-records-zephyr.csv"
CRASH_LOG_FILE = os.path.join(LOG_DIR, "crash.log")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(LLM_RAW_LOG_DIR, exist_ok=True)
os.makedirs(CPG_CACHE_DIR, exist_ok=True)

with open(CRASH_LOG_FILE, "w") as f:
    f.write("")
with open(FUNCTION_CHANGE_LOG, "w") as f:
    f.write("")

client = OpenAI(
    base_url='',
    api_key=''  # Replace with the actual API key
)

def generate_codeguarder_analysis(cve_desc: str, cwe_id: str, diff_text: str, cve_id: str) -> Dict:
    """
    Call LLM to generate security knowledge analysis results required by CodeGuarder
    :param cve_desc: CVE vulnerability description
    :param cwe_id: CWE vulnerability type ID
    :param diff_text: Complete PR diff content
    :param cve_id: CVE ID (for logging and caching)
    :return: Analysis result dictionary matching the specified format
    """
    if not all([cve_desc.strip(), cwe_id.strip(), diff_text.strip()]):
        log_warn(f"{cve_id} Missing necessary input (Description/CWE/Diff), skipping analysis")
        return {"error": "Missing required input data", "cve_id": cve_id}

    prompt = f"""Task: Analyze a vulnerability fixing commit to extract security knowledge.
Input:
• Vulnerability Description: {cve_desc}
• Vulnerability Type: {cwe_id}
• Fixing Commit (Diff): {diff_text}

Instructions:
(1) Describe the functionality of the vulnerable code snippet.
(2) Identify and extract the root cause of the vulnerability.
(3) Identify and extract the corresponding fixing pattern.

Output Format: Provide the output in JSON format, adhering to the following structure:
{{
  "Functionality": "<Description of the vulnerable code’s functionality>",
  "Root_Cause": [
    "<Detailed description of the vulnerability’s root cause>",
    "<Code example illustrating the vulnerability>"
  ],
  "Fixing_Pattern": [
    "<Detailed description of the fixing pattern>",
    "<Code example illustrating the vulnerability repair>"
  ]
}}"""

    try:
        log_info(f"Calling LLM to analyze {cve_id} to generate CodeGuarder data...")
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            timeout=60
        )
        
        save_llm_raw_output(
            cve_id=cve_id,
            llm_type="codeguarder_analysis",
            prompt=prompt,
            response=resp.choices[0].message.content.strip()
        )

        
        llm_output = resp.choices[0].message.content.strip()
        
        json_match = re.search(r"\{[\s\S]*\}", llm_output)
        if not json_match:
            raise ValueError("No valid JSON found in LLM output")
        clean_output = json_match.group(0)
        analysis_result = json.loads(clean_output)
        
        
        analysis_result["cve_id"] = cve_id
        analysis_result["cwe_id"] = cwe_id
        
        log_info(f"{cve_id} CodeGuarder analysis completed")
        return analysis_result

    except json.JSONDecodeError as e:
        log_error(f"{cve_id} LLM output JSON parse failed: {e}")
        return {"error": "JSON parse failed", "cve_id": cve_id, "raw_output": llm_output if 'llm_output' in locals() else ""}
    except Exception as e:
        log_error(f"{cve_id} CodeGuarder analysis failed: {e}")
        return {"error": str(e), "cve_id": cve_id}

def save_codeguarder_dataset(codeguarder_data: List[Dict]) -> None:
    """
    Save CodeGuarder dataset to the specified path
    :param codeguarder_data: List of analysis results for all CVEs
    """
    try:
        
        output_dir = os.path.dirname(CODEGUARDER_OUTPUT_PATH)
        os.makedirs(output_dir, exist_ok=True)
        
        
        with open(CODEGUARDER_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(codeguarder_data, f, indent=2, ensure_ascii=False)
        
        log_info(f"CodeGuarder dataset saved to: {CODEGUARDER_OUTPUT_PATH}")
        log_info(f"Dataset contains {len(codeguarder_data)} records in total")
    except Exception as e:
        log_error(f"Failed to save CodeGuarder dataset: {e}")
        raise

def deduplicate_list(data: List) -> List:
    return list(set(data))

def clean_repo(local_dir: str) -> None:
    run_cmd(["git", "reset", "--hard"], cwd=local_dir)
    run_cmd(["git", "clean", "-fd"], cwd=local_dir)

def parse_github_url(url: str) -> Tuple[Optional[str], Optional[str], Optional[Tuple[str, str]]]:
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    parts = urlparse(url)
    if 'github.com' not in parts.netloc:
        return None, None, None
    segs = parts.path.strip("/").split("/")
    if len(segs) < 2:
        return None, None, None
    owner, repo = segs[0], segs[1]
    repo_url = f"git@github.com:{owner}/{repo}.git"
    commit_identifier = None

    if "pull" in segs:
        idx = segs.index("pull")
        if len(segs) > idx + 1:
            commit_identifier = f"PR-{segs[idx+1]}"
    elif "commit" in segs:
        idx = segs.index("commit")
        if len(segs) > idx + 1:
            commit_identifier = segs[idx+1]
    elif "security/advisories" in parts.path:
        idx = segs.index("advisories") if "advisories" in segs else -1
        if idx != -1 and len(segs) > idx + 1:
            commit_identifier = segs[idx + 1]
    return repo_url, commit_identifier, (owner, repo)

def parse_nodes_data(nodes_str: str) -> Tuple[Optional[str], str, str]:
    try:
        nodes_str = nodes_str.strip().strip('"').replace('""', '"')
        nodes = json.loads(nodes_str)
    except Exception as e:
        log_warn(f"Failed to parse Nodes data: {e}")
        return None, "Unknown", "Unknown"

    cpe_list = []
    versions = set()

    def traverse(data):
        if isinstance(data, list):
            for item in data:
                traverse(item)
        elif isinstance(data, dict):
            traverse(data.get("nodes", []))
            for match in data.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpe = match.get("criteria", "").strip()
                    if cpe.startswith("cpe:2.3:"):
                        cpe_list.append(cpe)
                    start = match.get("versionStartIncluding", "")
                    end_excl = match.get("versionEndExcluding", "")
                    end_incl = match.get("versionEndIncluding", "")
                    if start and end_excl:
                        versions.add(f"{start} ~ {end_excl} (excl)")
                    elif start and end_incl:
                        versions.add(f"{start} ~ {end_incl} (incl)")
                    elif start:
                        versions.add(f">= {start}")
                    elif end_incl:
                        versions.add(f"<= {end_incl}")
                    else:
                        cpe_parts = cpe.split(":")
                        if len(cpe_parts) > 5:
                            versions.add(cpe_parts[5])

    traverse(nodes)
    cpe_info = ",".join(sorted(set(cpe_list))) if cpe_list else None
    repo_version = ",".join(sorted(versions)) if versions else "Unknown"
    return cpe_info, repo_version

def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_debug(message: str) -> None:
    if DEBUG:
        print(f"[{get_timestamp()}] [DEBUG] {message}")

def log_info(message: str) -> None:
    if INFO:
        print(f"[{get_timestamp()}] [INFO] {message}")

def log_warn(message: str) -> None:
    if WARN:
        print(f"[{get_timestamp()}] [WARN] {message}")

def log_error(message: str) -> None:
    if ERROR:
        print(f"[{get_timestamp()}] [ERROR] {message}")

def log_function_change(message: str) -> None:
    with open(FUNCTION_CHANGE_LOG, "a") as f:
        f.write(f"[{get_timestamp()}] {message}\n")

def save_llm_raw_output(cve_id: str, llm_type: str, prompt: str, response: str) -> None:
    cve_dir = os.path.join(LLM_RAW_LOG_DIR, cve_id)
    os.makedirs(cve_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = os.path.join(cve_dir, f"{llm_type}_{timestamp}.json")
    data = {
        "timestamp": datetime.now().isoformat(),
        "cve_id": cve_id,
        "llm_type": llm_type,
        "prompt": prompt,
        "raw_response": response
    }
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log_debug(f"LLM raw output saved to: {file_path}")

def create_session_with_retries() -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=RETRY_MAX,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

req_session = create_session_with_retries()
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

def get_fixed_tag(local_dir: str, merge_commit_sha: str) -> str:
    log_debug(f"Searching for the earliest official tag containing fix commit {merge_commit_sha[:8]}")
    try:
        tags = run_cmd(
            ["git", "tag", "--contains", merge_commit_sha, "--sort=v:refname"],
            cwd=local_dir
        ).splitlines()
        
        for tag in tags:
            if tag.startswith("v") and re.match(r'^v\d+\.\d+\.\d+$', tag):
                log_info(f"Found earliest official version containing fix: {tag}")
                return tag
        
        raise Exception("No official version tag found containing the fix commit")
    except Exception as e:
        log_error(f"Failed to get fixed version tag: {e}")
        raise

def get_vulnerable_tag(local_dir: str, fixed_tag: str) -> str:
    log_debug(f"Searching for pre-fix version based on fixed version {fixed_tag}")
    try:
        all_tags = run_cmd(
            ["git", "tag", "--sort=v:refname"],
            cwd=local_dir
        ).splitlines()
        
        valid_tags = [t for t in all_tags if t.startswith("v") and re.match(r'^v\d+\.\d+\.\d+$', t)]
        if fixed_tag not in valid_tags:
            raise Exception(f"Fixed version {fixed_tag} is not in the official version list")
        
        fixed_index = valid_tags.index(fixed_tag)
        if fixed_index == 0:
            raise Exception("Fixed version is the earliest version, cannot find pre-fix version")
        
        vulnerable_tag = valid_tags[fixed_index - 1]
        log_info(f"Found pre-fix version: {vulnerable_tag}")
        return vulnerable_tag
    except Exception as e:
        log_error(f"Failed to get pre-fix version tag: {e}")
        raise

def get_commit_from_tag(local_dir: str, tag: str) -> str:
    try:
        commit_sha = run_cmd(
            ["git", "rev-parse", f"{tag}^{{commit}}"],
            cwd=local_dir
        ).strip()
        log_info(f"Commit corresponding to version {tag}: {commit_sha[:8]}")
        return commit_sha
    except Exception as e:
        log_error(f"Failed to get commit for tag: {e}")
        raise

def switch_to_tag(local_dir: str, tag: str) -> str:
    try:
        original_branch = run_cmd(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=local_dir
        ).strip()
    except:
        original_branch = run_cmd(["git", "rev-parse", "HEAD"], cwd=local_dir).strip()
    log_debug(f"Current repo initial state: {original_branch}")

    log_debug(f"Cleaning local changes in repo {local_dir}...")
    clean_repo(local_dir)

    log_info(f"Switching repo {local_dir} to version: {tag}")
    run_cmd(["git", "checkout", tag], cwd=local_dir)
    return original_branch

def is_detached_head(local_dir: str) -> bool:
    try:
        result = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=local_dir)
        return result.strip() == "HEAD"
    except:
        return True

def restore_repo_version(local_dir: str, original_branch: str) -> None:
    log_debug(f"Restoring repo {local_dir} to initial state: {original_branch}")
    
    
    clean_repo(local_dir)

    
    try:
        run_cmd(["git", "checkout", original_branch], cwd=local_dir)
    except Exception as e:
        log_warn(f"Failed to switch to original state {original_branch}, attempting to create temp branch: {e}")
        
        temp_branch = f"temp_restore_{int(time.time())}"
        run_cmd(["git", "checkout", "-b", temp_branch], cwd=local_dir)
    
    
    if is_detached_head(local_dir):
        log_warn("Repo is in detached HEAD state, skipping git pull")
        return
    
    if original_branch.startswith("pr/"):
        log_debug(f"Currently on PR branch {original_branch}, skipping git pull")
        return

    try:
        run_cmd(["git", "pull"], cwd=local_dir)
    except Exception as e:
        log_warn(f"Standard git pull failed during restore (non-fatal, ignored): {e}")
        
        try:
            default_branch = "main"
            try:
                remote_branches = run_cmd(["git", "branch", "-r"], cwd=local_dir)
                if "origin/master" in remote_branches:
                    default_branch = "master"
            except:
                pass
            
            log_debug(f"Attempting to pull {default_branch} branch updates as fallback")
            run_cmd(["git", "pull", "origin", default_branch], cwd=local_dir)
        except Exception as e2:
            log_warn(f"Fallback git pull also failed, stopping update operation: {e2}")


def get_cached_cpg_path(project_name: str, commit_id: str) -> str:
    commit_short = commit_id[:8]
    return os.path.join(CPG_CACHE_DIR, f"{project_name}_{commit_short}_cpg.bin")

def load_or_generate_cpg(project_name: str, local_dir: str, commit_id: str) -> str:
    cpg_cache_path = get_cached_cpg_path(project_name, commit_id)
    if not os.path.exists(cpg_cache_path):
        log_info(f"Generating CPG (will be cached to: {cpg_cache_path})")
        cmd = [
            "joern-parse", 
            local_dir, 
            "-o", cpg_cache_path,
            "--language", "c"
        ]
        run_cmd(cmd)
        log_debug(f"CPG generation and caching complete: {cpg_cache_path}")
    else:
        log_info(f"Using cached CPG: {cpg_cache_path}")
    return cpg_cache_path

def run_joern_script(
    script_path: str,
    env_vars: Optional[Dict[str, str]] = None,
    timeout: int = 300
) -> str:
    if not os.path.exists(script_path):
        raise FileNotFoundError(f"Scala script does not exist: {script_path}")
    
    with tempfile.NamedTemporaryFile(
        mode='w', 
        suffix='.txt', 
        delete=False,
        dir=os.path.dirname(script_path)
    ) as f:
        output_path = f.name
    
    env = os.environ.copy()
    env["OUTPUT_PATH"] = output_path
    if env_vars:
        env.update(env_vars)
    
    cmd = [
        "joern",
        "--script", script_path
    ]
    
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode != 0:
            error_msg = f"Joern script execution failed (return code {result.returncode}):\n{result.stderr}"
            raise Exception(error_msg)
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            raise Exception(f"Script did not generate valid output, output file is empty: {output_path}")
        return output_path
    finally:
        pass

def extract_function_signatures(
    cpg_path: str,
    script_path: str = SIGNATURE_SCRIPT_PATH
) -> Dict[str, Dict]:
    env_vars = {
        "CPG_PATH": cpg_path
    }
    
    output_path = run_joern_script(
        script_path=script_path,
        env_vars=env_vars
    )
    
    signature_map = {}
    with open(output_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("||")
            if len(parts) != 5:
                log_warn(f"Warning: Invalid function signature format - {line}")
                continue
            file_path, func_name, param_types, start_line, end_line = parts
            key = f"{file_path}||{param_types}"
            signature_map[key] = {
                "file_path": file_path,
                "func_name": func_name,
                "param_types": param_types,
                "start_line": int(start_line),
                "end_line": int(end_line)
            }
    
    os.remove(output_path)
    
    log_debug(f"Successfully extracted {len(signature_map)} function signatures")
    return signature_map

def detect_function_renames(vulnerable_tag: str, fixed_tag: str, local_dir: str, project_name: str) -> Dict[str, List[str]]:
    log_info(f"Detecting function name changes (Vuln version: {vulnerable_tag} -> Fixed version: {fixed_tag})")
    
    def get_function_signatures(tag: str) -> Dict[str, Dict]:
        original_branch = run_cmd(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=local_dir
        ).strip()
        run_cmd(["git", "checkout", tag], cwd=local_dir)
        
        commit_id = get_commit_from_tag(local_dir, tag)
        cpg_path = get_cached_cpg_path(project_name, commit_id)
        load_or_generate_cpg(project_name, local_dir, commit_id)
        sig_map = extract_function_signatures(cpg_path)
        
        restore_repo_version(local_dir, original_branch)
        log_debug(f"Version {tag} extracted {len(sig_map)} function signatures")
        return sig_map
    
    vuln_sigs = get_function_signatures(vulnerable_tag)
    fix_sigs = get_function_signatures(fixed_tag)
    
    rename_map = defaultdict(list)
    
    for sig_key, vuln_func in vuln_sigs.items():
        if sig_key in fix_sigs:
            fix_func = fix_sigs[sig_key]
            if vuln_func["func_name"] != fix_func["func_name"]:
                log_function_change(
                    f"Detected function rename: {vuln_func['func_name']} -> {fix_func['func_name']} "
                    f"(File: {vuln_func['file_path'] or 'Unknown File'})"
                )
                rename_map[fix_func["func_name"]].append(vuln_func["func_name"])
    
    vuln_func_list = list(vuln_sigs.values())
    fix_func_list = list(fix_sigs.values())
    for vuln_func in vuln_func_list:
        overlapping_fix_funcs = [
            f for f in fix_func_list
            if f["file_path"] == vuln_func["file_path"]
            and not (f["end_line"] < vuln_func["start_line"] or f["start_line"] > vuln_func["end_line"])
        ]
        if len(overlapping_fix_funcs) >= 2:
            fix_names = [f["func_name"] for f in overlapping_fix_funcs]
            log_function_change(
                f"Detected function split: {vuln_func['func_name']} -> {fix_names} "
                f"(File: {vuln_func['file_path'] or 'Unknown File'})"
            )
            for fix_name in fix_names:
                rename_map[fix_name].append(vuln_func["func_name"])
    
    for fix_func in fix_func_list:
        overlapping_vuln_funcs = [
            v for v in vuln_func_list
            if v["file_path"] == fix_func["file_path"]
            and not (v["end_line"] < fix_func["start_line"] or v["start_line"] > fix_func["end_line"])
        ]
        if len(overlapping_vuln_funcs) >= 2:
            vuln_names = [v["func_name"] for v in overlapping_vuln_funcs]
            log_function_change(
                f"Detected function merge: {vuln_names} -> {fix_func['func_name']} "
                f"(File: {fix_func['file_path'] or 'Unknown File'})"
            )
            rename_map[fix_func["func_name"]].extend(vuln_names)
    
    log_info(f"Function name change detection completed, found {len(rename_map)} groups of relationships")
    return rename_map

def update_vulnerable_function_names(conn: sqlite3.Connection, cve_id: str, rename_map: Dict[str, List[str]], detected_func_name: str, file_path: str) -> None:
    if detected_func_name in rename_map:
        old_func_names = rename_map[detected_func_name]
        log_info(f"Supplementing old function names to database: {old_func_names} (Associated CVE: {cve_id})")
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT repo_version, func_purpose, vuln_trigger, call_patterns, 
                   fixing_pattern, vulnerable_commit
            FROM vuln_api_calls
            WHERE cve_id = ? AND file_path = ? AND vuln_func_name = ?
        """, (cve_id, file_path, detected_func_name))
        current_data = cursor.fetchone()
        if not current_data:
            log_warn("Corresponding record not found, cannot supplement old function names")
            return
        
        repo_version, func_purpose, vuln_trigger, call_patterns, fixing_pattern, vulnerable_commit = current_data
        for old_name in old_func_names:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO vuln_api_calls
                    (cve_id, repo_version, file_path, vuln_func_name, 
                     func_purpose, vuln_trigger, call_patterns, fixing_pattern, vulnerable_commit)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (cve_id, repo_version, file_path, old_name,
                      func_purpose, vuln_trigger, call_patterns, fixing_pattern, vulnerable_commit))
                log_debug(f"Supplemented old function name record: {old_name} (CVE: {cve_id})")
            except Exception as e:
                log_error(f"Failed to insert old function name record ({old_name}): {e}")
        conn.commit()

def build_reverse_call_chain(target_func_name: str, target_file_path: str, project_name: str, tag: str) -> List[str]:
    log_debug(f"Analyzing vulnerability API call chain: {target_func_name} (Version: {tag})")

    repo_local_dir = f"../../{project_name}"
    commit_id = get_commit_from_tag(repo_local_dir, tag)
    cpg_path = load_or_generate_cpg(project_name, repo_local_dir, commit_id)

    env_vars = {
        "CPG_PATH": cpg_path,
        "TARGET_FUNC_NAME": target_func_name,
        "TARGET_FILE_PATH": target_file_path
    }

    try:
        output_path = run_joern_script(
            script_path=CALLCHAIN_SCRIPT_PATH,
            env_vars=env_vars
        )
    except Exception as e:
        log_error(f"Call chain script execution failed: {e}")
        return []

    call_patterns = []
    with open(output_path, 'r', encoding='utf-8') as f:
        call_patterns = [line.strip() for line in f if line.strip()]
    
    os.remove(output_path)

    log_info(f"Generated {len(call_patterns)} vulnerability API call patterns: {call_patterns[:3]}...")
    return call_patterns

def extract_fixing_pattern(
    diff_text: str,
    func_name: str,
    cve_id: str,
    call_chain: List[Dict],
    cve_info: Dict[str, str]
) -> Dict[str, str]:
    log_debug(f"Extracting fixing pattern: {func_name} (CVE: {cve_id})")
    if not diff_text:
        log_warn("Diff content is empty, cannot extract fixing pattern")
        return {
            "guideline": "No fixing pattern available",
            "code_snippet": "// No code snippet",
            "patch_link": "TBD",
            "patch_diff": "// No diff"
        }

    prompt = f"""
    Analyze the git diff to extract fixing pattern for the vulnerable function '{func_name}'.
    Use the following additional information to improve your analysis:
    
    1. CVE Information:
       - CVE ID: {cve_info.get('cve_id', 'N/A')}
       - Description: {cve_info.get('description', 'N/A')}
       - CWE: {cve_info.get('cwe', 'N/A')}
       - Reference URLs: {', '.join(cve_info.get('reference_urls', [])) or 'N/A'}
    
    2. Reverse Call Chain of the Vulnerable API:
       This shows how the vulnerable function is invoked in the codebase:
       {json.dumps(call_chain)}
    
    Output JSON with:
    - guideline: Detailed instructions on how to fix similar vulnerabilities (considering the call chain context)
    - code_snippet: Fixed function body (only code, no explanations)
    - patch_link: Keep as "TBD"
    - patch_diff: Key part of the diff that shows the fix (relevant to the call chain and vulnerability)

    Git Diff:
    {diff_text}  # Do not truncate diff content

    Output ONLY JSON:
    {{
        "guideline": "...",
        "code_snippet": "...",
        "patch_link": "TBD",
        "patch_diff": "..."
    }}
    """

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        save_llm_raw_output(
            cve_id=cve_id,
            llm_type="fixing_pattern_extraction",
            prompt=prompt,
            response=resp.choices[0].message.content.strip()
        )
        
        content = resp.choices[0].message.content.strip()
        if not content.startswith("{"):
            match = re.search(r"\{[\s\S]*\}", content)
            content = match.group(0) if match else "{}"
        fixing_pattern = json.loads(content)
        fixing_pattern["patch_link"] = "TBD"
        return fixing_pattern
    except Exception as e:
        log_error(f"Failed to extract fixing pattern (Function: {func_name}, CVE: {cve_id}): {e}")
        return {
            "guideline": "Failed to extract guideline",
            "code_snippet": "// No code snippet available",
            "patch_link": "TBD",
            "patch_diff": "// No diff available"
        }

def load_projects() -> set:
    log_debug(f"Loading project configuration: {PROJECTS_CONFIG}")
    try:
        with open(PROJECTS_CONFIG) as f:
            cfg = yaml.safe_load(f)
        return set(cfg.get("projects", []))
    except Exception as e:
        log_error(f"Failed to load project configuration: {e}")
        raise

def ensure_db() -> sqlite3.Connection:
    log_debug("Initializing database")
    try:
        with open(CONFIG) as f:
            cfg = yaml.safe_load(f)
        db_path = cfg['save']['database']
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL UNIQUE,
            description TEXT,
            problemtype_json TEXT,
            nodes TEXT,
            reference_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vuln_api_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            repo_version TEXT NOT NULL,
            file_path TEXT NOT NULL,
            vuln_func_name TEXT NOT NULL,
            func_purpose TEXT,
            vuln_trigger TEXT,
            call_patterns TEXT,
            fixing_pattern TEXT,
            vulnerable_commit TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cve_records(cve_id)
        )
        """)

        cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_unique 
        ON vuln_api_calls (cve_id, file_path, vuln_func_name)
        """)
        
        cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_unique 
        ON cve_records (cve_id)
        """)
        
        conn.commit()
        log_info("Database initialization complete, created cve_records and vuln_api_calls tables")
        return conn
    except Exception as e:
        log_error(f"Database initialization failed: {e}")
        raise

def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> str:
    cmd_str = ' '.join(cmd)
    log_debug(f"Executing command: {cmd_str} (cwd: {cwd})")
    try:
        result = subprocess.check_output(
            cmd, cwd=cwd, text=True, stderr=subprocess.STDOUT
        )
        return result
    except subprocess.CalledProcessError as e:
        log_error(f"Command failed (return code {e.returncode}): {e.output}")
        raise

def clone_or_update(repo_url: str, local_dir: str) -> None:
    log_info(f"Cloning/Updating repository: {repo_url} -> {local_dir}")
    try:
        if not os.path.exists(local_dir):
            run_cmd(["git", "clone", repo_url, local_dir])
        else:
            run_cmd(["git", "remote", "update"], cwd=local_dir)
    except Exception as e:
        log_error(f"Repository operation failed: {e}")
        raise

def get_pr_details(owner: str, repo: str, pr_id: str) -> Optional[Dict]:
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_id}"
    try:
        response = req_session.get(url, headers=HEADERS, proxies=PROXIES, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        log_warn(f"Failed to get PR details: {e}")
        return None

def get_pr_merge_commit(owner: str, repo: str, pr_id: str) -> Optional[str]:
    pr_data = get_pr_details(owner, repo, pr_id)
    return pr_data.get("merge_commit_sha") if pr_data else None

def get_pr_full_diff(owner: str, repo: str, pr_id: str) -> Optional[str]:
    """Get complete diff content of PR via GitHub API"""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_id}"
    headers = HEADERS.copy()
    headers["Accept"] = "application/vnd.github.v3.diff"
    try:
        response = req_session.get(url, headers=headers, proxies=PROXIES, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        log_warn(f"Failed to get PR full diff: {e}")
        return None

def extract_pr_numbers_from_ghsa_description(description: str) -> List[str]:
    return re.findall(r'#(\d+)', description)

def get_ghsa_data(owner: str, repo: str, ghsa_id: str) -> Optional[Dict]:
    """Get complete GHSA data (including description field)"""
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    log_info(f"Requesting GHSA API: {url}")
    try:
        response = req_session.get(url, headers=HEADERS, proxies=PROXIES, timeout=10)
        log_info(f"GHSA API response status code: {response.status_code}")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        status_code = getattr(response, 'status_code', 'Unknown')
        error_msg = f"Failed to get GHSA data (status code: {status_code}): {str(e)}"
        log_error(error_msg)
        return None

def get_ghsa_related_info(owner: str, repo: str, ghsa_id: str) -> Tuple[List[str], str, Dict[str, str]]:
    """
    Get commits, description associated with GHSA, and the mapping between PR and merge commit
    Returns: (list of commits, description, {pr_id: merge_commit_sha})
    """
    ghsa_data = get_ghsa_data(owner, repo, ghsa_id)
    if not ghsa_data:
        return [], "", {}
    
    commits = []
    pr_commit_map = {}
    for vuln in ghsa_data.get("vulnerabilities", []):
        for patch in vuln.get("patches", []):
            if "commit" in patch:
                commit_sha = patch["commit"]["sha"]
                commits.append(commit_sha)
                log_info(f"Extracted commit from GHSA: {commit_sha[:8]}")
    
    pr_ids = extract_pr_numbers_from_ghsa_description(ghsa_data.get("description", ""))
    log_info(f"Extracted PR numbers from GHSA description: {pr_ids}")
    for pr_id in pr_ids:
        merge_commit = get_pr_merge_commit(owner, repo, pr_id)
        if merge_commit:
            commits.append(merge_commit)
            pr_commit_map[pr_id] = merge_commit
            log_info(f"Extracted merge commit from PR #{pr_id}: {merge_commit[:8]}")
    
    unique_commits = deduplicate_list(commits)
    log_info(f"Extracted {len(unique_commits)} valid commits in total for GHSA {ghsa_id}")
    return unique_commits, ghsa_data.get("description", ""), pr_commit_map

def fetch_pr_branch(local_dir: str, pr_id: str) -> str:
    try:
        run_cmd(["git", "rev-parse", "--verify", f"pr/{pr_id}"], cwd=local_dir)
    except subprocess.CalledProcessError:
        run_cmd(["git", "fetch", "origin", f"pull/{pr_id}/head:pr/{pr_id}"], cwd=local_dir)
    run_cmd(["git", "checkout", f"pr/{pr_id}"], cwd=local_dir)
    return f"pr/{pr_id}"

def resolve_commit_id(commit_identifier: str, owner: str, repo: str, local_dir: str) -> Optional[str]:
    if not commit_identifier:
        log_warn("Commit identifier is empty, cannot resolve")
        return None

    if commit_identifier.startswith("PR-"):
        pr_id = commit_identifier[3:]
        log_debug(f"Resolving PR identifier: {commit_identifier} -> PR ID {pr_id}")
        
        merge_commit = get_pr_merge_commit(owner, repo, pr_id)
        if merge_commit:
            log_info(f"Got merge commit for PR #{pr_id} from API: {merge_commit[:8]}")
            return merge_commit
        
        try:
            log_debug(f"API fetch failed, attempting to fetch PR #{pr_id} branch from local repo")
            pr_branch = fetch_pr_branch(local_dir, pr_id)
            commit_sha = run_cmd(
                ["git", "rev-parse", f"{pr_branch}^{{commit}}"],
                cwd=local_dir
            ).strip()
            log_info(f"Got commit from local PR branch: {commit_sha[:8]}")
            return commit_sha
        except Exception as e:
            log_error(f"PR branch processing failed (PR #{pr_id}): {e}")
            return None

    elif commit_identifier.startswith("GHSA-"):
        log_debug(f"Resolving GHSA identifier: {commit_identifier}")
        related_commits, _, _ = get_ghsa_related_info(owner, repo, commit_identifier)
        if related_commits:
            log_info(f"Got associated commit from GHSA {commit_identifier}: {related_commits[0][:8]}")
            return related_commits[0]
        else:
            log_warn(f"GHSA {commit_identifier} has no associated commits")
            return None

    else:
        log_debug(f"Using commit SHA directly: {commit_identifier[:8]}")
        return commit_identifier

def extract_cwe(problemtype_json_str: str) -> str:
    try:
        problemtypes = json.loads(problemtype_json_str)
    except Exception as e:
        log_warn(f"Failed to parse CWE: {e}")
        return "Unknown"

    cwe_set = set()
    for pt in problemtypes:
        for desc in pt.get("description", []):
            if desc.get("lang") == "en":
                val = desc.get("value", "").strip()
                if val.startswith("CWE-"):
                    cwe_set.add(val)

    result = ",".join(sorted(cwe_set)) if cwe_set else "Unknown"
    log_info(f"Extracted CWE list: {result}")
    return result

def extract_info_from_ghsa_urls(reference_urls: List[str], owner: str, repo: str) -> Tuple[List[str], Dict[str, str], Dict[str, str]]:
    """
    Extract commits, description mapping, and PR-commit mapping from GHSA links
    Returns: (list of commits, {ghsa_id: description}, {pr_id: commit_sha})
    """
    ghsa_commits = []
    ghsa_descriptions = {}
    pr_commit_map = {}
    
    unique_reference_urls = deduplicate_list(reference_urls)
    duplicate_count = len(reference_urls) - len(unique_reference_urls)
    if duplicate_count > 0:
        log_info(f"Removed {duplicate_count} duplicate reference links")
    
    log_info(f"Starting GHSA extraction from deduplicated reference links, total {len(unique_reference_urls)} links")
    
    for url in unique_reference_urls:
        if "github.com" in url and "/security/advisories/" in url:
            parts = urlparse(url)
            segs = parts.path.strip("/").split("/")
            idx = segs.index("advisories") if "advisories" in segs else -1
            if idx != -1 and len(segs) > idx + 1:
                ghsa_id = segs[idx + 1]
                log_info(f"Extracted GHSA ID from URL: {ghsa_id} (Full URL: {url})")
                
                related_commits, description, ghsa_pr_map = get_ghsa_related_info(owner, repo, ghsa_id)
                if related_commits:
                    ghsa_commits.extend(related_commits)
                if description:
                    ghsa_descriptions[ghsa_id] = description
                pr_commit_map.update(ghsa_pr_map)
            else:
                log_warn(f"Invalid GHSA link format: {url}")
    
    unique_commits = deduplicate_list(ghsa_commits)
    if len(unique_commits) < len(ghsa_commits):
        log_info(f"Removed {len(ghsa_commits) - len(unique_commits)} duplicate commits")
    
    return unique_commits, ghsa_descriptions, pr_commit_map

def analyze_with_gpt(diff_text: str, cve_info: Dict[str, str]) -> Optional[Dict]:
    cve_id = cve_info["cve_id"]
    log_info(f"GPT analyzing CVE: {cve_id}")
    
    unique_refs = deduplicate_list(cve_info["reference_urls"])
    refs_str = "\n".join([f"- {url}" for url in unique_refs])
    
    full_description = cve_info['description']
    full_diff = diff_text
    
    log_debug(f"CVE description length: {len(full_description)} chars, diff length: {len(full_diff)} chars")
    
    prompt = f"""
    Analyze {cve_id} and its git diff to extract vulnerable functions.
    Output JSON with "vulnerabilities" array containing:
    - file_path: Path of the file with vulnerable function
    - vuln_func_name: Exact name of the vulnerable function
    - func_purpose: What the function does (1 sentence)
    - vuln_trigger: Condition to trigger the vulnerability

    CVE Info:
    - Description: {full_description}
    - CWE: {cve_info['cwe']}
    - References: {refs_str}

    Git Diff:
    {full_diff}

    Output ONLY JSON:
    {{
        "vulnerabilities": [{{"file_path": "...", "vuln_func_name": "...", "func_purpose": "...", "vuln_trigger": "..."}}],
        "repo_version": "{cve_info['repo_version']}"
    }}
    """
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        save_llm_raw_output(
            cve_id=cve_id,
            llm_type="vulnerability_analysis",
            prompt=prompt,
            response=resp.choices[0].message.content.strip()
        )
        
        content = resp.choices[0].message.content.strip()
        if not content.startswith("{"):
            match = re.search(r"\{[\s\S]*\}", content)
            content = match.group(0) if match else "{}"
        return json.loads(content)
    except Exception as e:
        log_error(f"GPT analysis failed: {e}")
        log_warn("Failure likely due to excessive content length, suggest using truncated version")
        return None

def generate_vulnerability_dataset(db_path: str) -> None:
    log_info(f"Starting to generate vulnerability dataset, target path: {DATASET_OUTPUT_PATH}")
    
    dataset_dir = os.path.dirname(DATASET_OUTPUT_PATH)
    os.makedirs(dataset_dir, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            vac.cve_id, vac.repo_version, vac.file_path, vac.vuln_func_name,
            vac.func_purpose, vac.vuln_trigger, vac.call_patterns,
            vac.fixing_pattern, vac.vulnerable_commit,
            cve.description, cve.problemtype_json
        FROM vuln_api_calls vac
        LEFT JOIN cve_records cve ON vac.cve_id = cve.cve_id
    """)
    
    rows = cursor.fetchall()
    total_records = len(rows)
    dataset = []
    internal_id = 1
    
    if total_records == 0:
        log_warn("No valid vulnerability records found in database, generating empty dataset")
        dataset = [{"status": "empty", "message": "No vulnerable records found in database"}]
    else:
        log_info(f"Detected {total_records} vulnerability records in total, formatting data...")
        for row in rows:
            (cve_id, repo_version, file_path, vuln_func_name,
             func_purpose, vuln_trigger, call_patterns_json,
             fixing_pattern_json, vulnerable_commit, desc, problemtype_json) = row
            
            call_patterns = json.loads(call_patterns_json) if call_patterns_json else []
            fixing_pattern = json.loads(fixing_pattern_json) if fixing_pattern_json else {
                "guideline": "No fixing pattern available",
                "code_snippet": "",
                "patch_link": "TBD",
                "patch_diff": ""
            }
            
            cwe_id = extract_cwe(problemtype_json) if problemtype_json else "Unknown"
            
            full_vulnerability_desc = desc if desc else f"Vulnerability in {vuln_func_name}"
            
            dataset.append({
                "id": f"VULN-{internal_id:06d}",
                "vulnerability": full_vulnerability_desc,
                "affected_functions": [vuln_func_name],
                "functionality": func_purpose if func_purpose else "No purpose described",
                "call_patterns": [
                    {
                        "pattern": p,
                        "description": f"Vulnerable call chain leading to {vuln_func_name} (version: {vulnerable_commit})"
                    } for p in call_patterns
                ],
                "fixing_pattern": fixing_pattern,
                "severity": "HIGH",
                "exploit_prereqs": [vuln_trigger] if vuln_trigger else ["Unknown"],
                "mitigations": [
                    "Input validation for user-controlled parameters",
                    f"Apply fix from related patch",
                    f"Avoid using {vuln_func_name} in vulnerable versions ({repo_version})"
                ],
                "related_cve": [cve_id],
                "related_cwe": [cwe_id],
                "vulnerable_version": vulnerable_commit
            })
            internal_id += 1
    
    try:
        with open(DATASET_OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)
        log_info(f"Dataset generation completed! Path: {DATASET_OUTPUT_PATH}, Total records: {len(dataset)}")
    except Exception as e:
        log_error(f"Failed to write dataset: {e}")
        raise Exception(f"Failed to save dataset: {e}")
    finally:
        conn.close()

def process_csv(csv_file: str, allowed_projects: set) -> None:
    log_info(f"Starting to process CSV file: {csv_file}")
    
    conn = ensure_db()
    grouped_data = defaultdict(lambda: {
        "desc_text": "", "cpe_info": "", "commits": set(),
        "cwe": "Unknown", "reference_urls": [], "repo_version": "Unknown",
        "problemtype_json": "[]", "reference_json": "[]", "nodes": "",
        "owner": None, "repo": None, "ghsa_descriptions": {},
        "pr_commit_map": {}
    })

    codeguarder_data = []

    try:
        with open(csv_file, newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            total_rows = sum(1 for _ in csvfile) - 1
            csvfile.seek(0)
            
            log_info(f"CSV file contains {total_rows} rows of data, parsing and grouping by CVE...")
            for row_num, row in enumerate(reader, start=2):
                cve_id = row.get("cve_id")
                if not cve_id or cve_id == "cve_id":
                    continue
                
                nodes_str = row.get("nodes", "")
                problemtype_json = row.get("problemtype_json", "[]")
                reference_json = row.get("reference_json", "[]")
                desc_text = row.get("description", "").strip()
                
                cpe_info, repo_version = parse_nodes_data(nodes_str)
                if not cpe_info:
                    continue
                cwe = extract_cwe(problemtype_json)
                
                owner, repo = None, None
                try:
                    refs = json.loads(reference_json)
                    reference_urls = [ref.get("url", "") for ref in refs if ref.get("url")]
                    commit_urls = []
                    for url in reference_urls:
                        if "github.com" in url:
                            if not owner or not repo:
                                _, _, (parsed_owner, parsed_repo) = parse_github_url(url)
                                if parsed_owner and parsed_repo:
                                    owner = parsed_owner
                                    repo = parsed_repo
                            if "/commit/" in url or "/pull/" in url:
                                commit_urls.append(url)
                except Exception as e:
                    log_warn(f"Failed to parse reference URL at row {row_num}: {e}")
                    reference_urls = []
                    commit_urls = []
                
                data = grouped_data[cve_id]
                data["desc_text"] = desc_text
                data["cpe_info"] = cpe_info
                data["cwe"] = cwe
                data["reference_urls"].extend(reference_urls)
                data["repo_version"] = repo_version
                data["commits"].update(commit_urls)
                data["problemtype_json"] = problemtype_json
                data["reference_json"] = reference_json
                data["nodes"] = nodes_str
                data["owner"] = owner
                data["repo"] = repo

        cursor = conn.cursor()
        total_cves = len(grouped_data)
        log_info(f"Parsed {total_cves} CVEs in total, writing to cve_records table...")
        for cve_id, info in grouped_data.items():
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO cve_records
                    (cve_id, description, problemtype_json, nodes, reference_json)
                    VALUES (?, ?, ?, ?, ?)
                """, (cve_id, info["desc_text"], info["problemtype_json"], 
                      info["nodes"], info["reference_json"]))
            except Exception as e:
                log_error(f"Failed to write to cve_records table (CVE: {cve_id}): {e}")
        
        conn.commit()
        log_info(f"Finished writing to cve_records table, processed {total_cves} CVEs in total")

        successful_count = 0
        for cve_id, info in grouped_data.items():
            log_info(f"\n=== Starting processing CVE: {cve_id} ===")
            commits = list(info["commits"])
            owner = info["owner"]
            repo = info["repo"]

            log_info(f"CVE basic info - owner: {owner}, repo: {repo}, original commit link count: {len(commits)}")

            ghsa_commits = []
            ghsa_descriptions = {}
            pr_commit_map = {}
            if owner and repo:
                log_info(f"{cve_id} Attempting to extract info from GHSA")
                ghsa_commits, ghsa_descriptions, pr_commit_map = extract_info_from_ghsa_urls(info["reference_urls"], owner, repo)
                info["ghsa_descriptions"] = ghsa_descriptions
                info["pr_commit_map"] = pr_commit_map

            if ghsa_commits:
                commits = [f"https://github.com/{owner}/{repo}/commit/{c}" for c in ghsa_commits] + commits
                info["commits"].update(commits)
                log_info(f"Commit link count after merge: {len(commits)}")
            elif not commits:
                log_warn(f"{cve_id} No associated commit links (including GHSA), skipping processing")
                continue

            cve_description = info["desc_text"]
            if ghsa_descriptions:
                cve_description = next(iter(ghsa_descriptions.values()))
                log_info(f"Using GHSA description instead of original description (length: {len(cve_description)})")

            cve_info = {
                "cve_id": cve_id,
                "description": cve_description,
                "cwe": info["cwe"],
                "reference_urls": info["reference_urls"],
                "repo_version": info["repo_version"]
            }
            has_valid_data = False

            for url_idx, url in enumerate(commits, 1):
                try:
                    log_info(f"Processing {cve_id} commit link {url_idx}/{len(commits)}: {url}")
                    repo_url, commit_identifier, (owner, repo) = parse_github_url(url)
                    if not all([repo_url, commit_identifier, owner, repo]):
                        log_warn(f"Invalid commit link: {url}")
                        continue

                    project_name = Path(repo_url).stem
                    if project_name not in allowed_projects:
                        log_info(f"Project {project_name} not in allowed list, skipping")
                        continue

                    local_dir = f"../data/repos/{project_name}"
                    clone_or_update(repo_url, local_dir)

                    resolved_fix_commit = resolve_commit_id(commit_identifier, owner, repo, local_dir)
                    if not resolved_fix_commit:
                        log_error(f"Cannot resolve commit identifier: {commit_identifier}")
                        continue
                    log_info(f"CVE-{cve_id} fixing commit: {resolved_fix_commit[:8]}")

                    
                    matched_pr_id = None
                    for pr_id, commit_sha in info["pr_commit_map"].items():
                        if commit_sha.startswith(resolved_fix_commit[:8]):
                            matched_pr_id = pr_id
                            log_info(f"Found related PR #{pr_id} (merge commit match)")
                            break
                    
                    
                    if not matched_pr_id and commit_identifier and commit_identifier.startswith("PR-"):
                        matched_pr_id = commit_identifier.split("-")[1]
                        log_info(f"Found related PR #{matched_pr_id} (from URL parsing)")

                    
                    diff_text = ""
                    if matched_pr_id:
                        log_info(f"Attempting to get full diff for PR #{matched_pr_id} (using get_pr_full_diff)")
                        diff_text = get_pr_full_diff(owner, repo, matched_pr_id)
                        if diff_text:
                            log_info(f"Successfully retrieved full diff for PR #{matched_pr_id} (length: {len(diff_text)})")
                            
                            
                            cwe_id = extract_cwe(info["problemtype_json"])
                            codeguarder_result = generate_codeguarder_analysis(
                                cve_desc=cve_description,
                                cwe_id=cwe_id,
                                diff_text=diff_text,
                                cve_id=cve_id
                            )
                            if "error" not in codeguarder_result:
                                codeguarder_data.append(codeguarder_result)
                        else:
                            log_warn(f"Failed to get diff for PR #{matched_pr_id}, using git show fallback")
                            diff_text = run_cmd(["git", "show", resolved_fix_commit], cwd=local_dir)
                    else:
                        diff_text = run_cmd(["git", "show", resolved_fix_commit], cwd=local_dir)
                    
                    log_debug(f"Retrieved diff content with length {len(diff_text)} chars")

                    analysis = analyze_with_gpt(diff_text, cve_info)
                    if not analysis:
                        log_error(f"GPT analysis failed, skipping this commit")
                        continue

                    vuln_list = analysis.get("vulnerabilities", [])
                    final_repo_version = f"{info['repo_version']}"
                    if not vuln_list:
                        log_warn(f"GPT failed to extract vulnerable functions, skipping this commit")
                        continue

                    fixed_tag = get_fixed_tag(local_dir, resolved_fix_commit)
                    vulnerable_tag = get_vulnerable_tag(local_dir, fixed_tag)
                    log_info(f"Version info - Pre-fix: {vulnerable_tag}, Fixed: {fixed_tag}")
                    final_repo_version = f"{vulnerable_tag} -> {fixed_tag}"

                    original_branch = switch_to_tag(local_dir, vulnerable_tag)
                    vulnerable_commit = get_commit_from_tag(local_dir, vulnerable_tag)

                    for vuln in vuln_list:
                        file_path = vuln.get("file_path", "").strip()
                        vuln_func_name = vuln.get("vuln_func_name", "").strip()
                        if not all([file_path, vuln_func_name]):
                            log_warn(f"Invalid vulnerable function info (missing file path or function name)")
                            continue

                        rename_map = detect_function_renames(
                            vulnerable_tag=vulnerable_tag,
                            fixed_tag=fixed_tag,
                            local_dir=local_dir,
                            project_name=project_name
                        )

                        possible_old_names = rename_map.get(vuln_func_name, [vuln_func_name])
                        call_patterns = []
                        for func_name in possible_old_names:
                            patterns = build_reverse_call_chain(
                                target_func_name=func_name,
                                target_file_path=file_path,
                                project_name=project_name,
                                tag=vulnerable_tag
                            )
                            if patterns:
                                call_patterns = patterns
                                break
                        call_patterns_json = json.dumps(call_patterns)

                        fixing_pattern = extract_fixing_pattern(
                            diff_text=diff_text,
                            func_name=vuln_func_name,
                            cve_id=cve_id,
                            call_chain=call_patterns,
                            cve_info=cve_info
                        )
                        fixing_pattern["patch_link"] = url
                        if matched_pr_id:
                            fixing_pattern["patch_link"] = f"https://github.com/{owner}/{repo}/pull/{matched_pr_id}"
                        fixing_pattern_json = json.dumps(fixing_pattern)

                        try:
                            conn.execute("""
                                INSERT INTO vuln_api_calls
                                (cve_id, repo_version, file_path, vuln_func_name, 
                                 func_purpose, vuln_trigger, call_patterns, fixing_pattern, vulnerable_commit)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT (cve_id, file_path, vuln_func_name) DO UPDATE SET
                                call_patterns = excluded.call_patterns,
                                fixing_pattern = excluded.fixing_pattern,
                                vulnerable_commit = excluded.vulnerable_commit
                            """, (cve_id, final_repo_version, file_path, vuln_func_name,
                                  vuln.get("func_purpose", ""), vuln.get("vuln_trigger", ""),
                                  call_patterns_json, fixing_pattern_json, vulnerable_tag))
                            has_valid_data = True
                            log_info(f"Inserted/Updated vulnerable function record: {vuln_func_name} (CVE: {cve_id})")
                        except Exception as e:
                            log_error(f"Failed to insert vulnerable function record ({vuln_func_name}): {e}")
                            continue

                        update_vulnerable_function_names(
                            conn=conn,
                            cve_id=cve_id,
                            rename_map=rename_map,
                            detected_func_name=vuln_func_name,
                            file_path=file_path
                        )

                    restore_repo_version(local_dir, original_branch)

                except Exception as e:
                    log_error(f"Failed to process commit link {url} for {cve_id}: {e}")
                    with open(CRASH_LOG_FILE, "a") as f:
                        f.write(f"[{get_timestamp()}] CVE: {cve_id}, URL: {url}, Error: {e}\n")
                        f.write(traceback.format_exc() + "\n")
                    if 'original_branch' in locals():
                        restore_repo_version(local_dir, original_branch)
                    continue
            
            if has_valid_data:
                conn.commit()
                successful_count += 1
                log_info(f"CVE-{cve_id} processing completed (transaction committed)")
        
        
        save_codeguarder_dataset(codeguarder_data)
        
        db_absolute_path = conn.execute("PRAGMA database_list").fetchone()[2]
        generate_vulnerability_dataset(db_absolute_path)
        
        log_info(f"=== CSV processing completed ===")
        log_info(f"Total CVE count: {total_cves}")
        log_info(f"Successfully processed CVE count: {successful_count}")
        log_info(f"Processing success rate: {successful_count/total_cves*100:.1f}%" if total_cves > 0 else "No valid CVEs")
        log_info(f"CodeGuarder dataset generated, containing {len(codeguarder_data)} valid analysis records")
        
    except Exception as e:
        log_error(f"Fatal error in CSV processing flow: {e}")
        with open(CRASH_LOG_FILE, "a") as f:
            f.write(f"[{get_timestamp()}] Fatal error (CSV processing flow): {e}\n")
            f.write(traceback.format_exc() + "\n")
    finally:
        conn.close()
        log_info("Database connection closed")

if __name__ == "__main__":
    start_time = time.time()
    log_info("=== Starting Vulnerability Analysis and Dataset Generation Tool ===")
    
    try:
        projects = load_projects()
        log_info(f"Allowed projects list: {projects}")
        process_csv(CSV_FILE, projects)
    except Exception as e:
        log_error(f"Program failed to start: {e}")
        print(f"Stack trace: {traceback.format_exc()}")
    finally:
        end_time = time.time()
        elapsed_seconds = end_time - start_time
        elapsed_h = int(elapsed_seconds // 3600)
        elapsed_m = int((elapsed_seconds % 3600) // 60)
        elapsed_s = int(elapsed_seconds % 60)
        elapsed_str = f"{elapsed_h}h {elapsed_m}m {elapsed_s}s"
        
        log_info(f"=== Program execution finished ===")
        log_info(f"Total elapsed time: {elapsed_str}")