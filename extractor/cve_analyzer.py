
import datetime
import json
import os
import re
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pandas as pd
import requests
import yaml
from pandas import json_normalize

# ---------------------------------------------------------------------------------------------------------------------

urlhead = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
urltail = ".json.zip"
initYear = 2002
currentYear = datetime.datetime.now().year
DATA_PATH = "./data"

SAMPLE_LIMIT = 0

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if SAMPLE_LIMIT > 0:
    initYear = currentYear

df = pd.DataFrame()

ordered_cve_columns = [
    "cve_id",
    "published_date",
    "last_modified_date",
    "description",
    "nodes",
    "severity",
    "obtain_all_privilege",
    "obtain_user_privilege",
    "obtain_other_privilege",
    "user_interaction_required",
    "cvss2_vector_string",
    "cvss2_access_vector",
    "cvss2_access_complexity",
    "cvss2_authentication",
    "cvss2_confidentiality_impact",
    "cvss2_integrity_impact",
    "cvss2_availability_impact",
    "cvss2_base_score",
    "cvss3_vector_string",
    "cvss3_attack_vector",
    "cvss3_attack_complexity",
    "cvss3_privileges_required",
    "cvss3_user_interaction",
    "cvss3_scope",
    "cvss3_confidentiality_impact",
    "cvss3_integrity_impact",
    "cvss3_availability_impact",
    "cvss3_base_score",
    "cvss3_base_severity",
    "exploitability_score",
    "impact_score",
    "ac_insuf_info",
    "reference_json",
    "problemtype_json",
    "source_identifier",
    "cpe_entries"
]

cwe_columns = [
    "cwe_id",
    "cwe_name",
    "description",
    "extended_description",
    "url",
    "is_category"
]


def rename_columns(name):
    """
    converts the other cases of string to snake_case, and further processing of column names.
    """
    name = name.split(".", 2)[-1].replace(".", "_")
    name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    name = (
        name.replace("cvss_v", "cvss")
        .replace("_data", "_json")
        .replace("description_json", "description")
    )
    return name


def preprocess_jsons(df_in):
    print("Flattening CVE items and removing the duplicates...")
    
    cve_flat = json_normalize(df_in["cve"], sep="_")
    
    df_cve = pd.concat([df_in.reset_index(drop=True), cve_flat.reset_index(drop=True)], axis=1)

    df_cve["references"] = df_cve["references"].apply(lambda x: x if isinstance(x, list) else [])
    df_cve = df_cve[df_cve["references"].str.len() > 0]

    df_cve = df_cve.rename(columns={
        "id": "cve_id",
        "published": "published_date",
        "lastModified": "last_modified_date",
        "references": "reference_json",
        "weaknesses": "problemtype_json",
        "sourceIdentifier": "source_identifier"
    })

    def get_en_description(desc_list):
        if not isinstance(desc_list, list) or len(desc_list) == 0:
            return ""
        for desc in desc_list:
            if desc.get("lang") == "en":
                return desc.get("value", "").strip()
        return desc_list[0].get("value", "").strip()
    
    df_cve["description"] = df_cve["descriptions"].apply(get_en_description)

    df_cve["cvss2_vector_string"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_vectorString", "")
    df_cve["cvss2_access_vector"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_accessVector", "")
    df_cve["cvss2_access_complexity"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_accessComplexity", "")
    df_cve["cvss2_authentication"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_authentication", "")
    df_cve["cvss2_confidentiality_impact"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_confidentialityImpact", "")
    df_cve["cvss2_integrity_impact"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_integrityImpact", "")
    df_cve["cvss2_availability_impact"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_availabilityImpact", "")
    df_cve["cvss2_base_score"] = df_cve.get("metrics_cvssMetricV2_0_cvssData_baseScore", "")

    df_cve["cvss3_vector_string"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_vectorString", "")
    df_cve["cvss3_attack_vector"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_attackVector", "")
    df_cve["cvss3_attack_complexity"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_attackComplexity", "")
    df_cve["cvss3_privileges_required"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_privilegesRequired", "")
    df_cve["cvss3_user_interaction"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_userInteraction", "")
    df_cve["cvss3_scope"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_scope", "")
    df_cve["cvss3_confidentiality_impact"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_confidentialityImpact", "")
    df_cve["cvss3_integrity_impact"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_integrityImpact", "")
    df_cve["cvss3_availability_impact"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_availabilityImpact", "")
    df_cve["cvss3_base_score"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_baseScore", "")
    df_cve["cvss3_base_severity"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_baseSeverity", "")

    df_cve["obtain_all_privilege"] = df_cve.get("metrics_cvssMetricV2_0_obtainAllPrivilege", False)
    df_cve["obtain_user_privilege"] = df_cve.get("metrics_cvssMetricV2_0_obtainUserPrivilege", False)
    df_cve["obtain_other_privilege"] = df_cve.get("metrics_cvssMetricV2_0_obtainOtherPrivilege", False)
    df_cve["user_interaction_required"] = df_cve.get("metrics_cvssMetricV2_0_userInteractionRequired", False)
    df_cve["ac_insuf_info"] = df_cve.get("metrics_cvssMetricV2_0_acInsufInfo", False)
    df_cve["exploitability_score"] = df_cve.get("metrics_cvssMetricV2_0_exploitabilityScore", "")
    df_cve["impact_score"] = df_cve.get("metrics_cvssMetricV2_0_impactScore", "")
    df_cve["severity"] = df_cve.get("metrics_cvssMetricV31_0_cvssData_baseSeverity", 
                                    df_cve.get("metrics_cvssMetricV2_0_baseSeverity", ""))

    df_cve["nodes"] = df_cve.get("configurations", [])
    df_cve["nodes"] = df_cve["nodes"].apply(lambda x: x if isinstance(x, list) else [])
    
    def extract_cpe_entries(config_nodes):
        cpe_entries = []
        if isinstance(config_nodes, list):
            for node in config_nodes:
                if isinstance(node, dict) and "cpeMatch" in node:
                    for cpe in node["cpeMatch"]:
                        if "criteria" in cpe:
                            cpe_entries.append(cpe["criteria"])
        return cpe_entries
    
    df_cve["cpe_entries"] = df_cve["nodes"].apply(extract_cpe_entries)

    import json
    for col in ["reference_json", "problemtype_json", "nodes", "cpe_entries"]:
        if col in df_cve.columns:
            df_cve[col] = df_cve[col].apply(
                lambda x: json.dumps(x, ensure_ascii=False) if not isinstance(x, str) else x
            )

    for col in ordered_cve_columns:
        if col not in df_cve.columns:
            df_cve[col] = ""
    df_cve = df_cve[ordered_cve_columns]

    return df_cve


def import_cves():
    """
    gathering CVE records by processing JSON files.
    """
    print("-" * 70)
    for year in range(initYear, currentYear + 1):
        extract_target = "nvdcve-2.0-" + str(year) + ".json"
        zip_file_url = urlhead + str(year) + urltail

        if os.path.isfile(Path(DATA_PATH) / "json" / extract_target):
            print(f"Reusing the {year} CVE json file that was downloaded earlier...")
            json_file = Path(DATA_PATH) / "json" / extract_target
        else:
            r = requests.get(zip_file_url)
            z = ZipFile(BytesIO(r.content))
            json_file = z.extract(extract_target, Path(DATA_PATH) / "json")

        with open(json_file) as f:
            yearly_data = json.load(f)
            yearly_cve_list = yearly_data["vulnerabilities"]  
            if year == initYear:
                df_cve = pd.DataFrame(yearly_cve_list)
            else:
                df_cve = pd.concat([df_cve, pd.DataFrame(yearly_cve_list)], ignore_index=True)
            print(f"The CVE json for {year} has been merged")

    df_cve = preprocess_jsons(df_cve)
    df_cve = df_cve.map(str)
    print(len(df_cve))
    assert df_cve.cve_id.is_unique, "\nPrimary keys are not unique in cve records!"
    
    df_cve.to_csv(
        Path(DATA_PATH) / "cve-records.csv",
        index=False,
        quoting=1,
        encoding="utf-8-sig",
        chunksize=10000
    )
    print("All CVEs have been merged into the cve table")
    print("\nExamples: \n", df_cve.head(5))
    print("-" * 70)


def check_project_in_cve(df, prj, cve_file_dir):
    
    prj_clean = prj.split('/')[-1]
    prj_lower = prj_clean.lower()
    
    def safe_json_loads(x):
        try:
            return json.loads(x) if x else []
        except:
            return []
    
    def match_criteria(row):
        if prj_lower in str(row['description']).lower():
            return True
            
        if prj_lower in str(row['source_identifier']).lower():
            return True
            
        cpe_entries = safe_json_loads(row['cpe_entries'])
        for cpe in cpe_entries:
            if prj_lower in str(cpe).lower():
                return True
                
        references = safe_json_loads(row['reference_json'])
        for ref in references:
            if 'url' in ref and prj_lower in str(ref['url']).lower():
                return True
                
        return False
    
    prj_cve_mask = df.apply(match_criteria, axis=1)
    prj_cve_df = df[prj_cve_mask].copy()
    
    if len(prj_cve_df) > 0:
        print(f'Project [{prj_clean}] is in CVE list. Found {len(prj_cve_df)} related CVE records.')
        prj_cve_file = cve_file_dir / f"cve-records-{prj_clean}.csv"
        prj_cve_df.to_csv(
            prj_cve_file,
            index=False,
            quoting=1,
            encoding="utf-8-sig"
        )
        print(f'Project [{prj_clean}] CVE records saved to: {prj_cve_file}\n')
    else:
        print(f'Project [{prj_clean}] is not in CVE list. No related records.\n')


def run_checking():
    global cve_file
    cve_save_dir = cve_file.parent
    
    with open("./config/projects.yaml") as fp:
        config = yaml.safe_load(fp)
        print(f'List of projects to check: \n{config["projects"]}\n')

    print("Loading full CVE records from:", cve_file)
    df = pd.read_csv(
        cve_file,
        encoding="utf-8-sig",
        engine="python",
        on_bad_lines='skip'
    )
    print(f'Full CVE records loaded: {len(df)} rows.\n')

    for prj in config["projects"]:
        check_project_in_cve(df, prj, cve_save_dir)


if __name__ == "__main__":
    cve_file = Path(DATA_PATH) / "cve-records.csv"

    if not cve_file.is_file():
        print(f"cve-records.csv not found. Starting to crawl CVE data...")
        import_cves()
    else:
        print(f"cve-records.csv already exists. Skipping crawl.\n")

    run_checking()