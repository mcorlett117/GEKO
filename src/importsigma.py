from ast import pattern
from datetime import datetime
import os
import yaml
import requests
import urllib3
import re
from log import log_info, log_error, log_debug
from dotenv import load_dotenv
from opencti import get_techniques_ids, create_sigma_relationship
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============
# Config

# ==============
load_dotenv()
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")

OPENCTI_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json"
}

sigma_folder = f"./sigma/rules/windows/file"


def get_sigma_rules(sigma_folder):
    for root, dirs, files in os.walk(sigma_folder):
        for filename in files:
            if filename.endswith(".yml"):
                with open(os.path.join(root, filename), "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    if not rule:
                        log_error(f"Failed to parse Sigma rule: {filename}")
                        continue
                    title = rule.get('title', 'Unknown Title')
                    description = rule.get('description', 'No Description')
                    safe_description = f"\"\"{description}\"\""
                    rule_yaml = yaml.dump(rule)
                    log_debug(f"Processing rule: {title}")
                    # Escape triple quotes and backslashes in rule_yaml
                    safe_rule_yaml = f"\"\"{rule_yaml}\"\""
                    mutation = f"""
                    mutation {{
                        indicatorAdd(input: {{
                            name: "[SIGMA] - {title}"
                            description: "{safe_description}"
                            pattern_type: "sigma"
                            pattern: "{safe_rule_yaml}"
                        }}) {{
                            id
                            name
                        }}
                    }}
                    """
                    # Send the transformed rule to OpenCTI
                    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": mutation}, verify=False)
                    if response.status_code == 200:
                        resp_json = response.json()
                        if 'errors' in resp_json:
                            log_error(f"OpenCTI error for rule '{title}': {resp_json['errors']}. Skipping to next.")
                            continue
                        log_info(f"Successfully imported Sigma rule: {title}")
                        log_debug(f"Response: {resp_json}")
                        rule_id = resp_json.get("data", {}).get("indicatorAdd", {}).get("id")
                        if not rule_id:
                            log_error(f"Failed to get rule ID for Sigma rule: {title}. Skipping to next.")
                            continue
                        # add relationship for each technique tag
                        tags = rule.get('tags', [])
                        for tag in tags:
                            if tag.startswith('attack.t'):
                                # Extract txxx, txxxx, or txxxx.xxx
                                match = re.match(r'attack\.(t\d{4}(?:\.\d{3})?)', tag)
                                if match:
                                    technique_id = match.group(1)
                                    tid = get_techniques_ids(OPENCTI_URL, OPENCTI_HEADERS, technique_id)
                                    create_sigma_relationship(OPENCTI_URL, OPENCTI_HEADERS, rule_id, tid, title)
                    else:
                        log_error(f"Failed to import Sigma rule: {title} - {response.text}")
                    
def main():
    log_info(f"Starting Sigma import of {sigma_folder}")
    get_sigma_rules(sigma_folder)
    log_info("Sigma import completed.")

if __name__ == "__main__":
    main()