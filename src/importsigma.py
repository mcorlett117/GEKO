from ast import pattern
from datetime import datetime
import os
import yaml
import json
import requests
import urllib3
from log import log_info, log_error, log_debug
from dotenv import load_dotenv
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

sigma_folder = f"./sigma/rules/windows/file/file_change/"


def get_sigma_rules(sigma_folder):
    for root, dirs, files in os.walk(sigma_folder):
        for filename in files:
            if filename.endswith(".yml"):
                with open(os.path.join(root, filename), "r") as f:
                    rule = yaml.safe_load(f)
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
                    log_debug(f"Mutation: {mutation}")
                    # Send the transformed rule to OpenCTI
                    response = requests.post(OPENCTI_URL, headers=OPENCTI_HEADERS, json={"query": mutation}, verify=False)
                    log_debug(f"Response: {response.text}")
                    if response.status_code == 200:
                        log_info(f"Successfully imported Sigma rule: {title}")
                    else:
                        log_error(f"Failed to import Sigma rule: {title} - {response.text}")
                    
def main():
    log_info(f"Starting Sigma import of {sigma_folder}")
    get_sigma_rules(sigma_folder)
    log_info("Sigma import completed.")

if __name__ == "__main__":
    main()