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
ELASTIC_API_URL = os.getenv("ELASTIC_API_URL")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")

OPENCTI_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_TOKEN}",
    "Content-Type": "application/json"
}

sigma_folder = f"../sigma/rules/windows/file/file_change/"


def get_sigma_rules(sigma_folder):
    sigma_rules = []
    for root, dirs, files in os.walk(sigma_folder):
        for filename in files:
            if filename.endswith(".yml"):
                with open(os.path.join(root, filename), "r") as f:
                    rule = yaml.safe_load(f)
                    sigma_rules.append(rule)
    return sigma_rules


def sigmatoopencti(sigma_rules):
    for rule in sigma_rules:
        # Transform Sigma rule to OpenCTI format
        mutation = f"""
        mutation {{
            createIndicator(input: {{
                name: "[SIGMA] - {rule.get('title')}",
                description: "{rule.get('description')}",
                pattern: "{json.dumps(rule)}",
                type: "indicator"
            }}) {{
                id
            }}
        }}
        """
        log_debug(f"Transformed rule: {mutation}")
        # Send the transformed rule to OpenCTI
        response = requests.post(f"{OPENCTI_URL}/graphql", headers=OPENCTI_HEADERS, json=mutation)
        if response.status_code == 201:
            log_info(f"Successfully imported Sigma rule: {rule.get('title')}")
        else:
            log_error(f"Failed to import Sigma rule: {rule.get('title')} - {response.text}")


def main():
    log_debug(sigma_folder)
    log_info("Starting Sigma import...")
    sigma_rules = get_sigma_rules(sigma_folder)
    log_debug(f"Found {len(sigma_rules)} Sigma rules in {sigma_folder}")
    log_info(f"Retrieved {len(sigma_rules)} Sigma rules.")
    log_debug(f"Sigma rules: {sigma_rules}")
    sigmatoopencti(sigma_rules)
    log_info("Sigma import completed.")

if __name__ == "__main__":
    main()