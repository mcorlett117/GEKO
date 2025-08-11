import requests
from log import log_info, log_error, log_debug
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_elastic_rules(ELASTIC_API_URL, ELASTIC_HEADERS):
    all_rules = []
    page = 1
    page_size = 100
    while True:
        params = {"page": page, "per_page": page_size}
        response = requests.get(ELASTIC_API_URL, headers=ELASTIC_HEADERS, params=params, verify=False)
        if response.status_code != 200:
            log_error(f"Failed to fetch Elastic rules: {response.text}")
            return None
        data = response.json()
        rules = data.get("data", [])
        all_rules.extend(rules)
        if len(rules) < page_size:
            break
        page += 1
    # Separate enabled rules
    enabled_rules = [rule for rule in all_rules if rule.get("enabled", True)]
    return all_rules, enabled_rules

