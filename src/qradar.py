# You need: requests library (`pip install requests`)
import requests

QRADAR_HOSTS = [
    'https://<your-qradar-host1>',
    'https://<your-qradar-host2>',
    # Add more hosts as needed
]
AUTH_TOKEN = '<your-auth-token>'  # Get this from QRadar

headers = {
    'SEC': AUTH_TOKEN,
    'Accept': 'application/json'
}

def get_qradar_rules(host):
    url = f"{host}/api/rules"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        rules = response.json()
        print(f"Rules from {host}:")
        for rule in rules:
            print(f"Rule Name: {rule.get('name')}")
            print(f"Rule ID: {rule.get('id')}")
            print(f"Type: {rule.get('type')}")
            print('-' * 40)
    else:
        print(f"Error from {host}: {response.status_code} - {response.text}")

if __name__ == "__main__":
    for host in QRADAR_HOSTS:
        get_qradar_rules(host)