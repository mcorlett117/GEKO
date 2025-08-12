# GEKO: Threat-Informed Detection Engine :lizard:

![Project Status](https://img.shields.io/badge/Status-In_development-red)

An automated engine for creating a threat-informed detection lifecycle by integrating **G**itLab, **E**lasticsearch, **K**ibana, and **O**penCTI.

![Python Version](https://img.shields.io/badge/python-3\.10+-blue) ![OpenCTI](https://img.shields.io/badge/OpenCTI-6\.7\.9+-blue) ![ElasticSearch](https://img.shields.io/badge/ElasticSearch-8\.18\.3+-blue) ![Kibana](https://img.shields.io/badge/Kibana-8\.18\.3+-blue) ![GitLab](https://img.shields.io/badge/GitLab-18\.3+-blue)


---

## About The Project

GEKO is designed to bridge the gap between threat intelligence and security operations. It automates the process of mapping your active detection rules in Elasticsearch against the known tactics, techniques, and procedures (TTPs) of threat actors cataloged in OpenCTI.

The core goal is to provide a clear, data-driven view of your detection coverage, identify critical gaps, and prioritize detection engineering efforts based on relevant threats.

## Getting Started: Full Setup Guide

Follow these phases to get a local copy of the entire stack up and running for development.

#### Prerequisites:
**OpenCTI:** You will need a up and running OpenCTI instance to query `Intrusion Set` and `Attack Patterns.`
**ElasticSearch / Kibana:** You will need this to map you current `rules` for a coverage report. 

## GitHub & Project Setup
1. Fork the Sigma Repository on GitHub.
2. Create a new private GEKO repository on GitHub.
3. Clone your GEKO repository to your local machine.
4. Create the docker-compose.yml file as detailed in this repository.
5. Create the local secrets file (.env):

    a. Create a file named .env in the project root.
    b. Fill it with the required configuration values (see `env.example`). Leave the `KIBANA_SERVICE_TOKEN` blank for now.

6. Set up the Python Environment:
    a. In a new VS Code terminal, create and activate a Python virtual environment `(python -m venv venv` then `.\venv\Scripts\activate`).
    b. Install dependencies: `pip install -r requirements.txt`.

#### Usage Instructions
**Important:** Starting the Docker Stack
Due to the security model in modern Elastic Stack, you must follow a specific multi-step process the first time you start the services.

**Step 1:** Start Elasticsearch Only
The elasticsearch-siem service must be fully running before you can generate a token for Kibana.

```bash
docker-compose up -d elasticsearch-siem
```
Wait about 60 seconds for the service to initialize and become healthy.

**Step 2:** Generate the Kibana Service Token
Execute this command in your terminal to create a security token from within the running container.

```bash
docker exec -it elasticsearch-siem bin/elasticsearch-service-tokens create elastic/kibana kibana-token
```
A JSON block will be returned. Copy the long token value.

**Step 3:** Update Your .env File
Open your .env file and paste the token you just copied as the value for `KIBANA_SERVICE_TOKEN`.

Code snippet
```
# In your .env file
KIBANA_SERVICE_TOKEN="AAEAAWVsYXN0aWMva2liYW5hL2tpYmFuYS10b2tlbg_g...rest-of-your-token..."
```
**Step 4:** Start All Remaining Services
Now you can start the rest of the stack. Kibana will use the token from the .env file to authenticate.

```bash
docker-compose up -d
```
**Note:** This multi-step process is only required for the initial setup. For subsequent runs, you can just use `docker-compose up -d` to start everything.

#### Running the GEKO Script
Once the full stack is running, you can execute the analysis script.

``` bash
# Ensure your virtual environment is active
python src/main.py
```

**Accessing the Services**
OpenCTI UI: http://localhost:8080

Kibana UI: http://localhost:5601

GitLab UI: http://gitlab.geko.local:8929 (Requires editing your local hosts file)

**Roadmap**
[x] Phase 1: Foundational Reporting

[ ] Phase 2: Centralised Visualisation

[ ] Phase 3: Full Detection-as-Code

[ ] Phase 4: Automated Validation

**License**
Distributed under the MIT License.
