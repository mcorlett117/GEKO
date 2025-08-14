# GEKO: Threat-Informed Detection Engine :lizard:
change
![Project Status](https://img.shields.io/badge/Status-In_development-red) ![Python Version](https://img.shields.io/badge/python-3\.10+-blue)

An automated engine for creating a threat-informed detection lifecycle by integrating **G**itLab, **E**lasticsearch, **K**ibana, and **O**penCTI.

## About The Project

GEKO is designed to provide a clear, data-driven view of your detection coverage and prioritize detection engineering efforts based on relevant threats. It achieves this by bridging the gap between threat intelligence and security operations. The engine queries your OpenCTI instance for high-priority threat actors and their associated Tactics, Techniques, and Procedures (TTPs), then maps this threat landscape against your active detection rules in Elastic.

The core goal is to generate a comprehensive report that helps security professionals understand their current coverage, identify critical gaps, and focus their rule-writing efforts where they matter most.

## Getting Started: Local Setup

Follow these steps to get a local instance of the full GEKO stack running for development and testing.

#### Prerequisites
* [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
* [Docker](https://docs.docker.com/get-started/)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Installation Guide

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/047741/GEKO.git](https://github.com/047741/GEKO.git)
    cd GEKO
    ```

2.  **Create Your Environment File:**
    Create a file named `.env` in the project root and populate it with your configuration values. Refer to the `env.example` file for a template. Leave the `KIBANA_SERVICE_TOKEN` blank for now.

3.  **Start the GEKO Stack:**
    Due to the security model in modern Elastic Stack, you must follow a specific multi-step process the first time you start the services.

    * **Step 1:** Start Elasticsearch Only and wait for it to initialize (about 60 seconds).
        ```bash
        docker-compose up -d elasticsearch-siem
        ```

    * **Step 2:** Generate the Kibana Service Token.
        ```bash
        docker exec -it elasticsearch-siem bin/elasticsearch-service-tokens create elastic/kibana kibana-token
        ```
        Copy the long token value from the JSON block returned in the terminal.

    * **Step 3:** Update your `.env` file with the copied token.
        ```
        # In your .env file
        KIBANA_SERVICE_TOKEN="[your-long-token-here]"
        ```

    * **Step 4:** Start the remaining services.
        ```bash
        docker-compose up -d
        ```

### Usage Instructions

Once the full stack is running, you can execute the analysis script from a Python virtual environment.

1.  **Set up the Python Environment:**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    pip install -r requirements.txt
    ```

2.  **Run the GEKO Script:**
    ```bash
    python src/main.py
    ```

### Accessing the Services
* **OpenCTI UI:** `http://localhost:8080`
* **Kibana UI:** `http://localhost:5601`

## Roadmap

* [x] **Phase 1: Foundational Reporting**
    * Generate a strategic threat and detection coverage report.
* [ ] **Phase 2: Centralized Visualization**
    * Develop a centralized dashboard for interactive data exploration.
* [ ] **Phase 3: Automated Rule Prioritization**
    * Enable prioritizing detection efforts based on factors like country or target industry.
* [ ] **Phase 4: Full Detection-as-Code**
    * Automate the creation of detection rules from threat intelligence.

## License

Distributed under the MIT License. See `LICENSE` for more information.