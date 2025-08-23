# GEKO: Threat-Informed Detection Lifecycle Engine

GEKO is an automated engine that creates a threat-informed detection lifecycle. It provides a data-driven view of your detection coverage and prioritizes detection engineering efforts based on relevant threats. GEKO bridges the gap between threat intelligence and security operations by querying your OpenCTI instance for high-priority threat actors and their associated Tactics, Techniques, and Procedures (TTPs). It then maps this threat landscape against your active detection rules in Elastic to generate a comprehensive report. This report helps security professionals understand their current coverage, identify critical gaps, and focus their rule-writing efforts where they matter most.

---

## ⚙️ How it Works

GEKO automates the following tasks:

1.  **Queries OpenCTI:** Fetches your top threat actors and their associated TTPs.
2.  **Queries Elasticsearch:** Retrieves all enabled detection rules.
3.  **Correlates Data:** Maps the TTPs from OpenCTI to the detection rules in Elasticsearch.
4.  **Generates Report:** Creates a markdown report that visualizes the detection coverage for each threat actor and their TTPs.

---
## ✨ Bonus Feature: Sigma Rule Importer

Included in the `src` directory is `importsigma.py`, a powerful utility script to quickly populate your OpenCTI instance.

* **What it does:** The script imports detection logic from **Sigma rules** directly into OpenCTI as detection rules.
* **Automatic Mapping:** It automatically reads the tags in each Sigma rule and maps it to the corresponding MITRE ATT&CK TTPs within OpenCTI. This saves you the manual effort of associating detection logic with threat behaviors.

To use it, simply clone SigmaHQ rules and update script with folder location or point to your own sigma repo.
```bash
python src/importsigma.py
```
---

## 🚀 Getting Started

There are two primary use cases for GEKO, depending on whether you have an existing Elastic and OpenCTI stack.

### Option 1: You have your own Elastic and OpenCTI

If you already have your own instances of Elasticsearch and OpenCTI, you can get started quickly:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/047741/GEKO.git
    cd GEKO
    ```
2.  **Copy the `src` folder** to your desired location.

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Configure your environment:**
    * Create a `.env` file inside the `src` directory.
    * Update the `.env` file with your OpenCTI URL, credentials, Elastic URL, credentials, and a comma-separated list of your top threat actors.

5.  **Run GEKO:**
    ```bash
    python src/main.py
    ```
    This will generate a threat report like `Example-Report.md` in the `src` directory.

### Option 2: You do not have Elastic or OpenCTI

If you dont have an existing Elastic or OpenCTI stack, you can use the provided `docker-compose.yml` to set one up.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/047741/GEKO.git
    cd GEKO
    ```
2.  **Start Elasticsearch:**
    ```bash
    docker-compose up -d es-siem
    ```
3.  **Generate a Kibana service token:** Once Elasticsearch is running, execute the following command:
    ```bash
    docker exec -it es-siem bin/elasticsearch-service-tokens create elastic/kibana kibana-token
    ```
4.  **Configure your environment:**
    * Create a `.env` file in the project root by copying `env.example`.
    * Paste the generated token into the `ELASTICSEARCH_SERVICEACCOUNT_TOKEN` variable in your `.env` file.
    * Update the `.env` file with your chosen Kibana password and OpenCTI variables (connector IDs, admin credentials, etc.).

5.  **Start the remaining services:**
    ```bash
    docker-compose up -d kibana es-opencti redis minio rabbitmq opencti-platform worker
    ```
    You can also start any additional OpenCTI connectors as required by uncommenting them in the `docker-compose.yml` file.

6.  **Run GEKO:**
    * Once you have populated OpenCTI with threat intelligence and enabled detection rules in Kibana, you can run the `main.py` script to generate your threat report.
    * Follow the steps in **Option 1** to run the script.

---

## 📄 Example Report

An example of the generated threat report can be found in [`Example-Report.md`](Example-Report.md). This report will give you an idea of the insights you can gain from GEKO.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.