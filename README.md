# GEKO: Threat-Informed Detection Engine 🦎

An automated engine for creating a threat-informed detection lifecycle by integrating **G**it, **E**lasticsearch, **K**ibana, and **O**penCTI.

![Project Status](https://img.shields.io/badge/status-in%20development-blue)
![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)

---

## About The Project

GEKO is designed to bridge the gap between threat intelligence and security operations. It automates the process of mapping your active detection rules in Elasticsearch against the known tactics, techniques, and procedures (TTPs) of threat actors cataloged in OpenCTI.

The core goal is to provide a clear, data-driven view of your detection coverage, identify critical gaps, and prioritize detection engineering efforts based on relevant threats.

### Architecture Overview

The system operates on a local Docker-based stack for development, integrating with GitHub for version control and threat intelligence sourcing.

```mermaid
graph TD
    subgraph "Local Windows Machine"
        direction LR
        A1[VS Code]
        A2["Python Scripts (src/)"]
        A3[".env File (Secrets)"]
        A4["Python venv (Libraries)"]
        A5[Git Client]

        A1 <--> A2
        A2 -- Reads from --> A3
        A2 -- Uses --> A4
        A5 -- Manages --> A2
    end

    subgraph "GitHub (Cloud)"
        B1["GEKO Project Repo (Private)"]
        B2["Fork of SigmaHQ Repo"]
    end

    subgraph "OpenCTI Platform"
        C1[OpenCTI Server]
    end

    subgraph "Elastic Stack (SIEM)"
        D1[Elasticsearch]
        D2[Kibana]
        D1 <--> D2
    end

    A5 -- "git push/pull (Code)" --> B1;
    A2 -- "1. Queries Threat Intel" --> C1;
    A2 -- "2. Queries Rule Coverage" --> D1;
    C1 -- "Imports Sigma Rules" --> B2;
    D2 -- "Presents Dashboards" --> E1((You, the Engineer));