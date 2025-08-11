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
