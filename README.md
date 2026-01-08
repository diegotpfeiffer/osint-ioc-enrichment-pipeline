# OSINT IOC Enrichment Pipeline

## Overview

This project demonstrates a basic but realistic OSINT and Cyber Threat Intelligence (CTI) enrichment pipeline similar to those used in SOC, CTI, and threat research environments.

The tool automates the process of:

* Collecting data from **public web sources**
* Extracting **Indicators of Compromise (IOCs)**
* Normalizing and de-duplicating IOCs
* Enriching IOCs using **public threat-intelligence APIs**
* Exporting structured results for analysis

This repository is intended for **educational and professional demonstration purposes only**.

---


## Features

* Public web scraping (read-only)
* IOC extraction (IP, domain, hash)
* De-duplication and normalization
* Modular enrichment architecture
* Integration with AbuseIPDB (community API)
* Rate-limit awareness
* Command-line interface (CLI)
* JSON output for easy ingestion

---

## Project Structure

```
osint-ioc-enrichment-pipeline/
├── src/
│   └── pipeline.py
├── requirements.txt
├── config.example.env
├── output/
│   └── sample_output.json
├── README.md
└── LICENSE
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOURUSERNAME/osint-ioc-enrichment-pipeline.git
cd osint-ioc-enrichment-pipeline
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Keys

Create a `.env` file (or export environment variables):

```bash
export ABUSEIPDB_API_KEY=your_api_key_here
```

---

## Usage

Run the pipeline against one or more public URLs:

```bash
python src/pipeline.py --urls https://example.com/report1 https://example.com/report2 --out output/results.json
```

### Output

The tool produces structured JSON output containing:

* IOC value
* IOC type
* Source URL
* Enrichment data (if available)

---

## Example Output

```json
{
  "ioc": "8.8.8.8",
  "type": "ipv4",
  "source": "https://example.com/report",
  "enrichment": {
    "abuseConfidenceScore": 0,
    "countryCode": "US",
    "usageType": "Public DNS"
  }
}
```

---

## Author

Created by Diego Pfeiffer as a demonstration of OSINT automation and CTI-oriented Python development.

---

## Disclaimer

This project is for educational and research purposes only and is not intended for operational use against live targets.
