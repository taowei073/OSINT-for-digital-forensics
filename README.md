# OSINT-for-digital-forensics

A comprehensive toolkit for digital forensics and OSINT investigations. This project merges multiple forensic data sources (firewall logs, memory artifacts, etc.), extracts and enriches IOCs, and generates a final HTML report with a timeline and threat intelligence lookups.

---

## Project Structure

```plaintext
OSINT-for-digital-forensics/
├── data
│   ├── forensic_artifacts
│   │   └── ... (e.g., memory_artifacts.json, security logs, etc.)
│   └── processed
│       └── ... (e.g., firewall_artifacts.json, unified_iocs.json)
├── reports
│   └── osint_report.html
├── scripts
│   └── orchestrator.py         # High-level script to run the entire workflow
├── src
│   ├── forensics_modules
│   │   ├── firewall_artifacts.py    # Logic for parsing/loading firewall data
│   │   ├── memory_artifacts.py      # Logic for parsing/loading memory data
│   │   └── unified_ioc_loader.py    # Merges IOCs from different sources
│   ├── osint_modules
│   │   ├── misp_integration.py      # Batch MISP lookups
│   │   ├── shodan_query.py          # Shodan lookups for IPs
│   │   ├── virustotal_lookup.py     # VirusTotal lookups for domains/hashes etc.
│   │   └── whois_lookup.py          # WHOIS lookups for domains
│   └── reporting
│       └── ... (e.g., timeline scripts, report generation)
├── .gitignore
├── README.md
└── requirements.txt
```

### Key Directories

- **data/forensic_artifacts/**  
  Stores raw forensic data such as memory dumps, CSV logs, etc.
- **data/processed/**  
  Holds processed artifacts like `firewall_artifacts.json`, `unified_iocs.json`, `combined_forensics.json`.
- **reports/**  
  Contains generated HTML (e.g., `osint_report.html`).
- **scripts/**  
  High-level or “orchestrator” scripts that chain all modules together.
- **src/forensics_modules/**  
  Python modules for parsing and extracting internal forensic data from firewall logs, memory artifacts, and merging them.
- **src/osint_modules/**  
  Python modules integrating external OSINT services (MISP, VirusTotal, Shodan, WHOIS).
- **src/reporting/**  
  Modules that handle timeline visualization, HTML report generation, etc.

---

## Features

1. **Forensic Artifact Parsing**  
   - **Firewall Logs**: Extract IPs, domains, and actions.  
   - **Memory Artifacts**: Parse processes, drivers, network connections, etc.  
   - **Unified IOC Loading**: Combine artifacts into a single JSON for correlation.

2. **OSINT Integration**  
   - **VirusTotal**: Check file hashes, domains, IPs for malicious scores.  
   - **MISP**: Query attributes for advanced threat intel.  
     - Note: The MISP test environment was set up on a virtual machine. For details on installing and configuring MISP in a VM, see the official MISP installation documentation: [Download and Install MISP](https://www.misp-project.org/download/).  
   - **Shodan**: Retrieve open ports or host info for suspicious IPs.  
   - **WHOIS**: Get domain registration details, ownership info, and registrar data.

3. **Timeline Reconstruction**  
   - Merge timestamps from multiple sources (firewall, memory, etc.).  
   - Plot an event timeline (via Matplotlib library).  

4. **HTML Report Generation**  
   - Summarize findings: IOCs, timeline, OSINT lookups (including WHOIS), suspicious processes, etc.  
   - Provide a single HTML (`osint_report.html`) for easy review.

---

## Installation

1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/OSINT-for-digital-forensics.git
cd OSINT-for-digital-forensics
```

2. **Install Dependencies**

```bash
pip install -r requirements.txt
```

Typical dependencies include: `pandas`, `matplotlib`, `jinja2`, `requests`, `PyMISP`, `tldextract`, etc.

3. **Configure Environment Variables**  
   - `VIRUSTOTAL_API_KEY`  
   - `MISP_URL`, `MISP_API_KEY`  
   - `SHODAN_API_KEY`

---

## Usage

### 1. Forensic Artifact Processing

- **Firewall Logs**: `src/forensics_modules/firewall_artifacts.py`  
- **Memory Artifacts**: `src/forensics_modules/memory_artifacts.py`  
- **Unified IOC Loader**: `src/forensics_modules/unified_ioc_loader.py` merges the above into a single JSON.

### 2. OSINT Lookups

- **VirusTotal**: `src/osint_modules/virustotal_lookup.py`  
- **MISP**: `src/osint_modules/misp_integration.py`  
- **Shodan**: `src/osint_modules/shodan_query.py`  
- **WHOIS**: `src/osint_modules/whois_lookup.py`

### 3. Timeline & Report

- **Timeline**: A script in `src/reporting/` (e.g., `timeline.py`) merges events and plots them.  
- **Report**: The final HTML (`osint_report.html`) is generated via a Jinja2 template, by a dedicated `report_generator.py`.

**Example**:

```bash
python scripts/orchestrator.py \
  --firewall data/processed/firewall_artifacts.json \
  --memory data/forensic_artifacts/memory_artifacts.json \
  --output reports/osint_report.html
```


