#!/usr/bin/env python3
import os
import json
import requests
import tldextract


class VirusTotalLookup:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/domains/"
        if not self.api_key:
            raise ValueError("VirusTotal API key is required.")

    def lookup_domain(self, domain):
        """
        Query VirusTotal API for a single domain.
        """
        url = self.base_url + domain
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "response": response.text}
        except Exception as e:
            return {"error": str(e)}


class VirusTotalBatchProcessor:
    def __init__(self, unified_iocs_path, output_path, api_key=None):
        self.unified_iocs_path = unified_iocs_path
        self.output_path = output_path
        self.api_key = api_key
        self.domains = set()
        self.results = {}

    def load_domains(self):
        """
        Load domain list from unified IOCs and normalize with tldextract.
        """
        if not os.path.exists(self.unified_iocs_path):
            raise FileNotFoundError(f"File not found: {self.unified_iocs_path}")
        try:
            with open(self.unified_iocs_path, "r") as f:
                data = json.load(f)
            for domain in data.get("domains", []):
                extracted = tldextract.extract(domain.strip())
                if extracted.domain and extracted.suffix:
                    base = f"{extracted.domain}.{extracted.suffix}"
                    self.domains.add(base)
                else:
                    self.domains.add(domain.strip())
        except Exception as e:
            raise RuntimeError(f"Error loading unified IOCs: {e}")

    def run_lookups(self):
        """
        Perform batch lookups using the VirusTotal API.
        """
        vt = VirusTotalLookup(self.api_key)
        for domain in sorted(self.domains):
            print(f"Querying VirusTotal for: {domain}")
            self.results[domain] = vt.lookup_domain(domain)

    def save_results(self):
        """
        Save VirusTotal results to a JSON file.
        """
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"VirusTotal results saved to {self.output_path}")

    def run(self):
        self.load_domains()
        self.run_lookups()
        self.save_results()


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    unified_iocs_path = os.path.join(project_root, "data", "processed", "unified_iocs.json")
    output_path = os.path.join(project_root, "data", "processed", "virustotal_data.json")

    vt_processor = VirusTotalBatchProcessor(
        unified_iocs_path=unified_iocs_path,
        output_path=output_path,
        api_key=os.getenv("VIRUSTOTAL_API_KEY")
    )
    vt_processor.run()
