#!/usr/bin/env python3
import os
import json
import requests
import tldextract


class VirusTotalLookup:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.domain_url = "https://www.virustotal.com/api/v3/domains/"
        self.ip_url = "https://www.virustotal.com/api/v3/ip_addresses/"
        self.file_url = "https://www.virustotal.com/api/v3/files/"
        if not self.api_key:
            raise ValueError("VirusTotal API key is required.")

    def _query_virustotal(self, base_url, identifier):
        url = base_url + identifier
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "response": response.text}
        except Exception as e:
            return {"error": str(e)}

    def lookup_domain(self, domain):
        return self._query_virustotal(self.domain_url, domain)

    def lookup_ip(self, ip):
        return self._query_virustotal(self.ip_url, ip)

    def lookup_file_hash(self, file_hash):
        return self._query_virustotal(self.file_url, file_hash)


class VirusTotalBatchProcessor:
    def __init__(self, unified_iocs_path, output_path, api_key=None):
        self.unified_iocs_path = unified_iocs_path
        self.output_path = output_path
        self.api_key = api_key
        self.domains = set()
        self.ips = set()
        self.file_hashes = set()
        self.results = {"domains": {}, "ips": {}, "file_hashes": {}}

    def load_iocs(self):
        if not os.path.exists(self.unified_iocs_path):
            raise FileNotFoundError(f"File not found: {self.unified_iocs_path}")
        try:
            with open(self.unified_iocs_path, "r") as f:
                data = json.load(f)
            for domain in data.get("domains", []):
                extracted = tldextract.extract(domain.strip())
                if extracted.domain and extracted.suffix:
                    self.domains.add(f"{extracted.domain}.{extracted.suffix}")
                else:
                    self.domains.add(domain.strip())
            self.ips = set(data.get("ips", []))
            self.file_hashes = set(data.get("file_hashes", []))
        except Exception as e:
            raise RuntimeError(f"Error loading unified IOCs: {e}")

    def run_lookups(self):
        vt = VirusTotalLookup(self.api_key)

        for domain in sorted(self.domains):
            print(f"Querying VirusTotal for domain: {domain}")
            self.results["domains"][domain] = vt.lookup_domain(domain)

        for ip in sorted(self.ips):
            print(f"Querying VirusTotal for IP: {ip}")
            self.results["ips"][ip] = vt.lookup_ip(ip)

        for h in sorted(self.file_hashes):
            print(f"Querying VirusTotal for file hash: {h}")
            self.results["file_hashes"][h] = vt.lookup_file_hash(h)

    def save_results(self):
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"VirusTotal results saved to {self.output_path}")

    def run(self):
        self.load_iocs()
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
