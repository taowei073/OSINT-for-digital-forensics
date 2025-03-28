#!/usr/bin/env python3
import os
import json
from pymisp import PyMISP


class MISPIntegration:
    def __init__(self, misp_url, misp_key, verifycert=False):
        self.misp = PyMISP(misp_url, misp_key, verifycert, 'json')

    def search_attribute(self, attribute_type, value):
        try:
            return self.misp.search(controller='attributes', type_attribute=attribute_type, value=value)
        except Exception as e:
            return {"error": str(e)}

    def search_batch(self, domains=None, ips=None, hashes=None):
        """
        Search MISP for multiple types of indicators.
        """
        results = {"domain": {}, "ip": {}, "hash": {}}

        if domains:
            for domain in domains:
                print(f"Searching MISP for domain: {domain}")
                results["domain"][domain] = self.search_attribute("domain", domain)

        if ips:
            for ip in ips:
                print(f"Searching MISP for IP: {ip}")
                results["ip"][ip] = self.search_attribute("ip-dst", ip)

        if hashes:
            for h in hashes:
                print(f"Searching MISP for hash: {h}")
                results["hash"][h] = self.search_attribute("md5", h)

        return results


class MISPBatchProcessor:
    def __init__(self, unified_iocs_path, output_path, misp_url, misp_key, verifycert=False):
        self.unified_iocs_path = unified_iocs_path
        self.output_path = output_path
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.verifycert = verifycert
        self.iocs = {"domains": [], "ips": [], "file_hashes": []}
        self.results = {}

    def load_unified_iocs(self):
        if not os.path.exists(self.unified_iocs_path):
            raise FileNotFoundError(f"File not found: {self.unified_iocs_path}")
        try:
            with open(self.unified_iocs_path, "r") as f:
                data = json.load(f)
            self.iocs["domains"] = list(set(data.get("domains", [])))
            self.iocs["ips"] = list(set(data.get("ips", [])))

            # Extract hash values from file_hashes entries.
            raw_hashes = data.get("file_hashes", [])
            hashes = []
            for entry in raw_hashes:
                if isinstance(entry, dict) and "hash" in entry:
                    hashes.append(entry["hash"])
                else:
                    hashes.append(entry)
            self.iocs["file_hashes"] = list(set(hashes))
        except Exception as e:
            raise RuntimeError(f"Failed to load unified IOCs: {e}")

    def run_searches(self):
        misp_client = MISPIntegration(self.misp_url, self.misp_key, self.verifycert)
        self.results = misp_client.search_batch(
            domains=self.iocs["domains"],
            ips=self.iocs["ips"],
            hashes=self.iocs["file_hashes"]
        )

    def save_results(self):
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"MISP results saved to {self.output_path}")

    def run(self):
        self.load_unified_iocs()
        self.run_searches()
        self.save_results()


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    unified_iocs_path = os.path.join(project_root, "data", "processed", "unified_iocs.json")
    output_path = os.path.join(project_root, "data", "processed", "misp_data.json")

    # Load from environment or hardcode here temporarily
    misp_url = os.getenv("MISP_URL", "https://192.168.142.138")
    misp_key = os.getenv("MISP_API_KEY", "YOUR_MISP_API_KEY")  # Replace for testing

    processor = MISPBatchProcessor(
        unified_iocs_path=unified_iocs_path,
        output_path=output_path,
        misp_url=misp_url,
        misp_key=misp_key,
        verifycert=False  # Set to True if using valid TLS cert
    )
    processor.run()
