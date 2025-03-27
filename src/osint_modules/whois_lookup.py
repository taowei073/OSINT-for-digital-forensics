#!/usr/bin/env python3
import os
import json
import tldextract
import whois


class WhoisLookup:
    def __init__(self, domain):
        self.domain = domain.strip()

    def lookup(self):
        try:
            info = whois.whois(self.domain)
            return info
        except Exception as e:
            return {"error": str(e)}


class WhoisBatchProcessor:
    def __init__(self, unified_iocs_path, output_path):
        self.unified_iocs_path = unified_iocs_path
        self.output_path = output_path
        self.domains = set()
        self.results = {}

    def load_domains(self):
        if not os.path.exists(self.unified_iocs_path):
            raise FileNotFoundError(f"File not found: {self.unified_iocs_path}")
        try:
            with open(self.unified_iocs_path, "r") as f:
                data = json.load(f)
            raw_domains = data.get("domains", [])
            for domain in raw_domains:
                extracted = tldextract.extract(domain.strip())
                if extracted.domain and extracted.suffix:
                    base = f"{extracted.domain}.{extracted.suffix}"
                    self.domains.add(base)
                else:
                    self.domains.add(domain.strip())
        except Exception as e:
            raise RuntimeError(f"Error loading unified IOCs: {e}")

    def run_whois_lookups(self):
        for domain in sorted(self.domains):
            print(f"Performing WHOIS lookup for: {domain}")
            lookup = WhoisLookup(domain)
            self.results[domain] = lookup.lookup()

    def save_results(self):
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "w") as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"WHOIS data saved to {self.output_path}")

    def run(self):
        self.load_domains()
        self.run_whois_lookups()
        self.save_results()


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    unified_iocs_path = os.path.join(project_root, "data", "processed", "unified_iocs.json")
    output_path = os.path.join(project_root, "data", "processed", "whois_data.json")

    processor = WhoisBatchProcessor(unified_iocs_path, output_path)
    processor.run()
