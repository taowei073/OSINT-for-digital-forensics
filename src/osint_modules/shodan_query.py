#!/usr/bin/env python3
import os
import json
import shodan


class ShodanQuery:
    def __init__(self, api_key):
        """
        Initialize the ShodanQuery instance with API key.
        """
        self.api_key = api_key or os.getenv('SHODAN_API_KEY')
        if not self.api_key:
            raise ValueError("Shodan API key is required.")
        self.api = shodan.Shodan(self.api_key)

    def query_ip(self, ip):
        """
        Query Shodan for a single IP.
        """
        try:
            return self.api.host(ip)
        except Exception as e:
            return {"error": str(e)}

    def query_batch(self, ip_list):
        """
        Query Shodan for a list of IPs.
        """
        results = {}
        for ip in ip_list:
            print(f"Querying Shodan for: {ip}")
            results[ip] = self.query_ip(ip)
        return results


class ShodanBatchProcessor:
    def __init__(self, unified_iocs_path, output_path, api_key=None):
        self.unified_iocs_path = unified_iocs_path
        self.output_path = output_path
        self.api_key = api_key
        self.ip_list = []
        self.results = {}

    def load_ips_from_unified_iocs(self):
        """
        Load IPs from unified_iocs.json
        """
        if not os.path.exists(self.unified_iocs_path):
            raise FileNotFoundError(f"File not found: {self.unified_iocs_path}")
        try:
            with open(self.unified_iocs_path, "r") as f:
                data = json.load(f)
            self.ip_list = list(set(data.get("ips", [])))
        except Exception as e:
            raise RuntimeError(f"Error reading unified IOCs: {e}")

    def run_queries(self):
        """
        Run batch Shodan queries and store results.
        """
        shodan_query = ShodanQuery(self.api_key)
        self.results = shodan_query.query_batch(self.ip_list)

    def save_results(self):
        """
        Save results to output path.
        """
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, "w") as f:
            json.dump(self.results, f, indent=4, default=str)
        print(f"Shodan results saved to {self.output_path}")

    def run(self):
        self.load_ips_from_unified_iocs()
        self.run_queries()
        self.save_results()


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    unified_iocs_path = os.path.join(project_root, "data", "processed", "unified_iocs.json")
    output_path = os.path.join(project_root, "data", "processed", "shodan_data.json")

    api_key = os.getenv("SHODAN_API_KEY")

    processor = ShodanBatchProcessor(unified_iocs_path, output_path, api_key)
    processor.run()
