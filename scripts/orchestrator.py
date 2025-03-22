#!/usr/bin/env python3
import os
import json
import argparse
import tldextract

from src.osint_modules.whois_lookup import WhoisLookup
from src.osint_modules.shodan_query import ShodanQuery
from src.osint_modules.virustotal_lookup import VirusTotalLookup
from src.osint_modules.misp_integration import MISPIntegration  # New module for MISP

class OSINTOrchestrator:
    def __init__(self, artifacts_file):
        self.artifacts_file = artifacts_file
        self.artifacts = self.load_artifacts()

    def load_artifacts(self):
        """
        Load the JSON file containing the extracted artifacts.
        Expects a list of dictionaries (each a firewall log entry).
        """
        try:
            with open(self.artifacts_file, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                print("Warning: artifacts.json does not contain a list. Proceeding with empty data.")
                return []
            return data
        except Exception as e:
            print(f"Error loading artifacts from {self.artifacts_file}: {e}")
            return []

    def extract_unique_ips(self):
        """
        Extract unique 'Destination IP' values from each artifact entry.
        """
        ips = set()
        for entry in self.artifacts:
            for key, value in entry.items():
                if key.strip() == "Destination IP" and value:
                    ips.add(value.strip())
        return list(ips)

    def extract_unique_domains(self):
        """
        Extract unique base domains from 'Destination Domain' fields.
        Uses tldextract to extract the base domain.
        """
        domains = set()
        for entry in self.artifacts:
            for key, value in entry.items():
                if key.strip() == "Destination Domain" and value:
                    base_domain = self._get_base_domain(value.strip())
                    domains.add(base_domain)
        return list(domains)

    def _get_base_domain(self, domain_str):
        """
        Use tldextract to reliably extract the base domain.
        E.g., 'masterpoldo02.kozow.com' -> 'kozow.com'
        """
        extracted = tldextract.extract(domain_str)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        else:
            return domain_str

    def run_osint(self, api_keys):
        """
        Orchestrate OSINT lookups:
          - WHOIS lookup for each unique base domain.
          - Shodan query for each unique destination IP.
          - VirusTotal lookup for each domain.
          - MISP lookup for each domain.
        :param api_keys: Dict containing API keys and parameters (e.g., {"shodan": "KEY", "virustotal": "KEY", "misp_url": "URL", "misp_key": "KEY"}).
        :return: Dictionary containing combined OSINT results.
        """
        ip_list = self.extract_unique_ips()
        domain_list = self.extract_unique_domains()

        results = {}

        # WHOIS lookups for domains.
        whois_results = {}
        for domain in domain_list:
            print(f"Running WHOIS lookup for domain: {domain}")
            whois_info = WhoisLookup(domain).lookup()
            whois_results[domain] = whois_info
        results["whois"] = whois_results

        # Shodan queries for IPs.
        if ip_list:
            print(f"Running Shodan query for IPs: {ip_list}")
            try:
                shodan_info = ShodanQuery(ip_list).query()
                results["shodan"] = shodan_info
            except Exception as e:
                results["shodan"] = {"error": str(e)}
        else:
            results["shodan"] = {"note": "No IPs found to query"}

        # VirusTotal lookups for domains.
        vt_results = {}
        for domain in domain_list:
            print(f"Running VirusTotal lookup for domain: {domain}")
            vt_lookup = VirusTotalLookup(domain, api_key=api_keys.get("virustotal"))
            vt_results[domain] = vt_lookup.lookup()
        results["virustotal"] = vt_results

        # MISP queries for domains.
        misp_results = {}
        if api_keys.get("misp_url") and api_keys.get("misp_key"):
            try:
                misp_integration = MISPIntegration(args.misp_url, args.misp_key, False)
                for domain in domain_list:
                    print(f"Running MISP search for domain: {domain}")
                    misp_results[domain] = misp_integration.search_domain(domain)
            except Exception as e:
                misp_results = {"error": str(e)}
        else:
            misp_results = {"note": "MISP URL/API key not provided"}
        results["misp"] = misp_results

        return results

    def save_results(self, results, output_file):
        """
        Save the OSINT results to a JSON file.
        """
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4, default=str)
        print(f"OSINT results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT Orchestrator")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    parser.add_argument(
        "--artifacts",
        type=str,
        default=os.path.join(project_root, "data", "processed", "artifacts.json"),
        help="Path to the JSON file containing extracted artifacts"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(project_root, "data", "processed", "osint_results.json"),
        help="Path to save the OSINT results"
    )
    parser.add_argument("--shodan_key", type=str, default=None, help="Shodan API key")
    parser.add_argument("--virustotal_key", type=str, default=None, help="VirusTotal API key")
    parser.add_argument("--misp_url", type=str, default="https://192.168.142.138", help="MISP API URL (e.g., https://192.168.x.x)")
    parser.add_argument("--misp_key", type=str, default="4KrZOqmVyudoWr4lLBCQLqFpbuoziR4BsZOzjx3f", help="MISP API key")

    args = parser.parse_args()

    # Set API keys in environment if provided (if your modules rely on env variables)
    if args.shodan_key:
        os.environ["SHODAN_API_KEY"] = args.shodan_key

    orchestrator = OSINTOrchestrator(args.artifacts)
    results = orchestrator.run_osint(api_keys={
        "shodan": args.shodan_key,
        "virustotal": args.virustotal_key,
        "misp_url": args.misp_url,
        "misp_key": args.misp_key
    })
    orchestrator.save_results(results, args.output)
