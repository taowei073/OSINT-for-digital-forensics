#!/usr/bin/env python3
import os
import json
import argparse
import tldextract

from src.osint_modules.whois_lookup import WhoisLookup
from src.osint_modules.shodan_query import ShodanQuery
from src.osint_modules.virustotal_lookup import VirusTotalLookup
from src.osint_modules.misp_integration import MISPIntegration  # Optional: if you want to include MISP


class OSINTOrchestrator:
    def __init__(self, artifacts_file, memory_file=None):
        """
        Initialize the orchestrator with network artifacts and optionally memory artifacts.

        :param artifacts_file: Path to the JSON file with network artifacts (e.g., firewall logs).
        :param memory_file: Path to the JSON file with memory artifacts (e.g., memory dump analysis).
        """
        self.artifacts_file = artifacts_file
        self.memory_file = memory_file
        self.artifacts = self.load_artifacts()
        if memory_file:
            self.memory_artifacts = self.load_memory_artifacts(memory_file)
        else:
            self.memory_artifacts = {}

    def load_artifacts(self):
        """
        Load the network artifacts JSON file.
        Expects a list of dictionaries.
        """
        try:
            with open(self.artifacts_file, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                print("Warning: firewall_artifacts.json does not contain a list. Proceeding with empty data.")
                return []
            return data
        except Exception as e:
            print(f"Error loading artifacts from {self.artifacts_file}: {e}")
            return []

    def load_memory_artifacts(self, memory_file):
        """
        Load the memory artifacts JSON file.
        Expects a dictionary.
        """
        try:
            with open(memory_file, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                print("Warning: memory_artifacts.json does not contain a dictionary. Proceeding with empty data.")
                return {}
            return data
        except Exception as e:
            print(f"Error loading memory artifacts from {memory_file}: {e}")
            return {}

    def extract_unique_ips(self):
        """
        Extract unique 'Destination IP' values from each network artifact entry.
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
        Uses tldextract to get the base domain.
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
        Run OSINT lookups for network artifacts:
          - WHOIS lookup for each unique base domain.
          - Shodan query for each unique destination IP.
          - VirusTotal lookup for each domain.
          - Optionally, MISP search for each domain.
        :param api_keys: Dict containing API keys (e.g., {"shodan": "KEY", "virustotal": "KEY", "misp_url": "...", "misp_key": "..."})
        :return: Dictionary with OSINT results for network artifacts.
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

        # Optionally, perform a MISP search for domains.
        misp_results = {}
        if api_keys.get("misp_url") and api_keys.get("misp_key"):
            print("Running MISP searches for domains")
            misp_integration = MISPIntegration(args.misp_url, args.misp_key, False)
            for domain in domain_list:
                print(f"Running MISP search for domain: {domain}")
                misp_results[domain] = misp_integration.search_domain(domain)
            results["misp"] = misp_results
        else:
            results["misp"] = {"note": "MISP URL/API key not provided"}

        return results

    def merge_artifacts(self, network_results):
        """
        Merge network OSINT results with memory forensic artifacts.
        :param network_results: OSINT results from network artifacts.
        :return: Combined dictionary.
        """
        combined = {
            "osint_network": network_results,
            "memory_artifacts": self.memory_artifacts
        }
        return combined

    def run_full_forensics(self, api_keys):
        """
        Run OSINT on network artifacts and merge with memory artifacts.
        :param api_keys: Dict containing API keys.
        :return: Combined forensic results.
        """
        network_results = self.run_osint(api_keys)
        combined_results = self.merge_artifacts(network_results)
        return combined_results

    def save_results(self, results, output_file):
        """
        Save the combined forensic results to a JSON file.
        """
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4, default=str)
        print(f"Combined forensic results saved to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT Forensics Orchestrator")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_artifacts = os.path.join(project_root, "data", "processed", "unifiled_iocs.json")
    default_memory = os.path.join(project_root, "data", "forensic_artifacts", "memory_artifacts.json")
    default_output = os.path.join(project_root, "data", "processed", "combined_forensics.json")

    parser.add_argument("--artifacts", type=str, default=default_artifacts, help="Path to network artifacts JSON")
    parser.add_argument("--memory", type=str, default=default_memory, help="Path to memory artifacts JSON")
    parser.add_argument("--output", type=str, default=default_output, help="Path to save the combined forensic results")
    parser.add_argument("--shodan_key", type=str, default=None, help="Shodan API key")
    parser.add_argument("--virustotal_key", type=str, default=None, help="VirusTotal API key")
    parser.add_argument("--misp_url", type=str, default=None, help="MISP API URL (e.g., https://192.168.x.x)")
    parser.add_argument("--misp_key", type=str, default=None, help="MISP API key")

    args = parser.parse_args()

    if args.shodan_key:
        os.environ["SHODAN_API_KEY"] = args.shodan_key

    orchestrator = OSINTOrchestrator(args.artifacts, memory_file=args.memory)
    results = orchestrator.run_full_forensics(api_keys={
        "shodan": args.shodan_key,
        "virustotal": args.virustotal_key,
        "misp_url": args.misp_url,
        "misp_key": args.misp_key
    })
    orchestrator.save_results(results, args.output)
