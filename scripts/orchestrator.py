import os
import json
import argparse
import tldextract

from src.osint_modules.whois_lookup import WhoisLookup
from src.osint_modules.shodan_query import ShodanQuery
from src.osint_modules.virustotal_lookup import VirusTotalLookup
from src.osint_modules.misp_integration import MISPIntegration


class OSINTOrchestrator:
    def __init__(self, artifacts_file, memory_file=None):
        self.artifacts_file = artifacts_file
        self.memory_file = memory_file
        self.artifacts = self.load_json(artifacts_file, expected_type=dict)
        self.memory_artifacts = self.load_json(memory_file, expected_type=dict) if memory_file else {}

    def load_json(self, path, expected_type):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if not isinstance(data, expected_type):
                print(f"Warning: {path} does not contain a {expected_type.__name__}. Proceeding with empty data.")
                return expected_type()
            return data
        except Exception as e:
            print(f"Error loading JSON from {path}: {e}")
            return expected_type()

    def extract_iocs(self):
        ips = list(set(self.artifacts.get("ips", [])))
        raw_domains = self.artifacts.get("domains", [])
        base_domains = set()
        for domain in raw_domains:
            extracted = tldextract.extract(domain)
            if extracted.domain and extracted.suffix:
                base_domains.add(f"{extracted.domain}.{extracted.suffix}")
            else:
                base_domains.add(domain)
        raw_hashes = self.artifacts.get("file_hashes", [])
        file_hashes = set()
        for entry in raw_hashes:
            if isinstance(entry, dict) and "hash" in entry:
                file_hashes.add(entry["hash"])
            else:
                file_hashes.add(entry)
        processes = list(set(self.artifacts.get("processes", [])))
        return ips, list(base_domains), file_hashes, processes

    def run_osint(self, api_keys):
        ip_list, base_domains, file_hashes, process_list = self.extract_iocs()

        results = {}

        # WHOIS
        print("Running WHOIS lookups...")
        whois_results = {}
        for domain in base_domains:
            print(f"WHOIS lookup for: {domain}")
            whois_results[domain] = WhoisLookup(domain).lookup()
        results["whois"] = whois_results

        # SHODAN
        print("Running Shodan queries...")
        results["shodan"] = ShodanQuery(api_key=api_keys.get("shodan")).query_batch(ip_list)

        # VirusTotal
        print("Running VirusTotal lookups...")
        vt_lookup = VirusTotalLookup(api_key=api_keys.get("virustotal"))
        vt_results = {"domains": {}, "ips": {}, "file_hashes": {}}

        for domain in base_domains:
            print(f"VirusTotal lookup for domain: {domain}")
            vt_results["domains"][domain] = vt_lookup.lookup_domain(domain)

        for ip in ip_list:
            print(f"VirusTotal lookup for IP: {ip}")
            vt_results["ips"][ip] = vt_lookup.lookup_ip(ip)

        for h in file_hashes:
            print(f"VirusTotal lookup for file hash: {h}")
            vt_results["file_hashes"][h] = vt_lookup.lookup_file_hash(h)

        results["virustotal"] = vt_results

        # MISP
        if api_keys.get("misp_url") and api_keys.get("misp_key"):
            print("Running MISP lookups...")
            misp = MISPIntegration(api_keys.get("misp_url"), api_keys.get("misp_key"))
            results["misp"] = misp.bulk_search_domains(base_domains)
        else:
            results["misp"] = {"note": "MISP not configured."}

        # Processes (basic collection only)
        print("Collecting process list...")
        results["processes"] = {"suspicious_processes": process_list}

        return results

    def merge_artifacts(self, network_results):
        return {
            "osint_results": network_results,
            "input_iocs": self.artifacts
        }

    def run_full_forensics(self, api_keys):
        network_results = self.run_osint(api_keys)
        return self.merge_artifacts(network_results)

    def save_results(self, results, output_file):
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4, default=str)
        print(f"Results saved to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT Forensics Orchestrator")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_artifacts = os.path.join(project_root, "data", "processed", "unified_iocs.json")
    default_memory = os.path.join(project_root, "data", "forensic_artifacts", "memory_artifacts.json")
    default_output = os.path.join(project_root, "data", "processed", "combined_forensics.json")

    parser.add_argument("--artifacts", type=str, default=default_artifacts)
    parser.add_argument("--memory", type=str, default=default_memory)
    parser.add_argument("--output", type=str, default=default_output)
    parser.add_argument("--shodan_key", type=str)
    parser.add_argument("--virustotal_key", type=str)
    parser.add_argument("--misp_url", type=str)
    parser.add_argument("--misp_key", type=str)

    args = parser.parse_args()

    api_keys = {
        "shodan": args.shodan_key,
        "virustotal": args.virustotal_key,
        "misp_url": args.misp_url,
        "misp_key": args.misp_key
    }

    orchestrator = OSINTOrchestrator(args.artifacts, memory_file=args.memory)
    results = orchestrator.run_full_forensics(api_keys)
    orchestrator.save_results(results, args.output)
