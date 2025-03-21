#!/usr/bin/env python3
import os
import json
import argparse
from src.osint_modules.whois_lookup import WhoisLookup
from src.osint_modules.shodan_query import ShodanQuery
# from src.osint_modules.hibp_check import HIBPCheck

class OSINTOrchestrator:
    def __init__(self, artifacts_file):
        self.artifacts_file = artifacts_file
        self.artifacts = self.load_artifacts()

    def load_artifacts(self):
        # Load the JSON file containing the extracted artifacts.
        try:
            with open(self.artifacts_file, "r") as f:
                data = json.load(f)
            return data
        except Exception as e:
            print(f"Error loading artifacts from {self.artifacts_file}: {e}")
            return {}

    def get_target_values(self):
        # For example, select the first available value from each category.
        target_domain = self.artifacts.get("domains", [None])[0]
        target_ip = self.artifacts.get("ips", [None])[0]
        target_email = self.artifacts.get("emails", [None])[0]
        return target_domain, target_ip, target_email

    def run_osint(self, api_keys):
        target_domain, target_ip, target_email = self.get_target_values()
        results = {}

        # Run Whois Lookup if a domain exists.
        if target_domain:
            print(f"Running WHOIS lookup for: {target_domain}")
            whois_info = WhoisLookup(target_domain).lookup()
            results["whois"] = whois_info

        # Run Shodan Query if an IP exists.
        if target_ip:
            print(f"Running Shodan query for: {target_ip}")
            try:
                shodan_info = ShodanQuery(target_ip).query()
                results["shodan"] = shodan_info
            except Exception as e:
                results["shodan"] = {"error": str(e)}

        # Run HIBP Check if an email exists.
        # if target_email:
        #     print(f"Running HIBP check for: {target_email}")
        #     try:
        #         hibp_info = HIBPCheck().query_email(target_email)
        #         results["hibp"] = hibp_info
        #     except Exception as e:
        #         results["hibp"] = {"error": str(e)}
        #
        # return results

    def save_results(self, results, output_file):
        # Ensure the output directory exists.
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4, default=str)
        print(f"OSINT results saved to {output_file}")


if __name__ == "__main__":
    # Use argparse to allow specifying the artifacts file and output file.
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))

    parser = argparse.ArgumentParser(description="OSINT Orchestrator")
    parser.add_argument(
        "--artifacts", type=str, default=os.path.join(project_root, "data", "processed", "artifacts.json"),
        help="Path to the JSON file containing extracted artifacts"
    )
    parser.add_argument(
        "--output", type=str, default=os.path.join(project_root, "data", "processed", "osint_results.json"),
        help="Path to save the OSINT results"
    )
    # You can also pass API keys for various modules as needed.
    # For example, if you want to pass a Shodan API key:
    parser.add_argument("--shodan_key", type=str, default=None, help="Shodan API key")
    # parser.add_argument("--hibp_key", type=str, default=None, help="HIBP API key (if required)")

    args = parser.parse_args()

    # Update API keys in your modules if needed. For example:
    if args.shodan_key:
        os.environ["SHODAN_API_KEY"] = args.shodan_key
    # if args.hibp_key:
    #     os.environ["HIBP_API_KEY"] = args.hibp_key

    orchestrator = OSINTOrchestrator(args.artifacts)
    results = orchestrator.run_osint(api_keys={"shodan": args.shodan_key}) #, "hibp": args.hibp_key})
    orchestrator.save_results(results, args.output)
