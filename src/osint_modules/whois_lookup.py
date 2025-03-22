#!/usr/bin/env python3
import whois
import os
import json


class WhoisLookup:
    def __init__(self, domain):
        # Strip any extra whitespace from the domain.
        self.domain = domain.strip()

    def lookup(self):
        try:
            info = whois.whois(self.domain)
            return info
        except Exception as e:
            return {"error": str(e)}


def extract_base_domain(domain_str):
    """
    Given a full domain (possibly with subdomains), return the base domain.
    For example: "masterpoldo02.kozow.com" -> "kozow.com"
    (Note: This is a simplistic approach; for more robust extraction, consider libraries like tldextract.)
    """
    domain_str = domain_str.strip()
    parts = domain_str.split('.')
    if len(parts) >= 2:
        # This naive method assumes the last two parts form the base domain.
        return '.'.join(parts[-2:])
    return domain_str


if __name__ == "__main__":
    # Determine the project root (assuming this script is located in scripts/)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    # Path to the artifacts JSON file produced by your firewall log parser.
    artifacts_file = os.path.join(project_root, "data", "processed", "artifacts.json")

    # Load the artifacts
    try:
        with open(artifacts_file, "r") as f:
            artifacts = json.load(f)
    except Exception as e:
        print(f"Error loading artifacts: {e}")
        artifacts = []

    # Collect unique destination domains from the artifacts.
    destination_domains = set()
    for entry in artifacts:
        for key, value in entry.items():
            if key.strip() == "Destination Domain":
                destination_domains.add(value.strip())

    # Extract base domains from the collected destination domains.
    base_domains = {extract_base_domain(d) for d in destination_domains}

    # For each base domain, perform WHOIS lookup.
    results = {}
    for domain in base_domains:
        print(f"Performing WHOIS lookup for: {domain}")
        lookup = WhoisLookup(domain)
        results[domain] = lookup.lookup()

    # Save the WHOIS results to a JSON file.
    output_file = os.path.join(project_root, "data", "processed", "whois_data.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4, default=str)

    print(f"WHOIS data saved to {output_file}")
