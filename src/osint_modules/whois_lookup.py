#!/usr/bin/env python3
import whois
import os
import json


class WhoisLookup:
    def __init__(self, domain):
        self.domain = domain

    def lookup(self):
        try:
            info = whois.whois(self.domain)
            return info
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    domain = "example.com"
    lookup = WhoisLookup(domain)
    whois_data = lookup.lookup()
    # print(f"Whois info for {domain}:")
    # print(info)

    # Specify the output file path
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    output_file = os.path.join(project_root, "data", "processed", "whois_data.json")
    with open(output_file, "w") as f:
        # os.makedirs(os.path.dirname(output_file), exist_ok=True)
        json.dump(whois_data, f, indent=4, default=str)

    print(f"WHOIS data saved to {output_file}")