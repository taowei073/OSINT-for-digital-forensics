#!/usr/bin/env python3
import os
import shodan
import json

class ShodanQuery:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.api_key = os.getenv('SHODAN_API_KEY')
        if not self.api_key:
            raise Exception("SHODAN_API_KEY not set in environment")
        self.api = shodan.Shodan(self.api_key)

    def query(self):
        try:
            host = self.api.host(self.target_ip)
            return host
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    target_ip = "8.8.8.8"
    query = ShodanQuery(target_ip)
    shodan_data = query.query()
    print(f"Shodan result for {target_ip}:")
    print(shodan_data)


    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    output_file = os.path.join(project_root, "data", "processed", "shodan_data.json")
    with open(output_file, "w") as f:
        # os.makedirs(os.path.dirname(output_file), exist_ok=True)
        json.dump(shodan_data, f, indent=4, default=str)

    print(f"WHOIS data saved to {output_file}")