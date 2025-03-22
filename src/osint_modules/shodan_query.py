#!/usr/bin/env python3
import os
import shodan
import json


class ShodanQuery:
    def __init__(self, target_ips):
        """
        Initialize the ShodanQuery instance.

        :param target_ips: A list of IP addresses or a single IP address as a string.
        """
        if not isinstance(target_ips, list):
            target_ips = [target_ips]
        self.target_ips = target_ips

        self.api_key = os.getenv('SHODAN_API_KEY')
        if not self.api_key:
            raise Exception("SHODAN_API_KEY not set in environment")
        self.api = shodan.Shodan(self.api_key)

    def query(self):
        """
        Query Shodan for each IP in the list.

        :return: A dictionary with each IP as a key and the corresponding Shodan data (or error message) as its value.
        """
        results = {}
        for ip in self.target_ips:
            try:
                host = self.api.host(ip)
                results[ip] = host
            except Exception as e:
                results[ip] = {"error": str(e)}
        return results


def load_artifacts(artifacts_path):
    """
    Load the upstream artifacts from a JSON file.
    """
    try:
        with open(artifacts_path, "r") as f:
            artifacts = json.load(f)
        return artifacts
    except Exception as e:
        print(f"Error loading artifacts from {artifacts_path}: {e}")
        return []


def extract_destination_ips(artifacts):
    """
    Extract unique destination IPs from the artifacts.
    The key may have extra whitespace; we compare stripped keys.
    """
    destination_ips = set()
    for entry in artifacts:
        for key, value in entry.items():
            if key.strip() == "Destination IP" and value:
                destination_ips.add(value.strip())
    return list(destination_ips)


if __name__ == "__main__":
    # Determine the project root (assuming this script is two levels deep from the project root).
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    # Path to the artifacts JSON file produced by the firewall log parser.
    artifacts_file = os.path.join(project_root, "data", "processed", "artifacts.json")
    artifacts = load_artifacts(artifacts_file)

    # Extract unique destination IPs.
    target_ips = extract_destination_ips(artifacts)
    print(f"Extracted Destination IPs: {target_ips}")

    # Create an instance of ShodanQuery with the list of target IPs.
    query_instance = ShodanQuery(target_ips)

    # Perform Shodan queries.
    shodan_data = query_instance.query()
    print("Shodan results:")
    print(json.dumps(shodan_data, indent=4, default=str))

    # Save the Shodan results to a JSON file.
    output_file = os.path.join(project_root, "data", "processed", "shodan_data.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(shodan_data, f, indent=4, default=str)

    print(f"Shodan data saved to {output_file}")
