#!/usr/bin/env python3
import os
import re
import json


class FirewallLogParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.artifacts = {
            'ips': set(),
            'domains': set(),
            'emails': set()
        }
        # Regex patterns to match IP addresses, domains, and email addresses
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        self.email_pattern = re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w+\b')

    def parse(self):
        try:
            abs_path = os.path.abspath(self.file_path)
            print(f"Attempting to open file: {abs_path}")
            with open(self.file_path, 'r') as f:
                for line in f:
                    ips = self.ip_pattern.findall(line)
                    domains = self.domain_pattern.findall(line)
                    emails = self.email_pattern.findall(line)
                    self.artifacts['ips'].update(ips)
                    self.artifacts['domains'].update(domains)
                    self.artifacts['emails'].update(emails)
            return {
                'ips': list(self.artifacts['ips']),
                'domains': list(self.artifacts['domains']),
                'emails': list(self.artifacts['emails'])
            }
        except Exception as e:
            print(f"Error reading file {self.file_path}: {str(e)}")
            return None


if __name__ == "__main__":
    # Calculate the project root by going up two levels from the current script location.
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    # Construct the path to the firewall log relative to the project root.
    log_file_path = os.path.join(project_root, "data", "forensic_artifacts", "firewall.log")

    parser = FirewallLogParser(log_file_path)
    artifacts = parser.parse()
    # print("Extracted Artifacts:")
    # print(artifacts)

    output_file = os.path.join(project_root,"data", "processed","artifacts.json")

    with open(output_file, "w") as f:
        json.dump(artifacts, f, indent=4)
