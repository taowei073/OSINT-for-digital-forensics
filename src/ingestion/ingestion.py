#!/usr/bin/env python3
import os
import csv
import json


class FirewallLogParser:
    def __init__(self, file_path):
        """
        Initialize the parser with the CSV log file.
        """
        self.file_path = file_path
        self.entries = []

    def parse(self):
        """
        Parse the CSV log file and extract key forensic fields.
        Expected CSV header:
        Timestamp, Workstation, Source IP, Destination Domain, Destination IP, Destination Port, Bytes, Action
        """
        try:
            abs_path = os.path.abspath(self.file_path)
            print(f"Attempting to open file: {abs_path}")
            with open(self.file_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Normalize the "Bytes" field to an integer representing bytes
                    bytes_str = row.get("Bytes", "").strip()
                    row["Bytes"] = self._convert_bytes(bytes_str)
                    self.entries.append(row)
            return self.entries
        except Exception as e:
            print(f"Error reading file {self.file_path}: {str(e)}")
            return None

    def _convert_bytes(self, bytes_str):
        """
        Convert a string like "120 KB", "500 MB", or "1024" to a number of bytes.
        Returns a float representing the number of bytes.
        """
        try:
            if not bytes_str:
                return 0
            # Lowercase for easier matching
            lower_str = bytes_str.lower()
            if "kb" in lower_str:
                value = float(lower_str.replace("kb", "").strip()) * 1024
            elif "mb" in lower_str:
                value = float(lower_str.replace("mb", "").strip()) * 1024 * 1024
            elif "gb" in lower_str:
                value = float(lower_str.replace("gb", "").strip()) * 1024 * 1024 * 1024
            else:
                # Assume it's already in bytes or a simple number
                value = float(bytes_str)
            return value
        except Exception as e:
            print(f"Error converting bytes value '{bytes_str}': {e}")
            return bytes_str


if __name__ == "__main__":
    # Calculate the project root by going up two levels from the current script location.
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    # Construct the path to the firewall log relative to the project root.
    log_file_path = os.path.join(project_root, "data", "forensic_artifacts", "firewall.log")

    parser = FirewallLogParser(log_file_path)
    entries = parser.parse()

    if entries is not None:
        output_file = os.path.join(project_root, "data", "processed", "artifacts.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(entries, f, indent=4)

        print("Extracted Entries:")
        print(json.dumps(entries, indent=4))
    else:
        print("No entries were extracted.")
