#!/usr/bin/env python3
import os
import json
import tldextract


class UnifiedIOCLoader:
    def __init__(self, network_artifacts_path, memory_artifacts_path):
        """
        Initialize the UnifiedIOCLoader with paths to network and memory artifact files.

        :param network_artifacts_path: Path to the JSON file with network artifacts (e.g., firewall logs)
        :param memory_artifacts_path: Path to the JSON file with memory artifacts (e.g., from Volatility)
        """
        self.network_artifacts_path = network_artifacts_path
        self.memory_artifacts_path = memory_artifacts_path
        self.network_artifacts = {}
        self.memory_artifacts = {}
        self.unified_iocs = {}

    def load_json(self, filepath):
        """Generic method to load a JSON file."""
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return None
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON from {filepath}: {e}")
            return None

    def load_artifacts(self):
        """Load both network and memory artifacts."""
        self.network_artifacts = self.load_json(self.network_artifacts_path)
        if self.network_artifacts is None:
            self.network_artifacts = []
        self.memory_artifacts = self.load_json(self.memory_artifacts_path)
        if self.memory_artifacts is None:
            self.memory_artifacts = {}

    def extract_network_iocs(self):
        """
        Extract IPs and domains from network artifacts.
        Assumes network artifacts is a list of dictionary entries.
        """
        ips = set()
        domains = set()

        for entry in self.network_artifacts:
            for key, value in entry.items():
                if key.strip() == "Destination IP" and value:
                    ips.add(value.strip().lower())
                if key.strip() == "Destination Domain" and value:
                    # Normalize domain using tldextract
                    extracted = tldextract.extract(value.strip().lower())
                    if extracted.domain and extracted.suffix:
                        domains.add(f"{extracted.domain}.{extracted.suffix}")
                    else:
                        domains.add(value.strip().lower())
        return {"ips": list(ips), "domains": list(domains)}

    def extract_memory_iocs(self):
        """
        Extract IOCs from memory artifacts.
        For this example, we extract:
          - File hashes from drivers
          - Process names from process_list
          - Remote IPs from network_connections
        """
        file_hashes = set()
        processes = set()
        mem_net_ips = set()

        # Extract processes from memory artifact's process_list
        for proc in self.memory_artifacts.get("process_list", []):
            name = proc.get("name")
            if name:
                processes.add(name.strip().lower())

        # Extract file hashes from drivers and their referenced DLLs
        for driver in self.memory_artifacts.get("drivers", []):
            md5 = driver.get("md5sum")
            if md5:
                file_hashes.add(md5.strip().lower())
            for ref in driver.get("references", []):
                ref_md5 = ref.get("md5sum")
                if ref_md5:
                    file_hashes.add(ref_md5.strip().lower())

        # Extract remote IPs from network connections
        for conn in self.memory_artifacts.get("network_connections", []):
            remote = conn.get("remote_address")
            if remote:
                # Assume format "IP:Port"
                ip = remote.split(":")[0]
                mem_net_ips.add(ip.strip().lower())

        return {"file_hashes": list(file_hashes), "processes": list(processes), "memory_network_ips": list(mem_net_ips)}

    def merge_iocs(self, network_iocs, memory_iocs):
        """
        Merge network IOCs and memory IOCs into a unified dictionary.
        """
        unified = {}
        # Merge IPs from network artifacts and memory (remote connections)
        unified["ips"] = list(set(network_iocs.get("ips", [])) | set(memory_iocs.get("memory_network_ips", [])))
        # Domains come only from network artifacts in this example
        unified["domains"] = network_iocs.get("domains", [])
        unified["file_hashes"] = memory_iocs.get("file_hashes", [])
        unified["processes"] = memory_iocs.get("processes", [])
        return unified

    def run(self):
        """Run the full pipeline: load, extract, merge, and return unified IOCs."""
        self.load_artifacts()
        network_iocs = self.extract_network_iocs()
        memory_iocs = self.extract_memory_iocs()
        self.unified_iocs = self.merge_iocs(network_iocs, memory_iocs)
        return self.unified_iocs

    def save_unified_iocs(self, output_path):
        """Save the unified IOCs to a JSON file."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        try:
            with open(output_path, "w") as f:
                json.dump(self.unified_iocs, f, indent=4)
            print(f"Unified IOCs saved to {output_path}")
        except Exception as e:
            print(f"Error saving unified IOCs: {e}")


if __name__ == "__main__":
    # Define file paths based on your new project structure:
    # Network artifacts: data/processed/artifacts.json
    # Memory artifacts: data/forensic_artifacts/memory_artifacts.json
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    network_path = os.path.join(project_root, "data", "processed", "firewall_artifacts.json")
    memory_path = os.path.join(project_root, "data", "forensic_artifacts", "memory_artifacts.json")
    output_path = os.path.join(project_root, "data", "processed", "unified_iocs.json")

    loader = UnifiedIOCLoader(network_artifacts_path=network_path, memory_artifacts_path=memory_path)
    unified_iocs = loader.run()

    print("Unified IOCs:")
    print(json.dumps(unified_iocs, indent=4))

    loader.save_unified_iocs(output_path)
