#!/usr/bin/env python3
import json
import os
from datetime import datetime


class MemoryArtifactsLoader:
    def __init__(self, filepath):
        """
        Initialize the loader with the path to the memory artifacts JSON file.

        :param filepath: Path to the JSON file containing memory artifacts.
        """
        self.filepath = filepath
        self.data = {}

    def load(self):
        """
        Load the memory artifacts JSON file.

        :return: Dictionary containing memory artifacts if successful, else an empty dict.
        """
        if not os.path.exists(self.filepath):
            print(f"File not found: {self.filepath}")
            return {}
        try:
            with open(self.filepath, "r") as f:
                self.data = json.load(f)
            self.normalize()
            return self.data
        except Exception as e:
            print(f"Error loading memory artifacts: {e}")
            return {}

    def normalize(self):
        """
        Normalize the memory artifacts data.
        - Clean up empty or stray keys.
        - Convert timestamps (if available) to datetime objects for consistency.
        - Ensure key indicators like process names, file hashes, and network connections are in expected formats.
        """
        # Normalize image_info timestamp, if present
        image_info = self.data.get("image_info", {})
        timestamp_str = image_info.get("timestamp")
        if timestamp_str:
            try:
                image_info["timestamp_dt"] = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S UTC")
            except Exception as e:
                print(f"Error parsing image_info timestamp: {e}")
        self.data["image_info"] = image_info

        # Normalize process_list timestamps
        process_list = self.data.get("process_list", [])
        for proc in process_list:
            ts = proc.get("start_time")
            if ts:
                try:
                    proc["start_time_dt"] = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S UTC")
                except Exception as e:
                    print(f"Error parsing process start_time for PID {proc.get('pid')}: {e}")
        self.data["process_list"] = process_list

        # Optionally, you can normalize other fields as needed (e.g., network connection times)
        # For instance, converting connection_time fields into datetime objects:
        connections = self.data.get("network_connections", [])
        for conn in connections:
            conn_ts = conn.get("connection_time")
            if conn_ts:
                try:
                    conn["connection_time_dt"] = datetime.strptime(conn_ts, "%Y-%m-%d %H:%M:%S UTC")
                except Exception as e:
                    print(f"Error parsing connection time for PID {conn.get('pid')}: {e}")
        self.data["network_connections"] = connections

        # Remove stray empty keys if necessary
        if "" in self.data.get("image_info", {}):
            del self.data["image_info"][""]

        # Return normalized data (optional, as data is stored in self.data)
        return self.data


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    log_file_path = os.path.join(project_root, "data", "forensic_artifacts", "memory_artifacts.json")
    # Example usage:
    loader = MemoryArtifactsLoader(log_file_path)
    memory_data = loader.load()
    print("Loaded Memory Artifacts:")
    print(json.dumps(memory_data, indent=4, default=str))
