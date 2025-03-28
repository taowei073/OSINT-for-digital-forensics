#!/usr/bin/env python3
import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import argparse

def load_firewall_artifacts(file_path):
    """
    Load firewall artifacts from a JSON file (expected to be a list of events).
    Create a short description: "FW-1001: masterpoldo02.kozow.com ALLOW"
    and set 'Source' = 'firewall'.
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        if not isinstance(data, list):
            print(f"Warning: {file_path} does not contain a list of events.")
            return []

        enriched_events = []
        for e in data:
            event_id = e.get("EventID", "FW-???")
            domain   = e.get("DestinationDomain", e.get("Destination Domain", ""))
            action   = e.get("Action", "")
            # Example short label
            e["Description"] = f"{event_id}: {domain} {action}".strip()
            e["Source"] = "firewall"
            enriched_events.append(e)
        return enriched_events

    except Exception as ex:
        print(f"Error loading firewall artifacts from {file_path}: {ex}")
        return []

def load_security_events(file_path):
    """
    Load security events from a CSV file and convert them to a list of dicts.
    Create a short description: "SEC-2001: Logon by Alice"
    and set 'Source' = 'security'.
    """
    try:
        df = pd.read_csv(file_path)
        df.columns = [col.strip() for col in df.columns]

        if "Timestamp" not in df.columns:
            print(f"Security events CSV missing 'Timestamp' column in {file_path}.")
            return []

        # Example short description
        # If you have columns like "EventID", "User", "Action", you can combine them.
        # Here, we guess: "SEC-2002: Action=UserLogon"
        def build_desc(row):
            event_id = row.get("EventID", "SEC-???")
            action   = row.get("Action", "")
            return f"{event_id}: {action}"

        df["Description"] = df.apply(build_desc, axis=1)
        df["Source"] = "security"
        return df.to_dict(orient="records")

    except Exception as ex:
        print(f"Error loading security events from {file_path}: {ex}")
        return []

def load_memory_artifacts(file_path):
    """
    Load memory artifacts from a JSON file.
    Extract process-related events from 'process_list'.
    Create a short label like: "PID 1956: explorer.exe launched"
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        events = []
        for proc in data.get("process_list", []):
            ts   = proc.get("timestamp", "")
            pid  = proc.get("pid", "")
            name = proc.get("name", "unknown")
            event = {
                "Timestamp": ts,
                "Source": "memory",
                "Description": f"PID {pid}: {name} launched"
            }
            events.append(event)
        return events
    except Exception as ex:
        print(f"Error loading memory artifacts from {file_path}: {ex}")
        return []

def merge_events(firewall_events, security_events, memory_events):
    """
    Merge all events, parse timestamps, drop invalid, sort by time.
    """
    all_events = firewall_events + security_events + memory_events

    # Convert to datetime
    for ev in all_events:
        try:
            ev["Timestamp"] = pd.to_datetime(ev["Timestamp"], errors="coerce")
        except:
            ev["Timestamp"] = pd.NaT

    # Filter out invalid timestamps
    all_events = [ev for ev in all_events if pd.notnull(ev["Timestamp"])]

    # Sort by timestamp
    all_events.sort(key=lambda x: x["Timestamp"])
    return all_events

def plot_timeline(events, save_to_file=False, output_filename="timeline.png"):
    """
    Plot the timeline using matplotlib.
    - Short but more informative labels.
    - Color-code by source: firewall=blue, security=green, memory=red, else black.
    - Rotate x-axis labels to avoid overlap.
    """
    plt.figure(figsize=(12, 6))

    color_map = {"firewall": "blue", "security": "green", "memory": "red"}

    for idx, ev in enumerate(events):
        src = ev.get("Source", "other").lower()
        color = color_map.get(src, "black")

        plt.scatter(ev["Timestamp"], idx, marker='o', color=color)

        label = ev.get("Description", f"{src.title()} Event")
        plt.annotate(label,
                     (ev["Timestamp"], idx),
                     textcoords="offset points",
                     xytext=(10, 0),
                     ha='left',
                     fontsize=8)

    # Rotate x-axis labels for readability
    plt.gcf().autofmt_xdate()

    plt.xlabel("Timestamp")
    plt.ylabel("Event Index")
    plt.title("Unified Incident Timeline")
    plt.tight_layout()

    if save_to_file:
        plt.savefig(output_filename)
        print(f"Timeline saved to {output_filename}")
    else:
        plt.show()

def main():
    parser = argparse.ArgumentParser(description="Unified Timeline Reconstruction")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    # Default file paths - adjust to your project structure
    default_firewall = os.path.join(project_root, "data", "processed", "firewall_artifacts.json")
    default_security = os.path.join(project_root, "data", "forensic_artifacts", "security_events.csv")
    default_memory   = os.path.join(project_root, "data", "forensic_artifacts", "memory_artifacts.json")

    parser.add_argument("--firewall", type=str, default=default_firewall, help="Path to firewall_artifacts.json")
    parser.add_argument("--security", type=str, default=default_security, help="Path to security_events.csv")
    parser.add_argument("--memory",   type=str, default=default_memory,   help="Path to memory_artifacts.json")
    parser.add_argument("--output",   type=str, default="timeline.png",   help="Output timeline image filename")
    parser.add_argument("--save",     action="store_true",                help="Save timeline to file instead of showing it")

    args = parser.parse_args()

    # 1. Load each source
    firewall_events = load_firewall_artifacts(args.firewall)
    security_events = load_security_events(args.security)
    memory_events   = load_memory_artifacts(args.memory)

    # 2. Merge into one list
    all_events = merge_events(firewall_events, security_events, memory_events)
    print(f"Loaded {len(all_events)} total events after merging.")

    # 3. Plot timeline
    plot_timeline(all_events, save_to_file=args.save, output_filename=args.output)

if __name__ == "__main__":
    main()
