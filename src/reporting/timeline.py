#!/usr/bin/env python3
import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import argparse


class TimelineReconstructor:
    def __init__(self, artifacts_file):
        """
        Initialize with the path to the artifacts file.
        """
        self.artifacts_file = artifacts_file
        self.df = None

    def load_artifacts(self):
        """
        Load the JSON file into a pandas DataFrame.
        """
        try:
            with open(self.artifacts_file, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                print("Warning: The artifacts file does not contain a list of events.")
                return None
            self.df = pd.DataFrame(data)
            # Clean column names
            self.df.columns = [col.strip() for col in self.df.columns]
            print("Artifacts loaded successfully. Preview:")
            print(self.df.head())
            return self.df
        except Exception as e:
            print(f"Error loading artifacts: {e}")
            return None

    def process_data(self):
        """
        Convert the Timestamp field to datetime and sort the DataFrame.
        """
        if self.df is None:
            print("Dataframe not loaded. Call load_artifacts() first.")
            return None
        try:
            self.df['Timestamp'] = pd.to_datetime(self.df['Timestamp'])
            self.df.sort_values('Timestamp', inplace=True)
            return self.df
        except Exception as e:
            print(f"Error processing data: {e}")
            return None

    def plot_timeline(self, save_to_file=False, output_filename="timeline.png"):
        """
        Plot the timeline of events.
        """
        if self.df is None:
            print("Dataframe not loaded. Call load_artifacts() first.")
            return
        plt.figure(figsize=(12, 6))
        plt.scatter(self.df['Timestamp'], range(len(self.df)), marker='o', color='blue')
        for idx, row in self.df.iterrows():
            label = f"{row.get('Workstation', '')}\n{row.get('Destination Domain', '')}\n{row.get('Action', '')}"
            plt.annotate(label, (row['Timestamp'], idx), textcoords="offset points", xytext=(10, 0), ha='left',
                         fontsize=8)
        plt.xlabel('Timestamp')
        plt.ylabel('Event Index')
        plt.title('Firewall Log Timeline')
        plt.tight_layout()
        if save_to_file:
            plt.savefig(output_filename)
            print(f"Timeline saved to {output_filename}")
        else:
            plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Timeline Reconstruction")

    # Update the default path according to your project structure.
    # If your artifacts.json is in the project root under data/processed, use:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    default_artifacts = os.path.join(project_root, "data", "processed", "firewall_artifacts.json")

    parser.add_argument("--artifacts", type=str, default=default_artifacts, help="Path to artifacts.json")
    parser.add_argument("--output", type=str, default=os.path.join(project_root, "data", "processed", "timeline.png"),
                        help="Output file for timeline image")
    parser.add_argument("--save", action="store_true", help="Save the timeline to a file instead of displaying it")

    args = parser.parse_args()

    reconstructor = TimelineReconstructor(args.artifacts)
    reconstructor.load_artifacts()
    reconstructor.process_data()
    reconstructor.plot_timeline(save_to_file=args.save, output_filename=args.output)
