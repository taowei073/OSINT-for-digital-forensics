#!/usr/bin/env python3
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, correlated_data, output_file="report.html"):
        self.correlated_data = correlated_data
        self.output_file = output_file

    def generate(self):
        html_content = f"""
        <html>
          <head>
            <title>Digital Forensics OSINT Report</title>
          </head>
          <body>
            <h1>Digital Forensics OSINT Report</h1>
            <p>Generated on: {datetime.now()}</p>
            <h2>Forensic Artifacts</h2>
            <pre>{json.dumps(self.correlated_data.get("artifacts", {}), indent=4)}</pre>
            <h2>Whois Information</h2>
            <pre>{json.dumps(self.correlated_data.get("whois", {}), indent=4)}</pre>
            <h2>Shodan Data</h2>
            <pre>{json.dumps(self.correlated_data.get("shodan", {}), indent=4)}</pre>
            <h2>HIBP Results</h2>
            <pre>{json.dumps(self.correlated_data.get("hibp", {}), indent=4)}</pre>
          </body>
        </html>
        """
        try:
            with open(self.output_file, "w") as f:
                f.write(html_content)
            return self.output_file
        except Exception as e:
            print("Error generating report:", str(e))
            return None

if __name__ == "__main__":
    # Dummy correlated data for testing the report generation
    correlated_data = {
        "artifacts": {"ips": ["8.8.8.8"], "domains": ["example.com"], "emails": ["test@example.com"]},
        "whois": {"registrar": "Test Registrar", "creation_date": "2022-01-01"},
        "shodan": {"ports": [80, 443], "org": "Google LLC"},
        "hibp": [{"Name": "ExampleBreach", "Domain": "example.com"}]
    }
    generator = ReportGenerator(correlated_data)
    report_file = generator.generate()
    print(f"Report generated: {report_file}")
