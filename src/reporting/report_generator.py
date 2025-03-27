import json
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader


def generate_html_report(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)

    osint = data.get("osint_results", {})
    iocs = data.get("input_iocs", {})

    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")

    # Render the HTML with provided data
    html_content = template.render(
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        osint=osint,
        iocs=iocs,
        summary={
            "ip_count": len(iocs.get("ips", [])),
            "domain_count": len(iocs.get("domains", [])),
            "hash_count": len(iocs.get("file_hashes", [])),
            "process_count": len(iocs.get("processes", [])),
        }
    )

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"HTML report generated at {output_file}")


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    input_path = os.path.join(project_root, "data", "processed", "combined_forensics.json")
    output_path = os.path.join(project_root, "reports", "osint_report.html")

    generate_html_report(input_path, output_path)
