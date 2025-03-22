#!/usr/bin/env python3
import os
import requests

class VirusTotalLookup:
    def __init__(self, domain, api_key=None):
        """
        Initialize with the target domain and VirusTotal API key.
        """
        self.domain = domain
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY").strip()
        self.base_url = "https://www.virustotal.com/api/v3/domains/"

    def lookup(self):
        if not self.api_key:
            return {"error": "VirusTotal API key not provided"}
        url = self.base_url + self.domain
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "response": response.text}
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    vt = VirusTotalLookup("example.com", api_key="")
    print(vt.lookup())
