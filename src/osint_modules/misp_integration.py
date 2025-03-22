#!/usr/bin/env python3
from pymisp import PyMISP
import json
import os


class MISPIntegration:
    def __init__(self, misp_url, misp_key, verifycert=False):
        """
        Initialize the MISP integration module.

        :param misp_url: URL of the MISP instance.
        :param misp_key: API key for the MISP instance.
        :param verifycert: Boolean indicating if SSL certificates should be verified.
        """
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.verifycert = verifycert
        self.misp = PyMISP(misp_url, misp_key, verifycert, 'json')

    def search_attribute(self, attribute_type, value):
        """
        Search for a given attribute in MISP.

        :param attribute_type: Type of attribute to search (e.g., "domain", "ip-dst", "md5").
        :param value: The value to search for.
        :return: The JSON response from MISP.
        """
        result = self.misp.search(controller='attributes', type_attribute=attribute_type, value=value)
        return result

    def search_domain(self, domain):
        """
        Convenience method to search for a domain.

        :param domain: Domain to search for.
        :return: JSON response from MISP.
        """
        return self.search_attribute("domain", domain)

    def search_ip(self, ip):
        """
        Convenience method to search for an IP address.

        :param ip: IP address to search for.
        :return: JSON response from MISP.
        """
        return self.search_attribute("ip-dst", ip)


if __name__ == "__main__":
    # Example configuration; replace with your own MISP instance details.
    MISP_URL = "https://192.168.142.138"  # e.g., "https://misp.example.com"
    MISP_KEY = "4KrZOqmVyudoWr4lLBCQLqFpbuoziR4BsZOzjx3f"

    misp_integration = MISPIntegration(MISP_URL, MISP_KEY)

    # Example search: Look for events related to a specific domain.
    domain_to_search = "kozow.com"
    results = misp_integration.search_domain(domain_to_search)

    print("MISP search results for domain:")
    print(json.dumps(results, indent=4))
