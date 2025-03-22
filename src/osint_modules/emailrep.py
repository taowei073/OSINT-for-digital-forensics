#!/usr/bin/env python3
import requests
import json


class EmailRep:
    def __init__(self, email, api_key):
        """
        Initialize the EmailRep API client.

        :param email: The email address to query.
        :param api_key: Your API key for EmailRep.io.
        """
        self.email = email
        self.api_key = api_key
        self.base_url = f"https://emailrep.io/{self.email}"

    def query(self):
        """
        Query EmailRep.io for information about the email address.

        :return: A dictionary with the API response data.
        """
        headers = {"Key": self.api_key}

        response = requests.get(self.base_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"Status code {response.status_code}",
                "response": response.text
            }


if __name__ == "__main__":
    # Example email address for testing.
    email = "test@example.com"

    # Replace with your actual API key from EmailRep.io
    API_KEY = "YOUR_API_KEY_HERE"

    email_rep = EmailRep(email, api_key=API_KEY)

    result = email_rep.query()

    # Print the result in formatted JSON.
    print(json.dumps(result, indent=4))
