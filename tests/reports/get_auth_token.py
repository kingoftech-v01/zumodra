#!/usr/bin/env python3
"""
Script to obtain JWT authentication token
"""
import requests
import json
import sys

BASE_URL = "http://localhost:8002"

# Try to get JWT token (try both username and email)
auth_data_username = {
    "username": "admin@demo.localhost",
    "password": "Admin123!"
}

auth_data_email = {
    "email": "admin@demo.localhost",
    "password": "Admin123!"
}

print("Attempting to get JWT token...")
print(f"Credentials: admin@demo.localhost / Admin123!")

try:
    # First try with username field
    response = requests.post(
        f"{BASE_URL}/api/auth/token/",
        json=auth_data_username,
        headers={"Content-Type": "application/json"}
    )

    print(f"\nStatus Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print(f"\nResponse Body:")
    print(response.text)

    if response.status_code == 200:
        token_data = response.json()
        print("\n✅ SUCCESS! Got JWT tokens:")
        print(f"Access Token: {token_data.get('access', 'N/A')}")
        print(f"Refresh Token: {token_data.get('refresh', 'N/A')}")

        # Save token to file
        with open('/home/king/zumodra/auth_token.json', 'w') as f:
            json.dump(token_data, f, indent=2)
        print("\nToken saved to: auth_token.json")

        sys.exit(0)
    else:
        print(f"\n❌ Failed to get token")
        sys.exit(1)

except Exception as e:
    print(f"\n⚠️  Error: {e}")
    sys.exit(1)
