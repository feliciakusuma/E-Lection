import json
import os
import sys

import requests


def main() -> int:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    domain_name = os.getenv("RESEND_DOMAIN_NAME", "e-lection.com").strip()

    if not api_key:
        print("Missing RESEND_API_KEY.")
        return 1
    if not domain_name:
        print("Missing RESEND_DOMAIN_NAME.")
        return 1

    resp = requests.post(
        "https://api.resend.com/domains",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={"name": domain_name},
        timeout=20,
    )

    if resp.status_code in (200, 201):
        print("Domain created successfully.")
        print(json.dumps(resp.json(), indent=2))
        return 0

    # Resend may return conflict if domain already exists.
    if resp.status_code == 409:
        print("Domain already exists in Resend account.")
        print(resp.text)
        return 0

    print(f"Failed to create domain. HTTP {resp.status_code}")
    print(resp.text)
    return 1


if __name__ == "__main__":
    sys.exit(main())
