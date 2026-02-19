import json
import os
import sys

import requests


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _get_domain_details(api_key: str, domain_name: str) -> dict | None:
    list_resp = requests.get(
        "https://api.resend.com/domains",
        headers=_headers(api_key),
        timeout=20,
    )
    if list_resp.status_code != 200:
        print(f"Failed to list domains. HTTP {list_resp.status_code}")
        print(list_resp.text)
        return None

    payload = list_resp.json()
    domains = payload.get("data", []) if isinstance(payload, dict) else []
    target = next(
        (
            domain
            for domain in domains
            if str(domain.get("name", "")).strip().lower() == domain_name.lower()
        ),
        None,
    )
    if not target:
        print(f"Domain {domain_name!r} not found in domain list response.")
        return None

    domain_id = target.get("id")
    if not domain_id:
        return target

    detail_resp = requests.get(
        f"https://api.resend.com/domains/{domain_id}",
        headers=_headers(api_key),
        timeout=20,
    )
    if detail_resp.status_code != 200:
        print(f"Failed to fetch domain details. HTTP {detail_resp.status_code}")
        print(detail_resp.text)
        return target
    return detail_resp.json()


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
        headers=_headers(api_key),
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
        details = _get_domain_details(api_key, domain_name)
        if details is not None:
            print("Current domain details:")
            print(json.dumps(details, indent=2))
        else:
            print(resp.text)
        return 0

    print(f"Failed to create domain. HTTP {resp.status_code}")
    print(resp.text)
    return 1


if __name__ == "__main__":
    sys.exit(main())
