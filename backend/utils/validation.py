import re
import socket
from typing import Dict, Set

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")

MAJOR_CODE_MAP: Dict[str, str] = {
    "22": "Management",
    "37": "Industrial Engineering",
    "39": "Computer Science",
    "40": "Information Systems",
    "21": "Accounting",
    "51": "Psychology",
    "36": "Mechanical Engineering",
    "41": "Visual Communication Design",
    "12": "English Education",
}

SUPPORTED_COHORTS: Set[int] = {2022, 2023, 2024, 2025}

try:
    import dns.resolver  # type: ignore

    _DNS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    dns = None
    _DNS_AVAILABLE = False


def _domain_has_mx(domain: str) -> bool:
    if not _DNS_AVAILABLE:
        return False
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except Exception:
        return False


def _domain_has_a(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, 25)
        return True
    except Exception:
        return False


def is_valid_email_address(email: str) -> bool:
    """Very permissive email check: only require an '@' with a non-empty domain."""
    if not email or "@" not in email:
        return False
    local, _, domain = email.partition("@")
    return bool(local and domain)
