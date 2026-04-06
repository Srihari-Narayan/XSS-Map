"""Single-page crawler — discovers injection points from forms, links, and params."""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from xss_map.utils import info, success, warning


class InjectionPoint:
    """Represents a discovered injection point."""

    def __init__(self, url, method, param_name, param_type, form_action=None, form_data=None):
        """
        Args:
            url: Target URL.
            method: HTTP method (GET, POST).
            param_name: Name of the injectable parameter.
            param_type: Where the param lives — 'query', 'body', 'header'.
            form_action: Full action URL for form-based params.
            form_data: Dict of other form fields (pre-filled defaults).
        """
        self.url = url
        self.method = method.upper()
        self.param_name = param_name
        self.param_type = param_type
        self.form_action = form_action or url
        self.form_data = form_data or {}

    def __repr__(self):
        return (
            f"InjectionPoint({self.method} {self.param_type}:{self.param_name} "
            f"@ {self.form_action or self.url})"
        )


# Common header injection points worth testing
INJECTABLE_HEADERS = [
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
]


def crawl(url, session):
    """
    Crawl a single page and return a list of InjectionPoints.

    Args:
        url: Target URL to crawl.
        session: requests.Session with auth headers/cookies set.

    Returns:
        List of InjectionPoint objects.
    """
    points = []

    # 1. Query parameters from the URL itself
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    for param in query_params:
        points.append(InjectionPoint(
            url=url, method="GET", param_name=param, param_type="query",
        ))

    # 2. Fetch the page and parse forms
    try:
        resp = session.get(url, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        warning(f"Failed to fetch {url}: {e}")
        return points  # return whatever we have from the URL params

    soup = BeautifulSoup(resp.text, "html.parser")

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""

        # Resolve relative action URLs
        if action.startswith("/"):
            action_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif action.startswith("http"):
            action_url = action
        else:
            base = url.rsplit("/", 1)[0]
            action_url = f"{base}/{action}" if action else url

        # Collect existing form field defaults
        form_data = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            value = inp.get("value", "")
            form_data[name] = value

        # Each named input is a potential injection point
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inp_type = inp.get("type", "text").lower()
            if inp_type in ("submit", "hidden", "button", "image", "reset"):
                continue

            param_type = "query" if method == "GET" else "body"
            points.append(InjectionPoint(
                url=url,
                method=method,
                param_name=name,
                param_type=param_type,
                form_action=action_url,
                form_data={k: v for k, v in form_data.items() if k != name},
            ))

    # 3. Header injection points
    for header in INJECTABLE_HEADERS:
        points.append(InjectionPoint(
            url=url, method="GET", param_name=header, param_type="header",
        ))

    # Deduplicate
    seen = set()
    unique = []
    for p in points:
        key = (p.method, p.param_name, p.param_type, p.form_action)
        if key not in seen:
            seen.add(key)
            unique.append(p)

    return unique


def display_injection_points(points):
    """Pretty-print discovered injection points."""
    if not points:
        warning("No injection points discovered.")
        return
    success(f"Discovered {len(points)} injection point(s):")
    for i, p in enumerate(points, 1):
        method_color = "\033[92m" if p.method == "GET" else "\033[93m"
        print(
            f"    [{i}] {method_color}{p.method}\033[0m  "
            f"{p.param_type}:{p.param_name}  →  {p.form_action or p.url}"
        )
