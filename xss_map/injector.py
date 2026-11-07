"""Injector — fires payloads into injection points and captures responses."""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from xss_map.crawler import InjectionPoint
from xss_map.utils import extract_snippet


class InjectionResult:
    """Result of a single payload injection."""

    def __init__(self, injection_point, payload, status_code, response_body, snippet):
        self.injection_point = injection_point
        self.payload = payload
        self.status_code = status_code
        self.response_body = response_body
        self.snippet = snippet


def inject(session, injection_point, payload, rate_limiter=None):
    """
    Inject a payload into an injection point and return the result.

    Args:
        session: requests.Session with auth configured.
        injection_point: InjectionPoint to target.
        payload: XSS payload string.
        rate_limiter: Optional RateLimiter instance.

    Returns:
        InjectionResult or None on network error.
    """
    if rate_limiter:
        rate_limiter.wait()

    ip = injection_point

    try:
        if ip.param_type == "header":
            # Inject into a request header
            headers = {ip.param_name: payload}
            resp = session.get(ip.url, headers=headers, timeout=15, allow_redirects=True)

        elif ip.param_type == "query":
            # Inject into URL query parameter
            parsed = urlparse(ip.form_action)
            params = parse_qs(parsed.query, keep_blank_values=True)
            # Flatten existing params
            flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            # Merge form defaults
            flat_params.update(ip.form_data)
            # Set the payload
            flat_params[ip.param_name] = payload
            new_query = urlencode(flat_params)
            new_url = urlunparse(parsed._replace(query=new_query))

            if ip.method == "POST":
                # Some forms use GET params in action URL + POST body
                resp = session.post(ip.form_action, data=flat_params, timeout=15, allow_redirects=True)
            else:
                resp = session.get(new_url, timeout=15, allow_redirects=True)

        elif ip.param_type == "body":
            # Inject into POST body
            data = dict(ip.form_data)
            data[ip.param_name] = payload
            resp = session.post(ip.form_action, data=data, timeout=15, allow_redirects=True)

        else:
            return None

        body = resp.text
        snippet = extract_snippet(body, payload)

        return InjectionResult(
            injection_point=ip,
            payload=payload,
            status_code=resp.status_code,
            response_body=body,
            snippet=snippet,
        )

    except Exception:
        return None
