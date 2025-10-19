import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'verify your account',
    'urgent',
    'password expired',
    'update payment',
    'click here',
    'limited time',
    'act now',
    'confirm your identity',
    'invoice attached',
    'unusual activity',
]

SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'rb.gy', 'ow.ly'
]

BRAND_SQUATTING_PATTERNS = [
    r'paypa1|paypol|páypal',
    r'micr0soft|rnicrosoft',
    r'go0gle|g00gle',
]


INDICATOR_WEIGHTS = {
    'suspicious_keyword': 10,
    'shortener': 15,
    'brand_squatting': 20,
    'http_not_https': 10,
    'ip_in_url': 15,
    'too_many_subdomains': 10,
    'attachment_prompt': 10,
    'misspellings': 10,
}


MISSPELLINGS = [
    'recieve', 'passwrod', 'immediatly', 'credentails', 'priviledge', 'occured'
]


def analyze_input(text: str, mode: str = 'auto'):
    text_lower = (text or '').lower().strip()
    indicators = []

    # detect URLs
    urls = extract_urls(text)

    # keyword checks
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in text_lower:
            indicators.append(('suspicious_keyword', f"Contains phrase: '{kw}'"))

    # misspellings
    for miss in MISSPELLINGS:
        if re.search(rf'\b{re.escape(miss)}\b', text_lower):
            indicators.append(('misspellings', f"Possible misspelling: '{miss}'"))

    # URL-based indicators
    for u in urls:
        parsed = urlparse(u)
        host = parsed.netloc.lower()
        scheme = parsed.scheme.lower()

        if scheme == 'http':
            indicators.append(('http_not_https', f'URL not using HTTPS: {u}'))

        if host.count('.') >= 3:
            indicators.append(('too_many_subdomains', f'Many subdomains: {host}'))

        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            indicators.append(('ip_in_url', f'IP address used as host: {host}'))

        # URL shorteners
        for sd in SUSPICIOUS_DOMAINS:
            if host.endswith(sd):
                indicators.append(('shortener', f'URL shortener used: {host}'))

        # brand squatting
        for patt in BRAND_SQUATTING_PATTERNS:
            if re.search(patt, host):
                indicators.append(('brand_squatting', f'Possible impersonation in domain: {host}'))

    # attachment prompt
    if 'attached' in text_lower and ('invoice' in text_lower or 'payment' in text_lower):
        indicators.append(('attachment_prompt', 'Mentions attached invoice/payment'))

    # scoring
    score = sum(INDICATOR_WEIGHTS.get(ind[0], 5) for ind in indicators)
    label = 'phishing' if score >= 30 else 'suspicious' if score >= 15 else 'likely_safe'

    return label, score, indicators


def extract_urls(text: str):
    if not text:
        return []
    # very simple URL regex
    url_regex = r'(https?://[\w\.-/:?#%=&~+]+)'
    return re.findall(url_regex, text, flags=re.IGNORECASE)
