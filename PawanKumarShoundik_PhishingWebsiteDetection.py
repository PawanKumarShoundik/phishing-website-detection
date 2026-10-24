"""Educational URL-based phishing warning checker. Does not visit submitted URLs."""
import argparse, ipaddress, re, unittest
from urllib.parse import urlsplit, unquote

KEYWORDS = {"login","verify","verification","secure","account","update","signin","password","confirm","wallet","banking","payment","recover","authenticate"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rb.gy"}

def analyze_url(raw):
    if not isinstance(raw, str):
        raise TypeError("URL must be a string")
    raw = raw.strip()
    if not raw:
        return {"url":"","score":0,"label":"No input","findings":["Enter a URL to analyze."]}
    url = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    findings, score = [], 0
    try:
        p = urlsplit(url)
        host = (p.hostname or "").lower().rstrip(".")
        scheme = p.scheme.lower()
    except ValueError:
        return {"url":url,"score":60,"label":"Potentially suspicious","findings":["URL parsing failed; verify the destination carefully."]}
    path_query = unquote((p.path or "") + " " + (p.query or "")).lower()
    if not host:
        findings.append("Could not parse a hostname."); score += 25
    if scheme not in {"http","https"}:
        findings.append("Unusual or unsupported URL scheme."); score += 20
    elif scheme == "http":
        findings.append("Uses HTTP rather than HTTPS."); score += 8
    if "@" in url:
        findings.append("Contains '@', which can obscure the destination."); score += 18
    if host:
        try:
            ipaddress.ip_address(host)
            findings.append("Uses an IP address instead of a domain name."); score += 20
        except ValueError:
            pass
        if len(host) > 35:
            findings.append("Hostname is unusually long."); score += 10
        if host.count("-") >= 2:
            findings.append("Hostname contains multiple hyphens."); score += 8
        if host.count(".") >= 4:
            findings.append("Hostname contains many subdomain levels."); score += 10
        if host.startswith("xn--") or ".xn--" in host:
            findings.append("Hostname includes a punycode label; verify carefully."); score += 12
        if host in SHORTENERS:
            findings.append("Uses a URL shortener that hides the final destination."); score += 18
    if len(url) > 100:
        findings.append("URL is unusually long."); score += 8
    matches = sorted(k for k in KEYWORDS if re.search(r"(?<![a-z])"+re.escape(k)+r"(?![a-z])", path_query))
    if matches:
        findings.append("Sensitive-action keywords in path/query: " + ", ".join(matches[:6]) + ".")
        score += min(20, 5 + 3*len(matches))
    if re.search(r"%[0-9a-fA-F]{2}", url):
        findings.append("Contains percent-encoded characters; inspect destination carefully."); score += 4
    score = max(0, min(100, score))
    label = "Lower heuristic risk" if score < 20 else ("Use caution" if score < 45 else "Potentially suspicious")
    if not findings:
        findings.append("No listed warning signs detected. This does not prove the site is safe.")
    return {"url":url,"score":score,"label":label,"findings":findings}

def print_report(r):
    print("\nPhishing Website Detection — URL Analysis")
    print("-----------------------------------------")
    print("URL:", r["url"] or "(empty)")
    print(f"Score: {r['score']}/100 (heuristic)")
    print("Risk:", r["label"])
    for f in r["findings"]: print("-", f)
    print("\nThe program analyzed URL text only; it did not visit the URL.")
    print("A low score does not guarantee that a website is legitimate.")

class Tests(unittest.TestCase):
    def test_empty(self): self.assertEqual(analyze_url("")["label"], "No input")
    def test_ip(self): self.assertTrue(any("IP address" in x for x in analyze_url("http://192.0.2.10/login")["findings"]))
    def test_at(self): self.assertTrue(any("'@'" in x for x in analyze_url("http://example.com@192.0.2.10")["findings"]))
    def test_suspicious_path(self): self.assertTrue(analyze_url("http://secure-login.example.invalid/account/verify")["score"] > 0)
    def test_no_fetch(self): self.assertEqual(analyze_url("https://example.com")["url"], "https://example.com")

def main():
    ap = argparse.ArgumentParser(description="Analyze URL text for phishing warning signs.")
    ap.add_argument("url", nargs="?", help="URL to analyze")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    print_report(analyze_url(a.url if a.url is not None else input("Enter URL to analyze (do not open it): ")))
if __name__ == "__main__": main()
