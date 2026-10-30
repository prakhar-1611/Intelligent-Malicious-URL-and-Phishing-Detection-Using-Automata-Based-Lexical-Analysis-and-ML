"""API contract and hardening.

Owner: Amrita Bhatia (24BCI0215), hardening checks: Prakhar Tandon (24BCI0222)
"""
import os

os.environ.setdefault("RATE_LIMIT_ENABLED", "0")

from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.json()["rules"] == 23 and r.json()["url_flags"] == 14  # shown on the dashboard's How it works


def test_analyze_contract():
    r = client.post("/analyze", json={"url": "https://paypal.com@evil.example/verify"})
    assert r.status_code == 200
    body = r.json()
    for key in ("verdict", "score", "tokens", "flags", "trace", "explanation", "url_defanged", "steps"):
        assert key in body
    assert body["verdict"] in ("Safe", "Suspicious", "Malicious")
    assert "S_AT_ABUSE" in {f["code"] for f in body["flags"]}
    assert body["url_defanged"] == "hxxps://paypal[.]com[@]evil[.]example/verify"
    assert len(body["trace"]) == len("https://paypal.com@evil.example/verify")


def test_input_cap_2048():
    assert client.post("/analyze", json={"url": "http://a.com/" + "a" * 2100}).status_code == 422
    assert client.post("/analyze", json={"url": ""}).status_code == 422


def test_batch():
    r = client.post("/analyze/batch", json={"urls": ["https://example.com", "http://3232235777/x"]})
    assert r.status_code == 200
    rows = r.json()["results"]
    assert len(rows) == 2 and "S_IP_OBFUSCATED" in rows[1]["flags"]


def test_email_endpoint():
    raw = 'From: "PayPal" <x@evil.example>\nReply-To: y@other.example\n\nhttps://paypal.com@evil.example/'
    r = client.post("/analyze/email", json={"raw": raw})
    assert r.status_code == 200
    body = r.json()
    assert "S_DISPLAYNAME_SPOOF" in body["summary"]["header_flags"]
    assert body["urls"][0]["url_defanged"].startswith("hxxps://")


def test_automata_endpoints():
    lst = client.get("/automata").json()
    assert "HOST_LABEL" in lst["rules"] and "mode:AUTHORITY" in lst["modes"]
    for stage in ("nfa", "dfa", "min"):
        g = client.get(f"/automata/LABEL_A?stage={stage}").json()["graph"]
        assert g["nodes"] and g["edges"]
    assert client.get("/automata/NOPE").status_code == 404


def test_custom_pattern_and_syntax_error():
    ok = client.post("/automata/custom", json={"pattern": "ab*|c", "stage": "min"})
    assert ok.status_code == 200 and ok.json()["graph"]["nodes"]
    bad = client.post("/automata/custom", json={"pattern": "(ab", "stage": "nfa"})
    assert bad.status_code == 400 and "column" in bad.json()["detail"]


def test_security_headers_and_no_fetch():
    r = client.post("/analyze", json={"url": "http://example.com"})
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_figure_path_traversal_blocked():
    assert client.get("/results/figures/..%2F..%2Fapi%2Fmain.py").status_code in (400, 404)


def test_email_endpoint_explains_combined_verdict():
    samples = client.get("/samples/emails").json()
    assert set(samples) == {"benign_folded", "spoofed_paypal"}
    body = client.post("/analyze/email", json={"raw": samples["spoofed_paypal"]}).json()
    s = body["summary"]
    assert s["verdict"] == "Phishing" and s["rule"] and s["deciding_rule"]
    assert {"S_LINK_MISMATCH", "S_RISKY_ATTACHMENT"} == set(s["body_flags"])
    assert {r["code"] for r in s["reasons"]} == set(s["header_flags"]) | set(s["body_flags"])
    assert body["mime"]["children"] and all(link["href"].startswith("hxxp") for link in body["links"])
    assert all(f["description"] for f in body["flags"])


def test_email_first_party_links_of_verified_sender_are_safe():
    raw = ("Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nFrom: News <news@shop.com>\n"
           "Content-Type: text/plain\n\nhttps://click.shop.com/AbC123xYz%2F%3Fq%3D1/track?u=Zm9vYmFy&id=99887766")
    j = client.post("/analyze/email", json={"raw": raw}).json()
    assert j["urls"][0]["verdict"] == "Safe" and "first-party" in j["urls"][0]["basis"]
    # the same link from an unverified sender keeps the normal checks
    j2 = client.post("/analyze/email", json={"raw": raw.replace("dmarc=pass", "dmarc=fail")}).json()
    assert "first-party" not in j2["urls"][0]["basis"]
