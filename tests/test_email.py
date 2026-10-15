"""Email header lexer (RFC 5322 subset).

Owner: Prakhar Tandon (24BCI0222)
"""
from pathlib import Path

from lexer.email_lexer import find_urls, match_key, parse_address, scan_email, unfold

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples" / "emails"


def codes(res):
    return {f.code for f in res.flags}


def test_unfolding_joins_continuation_lines():
    lines, body, folds = unfold("Subject: a\r\n b\r\n\tc\r\nTo: x@y.z\r\n\r\nbody")
    assert lines == ["Subject: a b c", "To: x@y.z"]
    assert folds == 2 and body == "body"


def test_header_key_dfa():
    assert match_key("From: x") == 5
    assert match_key("X-Mailer: y") == 9
    assert match_key(" no key") == 0
    assert match_key("no colon here") == 0


def test_parse_address_forms():
    a = parse_address('"PayPal" <service@Evil.Example>')
    assert (a.display, a.local, a.domain) == ("PayPal", "service", "evil.example")
    b = parse_address("plain@example.com (comment)")
    assert b.domain == "example.com"
    assert parse_address("<>").domain == ""


def test_benign_sample_has_no_flags():
    res = scan_email((SAMPLES / "benign_folded.eml").read_text(encoding="utf-8"))
    assert codes(res) == set()
    assert res.folds == 3
    subject = next(h for h in res.headers if h["key"] == "Subject")
    assert "folded header line and a tab-folded" in subject["value"]
    assert res.auth_results == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert len(res.urls) == 2


def test_spoofed_sample_raises_all_three_header_flags():
    res = scan_email((SAMPLES / "spoofed_paypal.eml").read_text(encoding="utf-8"))
    assert {"S_FROM_REPLYTO_MISMATCH", "S_RETURNPATH_MISMATCH", "S_DISPLAYNAME_SPOOF"} <= codes(res)
    assert res.auth_results["spf"] == "fail"
    url_flags = {f["code"] for u in res.urls for f in u["flags"]}
    assert {"S_AT_ABUSE", "S_IP_OBFUSCATED", "S_OPEN_REDIRECT_PARAM"} <= url_flags


def test_same_registered_domain_is_not_a_mismatch():
    raw = "From: a@mail.example.com\nReply-To: b@example.com\nReturn-Path: <c@bounce.example.com>\n\nx"
    assert codes(scan_email(raw)) == set()


def test_display_name_with_foreign_address():
    raw = 'From: "service@paypal.com" <x@evil.example>\n\nhi'
    assert "S_DISPLAYNAME_SPOOF" in codes(scan_email(raw))


def test_display_name_brand_on_own_domain_is_fine():
    raw = 'From: "PayPal" <service@paypal.com>\n\nhi'
    assert "S_DISPLAYNAME_SPOOF" not in codes(scan_email(raw))


def test_find_urls_in_text():
    body = "see (https://a.com/x), or www.b.org/y. Also http://c.net"
    assert find_urls(body) == ["https://a.com/x", "www.b.org/y", "http://c.net"]
