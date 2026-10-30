"""Email header lexer (RFC 5322 subset).

Owner: Prakhar Tandon (24BCI0222)
"""
from pathlib import Path

from core.types import Flag
from lexer.email_lexer import (MAX_MIME_PARTS, _MimeAcc, combine_verdict, decode_body, find_urls, header_params,
                               match_key, parse_address, parse_part, scan_email, split_multipart, unfold)

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


# ------------------------------------------------------------------ Review 3: MIME, body signals, verdict

THRESHOLDS = {"suspicious": 0.4, "malicious": 0.9}


def spoofed():
    return scan_email((SAMPLES / "spoofed_paypal.eml").read_text(encoding="utf-8"))


def test_mime_part_tree_of_spoofed_sample():
    tree = spoofed().mime
    assert tree["content_type"] == "multipart/mixed"
    alt, att = tree["children"]
    assert [c["content_type"] for c in alt["children"]] == ["text/plain", "text/html"]
    assert alt["children"][1]["encoding"] == "quoted-printable"
    assert att["filename"] == "Invoice-2026.pdf.exe" and att["risky"] and att["size"] > 0


def test_spoofed_sample_raises_review3_flags():
    res = spoofed()
    assert {"S_AUTH_FAIL", "S_LOOKALIKE_SENDER", "S_LINK_MISMATCH", "S_RISKY_ATTACHMENT"} <= codes(res)
    link = next(link for link in res.links if link["mismatch"])
    assert (link["text_domain"], link["href_domain"]) == ("paypal.com", "3232235777")
    assert link["href"].startswith("hxxp://")  # defanged, never a raw link


def test_benign_sample_has_no_review3_flags():
    res = scan_email((SAMPLES / "benign_folded.eml").read_text(encoding="utf-8"))
    assert res.mime["content_type"] == "text/plain" and res.links == []
    assert codes(res) == set()


def test_header_params_keeps_quoted_semicolons():
    assert header_params('multipart/mixed; boundary="a;b"; charset=UTF-8') == \
        ("multipart/mixed", {"boundary": "a;b", "charset": "UTF-8"})
    assert header_params("") == ("", {})


def test_split_multipart_drops_preamble_and_tolerates_missing_close():
    body = "preamble\n--b\nX: 1\n\none\n--b\n\ntwo\n--b--\nepilogue"
    assert split_multipart(body, "b") == ["X: 1\n\none", "\ntwo"]
    assert split_multipart("--b\n\nonly", "b") == ["\nonly"]


def test_part_without_headers_and_bad_base64():
    acc = _MimeAcc()
    node = parse_part(['Content-Type: multipart/mixed; boundary="b"'], "--b\n\nplain body\n--b--", acc)
    assert node["children"][0]["content_type"] == "text/plain"
    assert acc.texts[0][1].startswith("plain body")
    assert decode_body("!!not base64!!", "base64") == b"!!not base64!!"


def test_mime_part_cap():
    body = "".join(f"--b\n\npart {i}\n" for i in range(MAX_MIME_PARTS + 20)) + "--b--"
    res = scan_email('Content-Type: multipart/mixed; boundary="b"\n\n' + body)
    assert res.mime_truncated and len(res.mime["children"]) < MAX_MIME_PARTS


def test_link_text_matching_href_is_not_a_mismatch():
    raw = ('Content-Type: text/html\n\n<a href="https://www.example.com/a">example.com</a>'
           '<a href="https://evil.example/">Click here</a>')
    res = scan_email(raw)
    assert "S_LINK_MISMATCH" not in codes(res) and len(res.links) == 2


def test_auth_results_pass_and_none_do_not_flag():
    raw = "From: a@example.com\nAuthentication-Results: mx; spf=pass; dkim=none; dmarc=pass\n\nhi"
    assert "S_AUTH_FAIL" not in codes(scan_email(raw))
    assert "S_AUTH_FAIL" in codes(scan_email(raw.replace("spf=pass", "spf=softfail")))


def test_lookalike_sender_domain():
    assert "S_LOOKALIKE_SENDER" in codes(scan_email("From: a@pypal.com\n\nhi"))
    assert "S_LOOKALIKE_SENDER" in codes(scan_email("From: a@secure-micosoft.com\n\nhi"))
    assert "S_LOOKALIKE_SENDER" not in codes(scan_email("From: a@paypal.com\n\nhi"))


def test_safe_attachment_is_not_risky():
    raw = ('Content-Type: multipart/mixed; boundary="b"\n\n--b\nContent-Disposition: attachment; '
           'filename="report.pdf"\n\nx\n--b--')
    res = scan_email(raw)
    assert "S_RISKY_ATTACHMENT" not in codes(res) and res.mime["children"][0]["filename"] == "report.pdf"


def _f(code, sev):
    return Flag(code, 0, 0, "e", sev, "attr")


def test_combine_verdict_rules():
    assert combine_verdict([], [], THRESHOLDS)["verdict"] == "Safe"
    assert combine_verdict([], [0.95], THRESHOLDS)["verdict"] == "Phishing"
    assert combine_verdict([], [0.5], THRESHOLDS)["verdict"] == "Suspicious"
    assert combine_verdict([_f("S_AUTH_FAIL", 2)], [0.1], THRESHOLDS)["verdict"] == "Suspicious"
    two_strong = combine_verdict([_f("S_LINK_MISMATCH", 3), _f("S_RISKY_ATTACHMENT", 3)], [], THRESHOLDS)
    assert two_strong["verdict"] == "Phishing" and two_strong["evidence_points"] == 6
    assert two_strong["rule"] and "6 evidence points" in two_strong["deciding_rule"]


def test_authenticated_sender_with_only_a_high_link_is_suspicious_not_phishing():
    """Real Google Play mail: DMARC pass, no flags, c.gle tracking links the URL model scores ~0.99."""
    assert combine_verdict([], [0.99], THRESHOLDS, authenticated=True)["verdict"] == "Suspicious"
    assert combine_verdict([], [0.99], THRESHOLDS, authenticated=False)["verdict"] == "Phishing"
    # any email flag removes the cap: a look-alike domain can pass DMARC for itself
    assert combine_verdict([_f("S_LOOKALIKE_SENDER", 3)], [0.99], THRESHOLDS, authenticated=True)["verdict"] == "Phishing"


def test_only_topmost_authentication_results_is_trusted():
    raw = ("Authentication-Results: mx.receiver; spf=fail; dkim=fail; dmarc=fail\n"
           "Authentication-Results: forged-by-sender; spf=pass; dkim=pass; dmarc=pass\n\nhi")
    res = scan_email(raw)
    assert res.auth_results["dmarc"] == "fail" and "S_AUTH_FAIL" in codes(res)


def test_same_organisation_domains():
    from lexer.email_lexer import same_org
    assert same_org("unstop.news", "unstop.com") and same_org("amazon.in", "amazon.com")
    assert not same_org("unst0p.com", "unstop.com") and not same_org("paypa1.com", "paypal.com")
    raw = "From: a@unstop.news\nReply-To: b@unstop.com\n\nhi"
    assert "S_FROM_REPLYTO_MISMATCH" not in codes(scan_email(raw))


def test_return_path_mismatch_is_normal_when_dmarc_passes():
    raw = ("Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nFrom: a@news.shop.com\n"
           "Return-Path: <bounce@mailerservice.net>\n\nhi")
    assert "S_RETURNPATH_MISMATCH" not in codes(scan_email(raw))
    assert "S_RETURNPATH_MISMATCH" in codes(scan_email(raw.replace("dmarc=pass", "dmarc=none")))


def test_first_party_click_tracker_is_not_a_link_mismatch():
    head = "Authentication-Results: mx; dmarc=pass\nFrom: a@shop.com\nContent-Type: text/html\n\n"
    own = head + '<a href="https://click.shop.com/t/abc">www.shop.in</a>'
    other = head + '<a href="https://click.tracker-elsewhere.com/t/abc">www.shop.in</a>'
    assert "S_LINK_MISMATCH" not in codes(scan_email(own))
    assert "S_LINK_MISMATCH" in codes(scan_email(other))


def test_href_wrapped_over_lines_is_joined_like_a_browser_does():
    raw = 'Content-Type: text/html\n\n<a href="https://www.example.com/track?id=\n\tabc123">Open</a>'
    res = scan_email(raw)
    assert res.urls[0]["url"] == "https://www.example.com/track?id=abc123"
    assert not any(f["code"] == "S_CONTROL_ANOMALY" for f in res.urls[0]["flags"])
