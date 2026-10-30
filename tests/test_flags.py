"""Security flags: at least 5 positive and 5 negative cases for every flag.

Owner: Prakhar Tandon (24BCI0222)
"""
import pytest

from lexer.scanner import scan

CYR_A, CYR_O = "а", "о"

CASES = {
    "S_PUNY_DETECT": (
        ["http://xn--pypal-4ve.com/", "https://xn--80ak6aa92e.com/", "http://sub.xn--bcher-kva.example/",
         "http://XN--abc.com", "http://xn--e1afmkfd.xn--p1ai/"],
        ["http://example.com", "http://xn.com", "http://axn--b.com", "http://example.com/xn--path",
         "https://my-xn.com"]),
    "S_PCT_ENCODE": (
        ["http://a.com/%2e%2e/", "http://a.com/%61", "http://a.com/?q=%20", "http://a.com/#%41",
         "http://ex%61mple.com/"],
        ["http://a.com/100", "http://a.com/%zz", "http://a.com/", "http://a.com/?q=5", "http://a.com/a%2"]),
    "S_IP_HOST": (
        ["http://192.168.1.1/", "http://10.0.0.1:8080/x", "http://[::1]/", "http://3232235777/", "https://8.8.8.8"],
        ["http://example.com", "http://1.2.3.com/", "http://v1.2.example.com", "http://192-168-1-1.example.com",
         "http://example.com/192.168.1.1"]),
    "S_PORT_ANOMALY": (
        ["http://a.com:8080/", "https://a.com:8443", "ftp://a.com:21/", "http://a.com:3000/x", "http://1.2.3.4:65535"],
        ["http://a.com:80/", "https://a.com:443/", "http://a.com/", "http://a.com/x:8080", "http://u:123@a.com/"]),
    "S_AT_ABUSE": (
        ["https://paypal.com@evil.example/", "http://a@b.com", "http://user:pw@host.com", "http://x@y@z.com",
         "http://google.com%40@evil.com"],
        ["http://a.com/@user", "mailto:x@y.com", "http://a.com/?e=a@b.com", "http://a.com/#@x",
         "https://medium.com/@user/post"]),
    "S_REDIRECT_ABUSE": (
        ["http://a.com//evil.com", "http://a.com/x//y", "http://a.com/redirect/http://evil.com", "http://a.com///",
         "https://a.com/a/b//c"],
        ["http://a.com/x/y", "http://a.com/?u=http://evil.com", "http://a.com", "http://a.com/#//x",
         "https://a.com/a/b"]),
    "S_CONTROL_ANOMALY": (
        ["http://a\x00.com/", "http://a.com/\tx", "http://a.com/x\ny", "http://a.com/\x7f", "\x1bhttp://a.com/"],
        ["http://a.com/", "https://www.example.org/x?y=1", "http://a.com/~x", "http://a.com/#z", "a.com"]),
    "S_SUBDOMAIN_DEPTH": (
        ["http://a.b.c.example.com", "http://paypal.com.verify.login.example.net", "http://w.x.y.z.site.org",
         "http://1.2.3.4.evil.com", "http://a.b.c.d.e.co.uk"],
        ["http://www.example.com", "http://a.b.example.com", "http://example.com", "http://www.bbc.co.uk",
         "http://mail.google.com"]),
    "S_MIXED_SCRIPT": (
        [f"http://p{CYR_A}ypal.com", "http://xn--pypal-4ve.com", f"http://g{CYR_O}{CYR_O}gle.com",
         f"http://{CYR_A}pple.com", f"http://micr{CYR_O}soft.com"],
        ["http://пример.рф", "http://例え.jp", "http://münchen.de", "http://example.com", "http://παράδειγμα.gr"]),
    "S_DOUBLE_ENCODE": (
        ["http://a.com/%252e", "http://a.com/%2541", "http://a.com/a%252f", "http://a.com/?x=%2520",
         "http://a.com/#%2561"],
        ["http://a.com/%25", "http://a.com/%2e", "http://a.com/%25z", "http://a.com/", "http://a.com/25"]),
    "S_IP_OBFUSCATED": (
        ["http://3232235777/", "http://0xC0A80101/", "http://0300.0250.0001.0001/", "http://0xC0.0xA8.1.1/",
         "http://192.11010305/"],
        ["http://192.168.1.1/", "http://8.8.8.8/", "http://example.com/", "http://123.example.com/",
         "http://[::1]/"]),
    "S_OPEN_REDIRECT_PARAM": (
        ["http://a.com/?next=https://evil.com", "http://a.com/?url=http%3A%2F%2Fevil.com",
         "http://a.com/?redirect=//evil.com", "http://a.com/?returnUrl=https%253A%252F%252Fevil.com",
         "http://a.com/login?x=1&r=http://x.y"],
        ["http://a.com/?next=/home", "http://a.com/?url=example", "http://a.com/?q=https://x.com",
         "http://a.com/?id=1", "http://a.com/?redirect=false"]),
    "S_HOMOGLYPH": (
        ["http://paypa1.com", "http://g00gle.com", f"http://p{CYR_A}ypal.com", "http://arnazon.com",
         "http://xn--pypal-4ve.com"],
        ["http://paypal.com", "http://google.com", "http://example.com", "http://paypal-help.com",
         "http://amazon.co.uk"]),
    "S_TYPOSQUAT": (
        ["http://pypal.com/login", "https://paypla.com", "http://gooogle.com", "http://faceboook.net",
         "https://www.micosoft.com/", "http://instagarm.com", "http://amazom.co.uk"],
        ["http://paypal.com", "http://google.com", "http://email.com", "http://example.com",
         "http://pypal.example.com", "http://paypal-help.com", "http://paypa1.com", "http://apples.com"]),
}


def test_typosquat_does_not_change_model_features():
    """S_TYPOSQUAT is not a model input until a retrain (lexer.rules.UNTRAINED_FLAGS)."""
    from ml.features import FeatureExtractor

    fx = FeatureExtractor()
    assert "flag_typosquat" not in fx.names
    x, _ = fx.extract("http://pypal.com/")
    names = fx.names
    assert x[names.index("n_flags_attr")] == 0 and x[names.index("flag_severity_sum")] == 0


def codes(url):
    return {f.code for f in scan(url).flags}


@pytest.mark.parametrize("flag", sorted(CASES))
def test_case_counts(flag):
    pos, neg = CASES[flag]
    assert len(pos) >= 5 and len(neg) >= 5


@pytest.mark.parametrize("flag,url", [(f, u) for f, (pos, _) in CASES.items() for u in pos])
def test_positive(flag, url):
    assert flag in codes(url), f"{flag} not raised for {url!r}: {codes(url)}"


@pytest.mark.parametrize("flag,url", [(f, u) for f, (_, neg) in CASES.items() for u in neg])
def test_negative(flag, url):
    assert flag not in codes(url), f"{flag} wrongly raised for {url!r}"


def test_flag_sources():
    """DFA-state flags vs attribute-check flags are labelled correctly."""
    r = scan("http://paypal.com@3232235777:8080/%252e")
    src = {f.code: f.source for f in r.flags}
    assert src["S_AT_ABUSE"] == "dfa"
    assert src["S_DOUBLE_ENCODE"] == "dfa"
    assert src["S_IP_OBFUSCATED"] == "attr"
    assert src["S_PORT_ANOMALY"] == "attr"


def test_flag_spans_point_at_evidence():
    url = "https://paypal.com@evil.example/%2e"
    for f in scan(url).flags:
        if f.source == "dfa":
            assert url[f.start:f.end] == f.evidence
