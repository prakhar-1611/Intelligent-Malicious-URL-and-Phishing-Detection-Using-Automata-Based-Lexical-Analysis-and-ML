"""Golden token streams.

Owner: Ishitwo Khanra (24BCE2975)

Two sources of expected token streams, both written independently of the scanner:

1. COMPOSED: URLs assembled from parts whose tokens are known by construction
   (scheme x host x port x path x query x fragment). A deterministic sample of
   the product gives ~200 cases covering every component combination.
2. HAND: hand-labelled edge cases (userinfo, IPv6, opaque schemes, encodings,
   public-suffix hosts, empty components, panic-mode errors).
"""
import itertools
import random

import pytest

from lexer.scanner import scan

SCHEMES = [("https://", [("SCHEME", "https")]), ("http://", [("SCHEME", "http")]), ("", [])]
HOSTS = [
    ("example.com", [("BASE_DOMAIN", "example"), ("TLD", "com")]),
    ("www.example.com", [("SUBDOMAIN", "www"), ("BASE_DOMAIN", "example"), ("TLD", "com")]),
    ("mail.google.co.uk", [("SUBDOMAIN", "mail"), ("BASE_DOMAIN", "google"), ("TLD", "co.uk")]),
    ("a.b.c.example.org", [("SUBDOMAIN", "a"), ("SUBDOMAIN", "b"), ("SUBDOMAIN", "c"),
                           ("BASE_DOMAIN", "example"), ("TLD", "org")]),
    ("my-site.github.io", [("BASE_DOMAIN", "my-site"), ("TLD", "github.io")]),
    ("192.168.0.1", [("IP_HOST", "192.168.0.1")]),
    ("login-secure.bank.in", [("SUBDOMAIN", "login-secure"), ("BASE_DOMAIN", "bank"), ("TLD", "in")]),
    ("xn--80ak6aa92e.com", [("BASE_DOMAIN", "xn--80ak6aa92e"), ("TLD", "com")]),
    ("shop.example.com.au", [("SUBDOMAIN", "shop"), ("BASE_DOMAIN", "example"), ("TLD", "com.au")]),
    ("localhost", [("BASE_DOMAIN", "localhost")]),
]
PORTS = [("", []), (":8080", [("PORT", "8080")])]
PATHS = [("", []), ("/", [("PATH", "/")]), ("/account/reset", [("PATH", "/account/reset")]),
         ("/a/b/c.php", [("PATH", "/a/b/c.php")]), ("/wp-admin/x_y~z", [("PATH", "/wp-admin/x_y~z")])]
QUERIES = [("", []), ("?id=123", [("QUERY_PARAM", "id=123")]),
           ("?a=1&b=two", [("QUERY_PARAM", "a=1"), ("QUERY_PARAM", "b=two")]), ("?q=", [("QUERY_PARAM", "q=")])]
FRAGS = [("", []), ("#login", [("FRAGMENT", "login")]), ("#top/section", [("FRAGMENT", "top/section")])]

_ALL = list(itertools.product(SCHEMES, HOSTS, PORTS, PATHS, QUERIES, FRAGS))
COMPOSED = random.Random(2026).sample(_ALL, 200)


def _composed_case(parts):
    url = "".join(p[0] for p in parts)
    expected = [tok for p in parts for tok in p[1]]
    return url, expected


HAND = [
    ("https://www.example.com/account/reset?id=123#login",
     [("SCHEME", "https"), ("SUBDOMAIN", "www"), ("BASE_DOMAIN", "example"), ("TLD", "com"),
      ("PATH", "/account/reset"), ("QUERY_PARAM", "id=123"), ("FRAGMENT", "login")]),
    ("https://paypal.com@evil.example/verify",
     [("SCHEME", "https"), ("USERINFO", "paypal.com"), ("BASE_DOMAIN", "evil"), ("TLD", "example"),
      ("PATH", "/verify")]),
    ("http://user:pw@[::1]:80/", [("SCHEME", "http"), ("USERINFO", "user:pw"), ("IP_HOST", "[::1]"),
                                  ("PORT", "80"), ("PATH", "/")]),
    ("http://3232235777/login", [("SCHEME", "http"), ("IP_HOST", "3232235777"), ("PATH", "/login")]),
    ("javascript:alert(1)", [("SCHEME", "javascript"), ("PATH", "alert(1)")]),
    ("mailto:someone@example.com", [("SCHEME", "mailto"), ("PATH", "someone@example.com")]),
    ("www.bbc.co.uk/news", [("SUBDOMAIN", "www"), ("BASE_DOMAIN", "bbc"), ("TLD", "co.uk"), ("PATH", "/news")]),
    ("HTTPS://WWW.EXAMPLE.COM", [("SCHEME", "HTTPS"), ("SUBDOMAIN", "WWW"), ("BASE_DOMAIN", "EXAMPLE"),
                                 ("TLD", "COM")]),
    ("http://ex%61mple.com/", [("SCHEME", "http"), ("BASE_DOMAIN", "ex%61mple"), ("TLD", "com"), ("PATH", "/")]),
    ("http://a.com/x%2Fy?q=%20#f", [("SCHEME", "http"), ("BASE_DOMAIN", "a"), ("TLD", "com"), ("PATH", "/x%2Fy"),
                                    ("QUERY_PARAM", "q=%20"), ("FRAGMENT", "f")]),
    ("http://a.com//evil.com/x", [("SCHEME", "http"), ("BASE_DOMAIN", "a"), ("TLD", "com"),
                                  ("PATH", "//evil.com/x")]),
    ("http://a.com?x=1", [("SCHEME", "http"), ("BASE_DOMAIN", "a"), ("TLD", "com"), ("QUERY_PARAM", "x=1")]),
    ("http://a.com#frag", [("SCHEME", "http"), ("BASE_DOMAIN", "a"), ("TLD", "com"), ("FRAGMENT", "frag")]),
    ("http://a.com/?next=http://b.com/x?y=1", [("SCHEME", "http"), ("BASE_DOMAIN", "a"), ("TLD", "com"),
                                               ("PATH", "/"), ("QUERY_PARAM", "next=http://b.com/x?y=1")]),
    ("https://user.github.io/repo", [("SCHEME", "https"), ("BASE_DOMAIN", "user"), ("TLD", "github.io"),
                                     ("PATH", "/repo")]),
    # panic mode: the space becomes an ERROR token but stays inside the label text
    ("http://a b.com/", [("SCHEME", "http"), ("BASE_DOMAIN", "a b"), ("ERROR", " "), ("TLD", "com"), ("PATH", "/")]),
    ("http://例え.jp/", [("SCHEME", "http"), ("BASE_DOMAIN", "例え"), ("TLD", "jp"), ("PATH", "/")]),
    ("ftp://files.example.net:21/pub", [("SCHEME", "ftp"), ("SUBDOMAIN", "files"), ("BASE_DOMAIN", "example"),
                                        ("TLD", "net"), ("PORT", "21"), ("PATH", "/pub")]),
    ("http://0300.0250.01.01/", [("SCHEME", "http"), ("IP_HOST", "0300.0250.01.01"), ("PATH", "/")]),
    ("http://co.uk/", [("SCHEME", "http"), ("BASE_DOMAIN", "co"), ("TLD", "uk"), ("PATH", "/")]),
]

CASES = [_composed_case(p) for p in COMPOSED] + HAND


def tokens(url):
    return [(t.type, t.value) for t in scan(url).tokens]


@pytest.mark.parametrize("url,expected", CASES, ids=[c[0][:60] for c in CASES])
def test_golden(url, expected):
    assert tokens(url) == expected  # tokens are ordered by start position


def test_case_count():
    assert len(CASES) >= 150


def test_positions_are_exact():
    url = "https://www.example.com:8443/a?b=c#d"
    for t in scan(url).tokens:
        assert url[t.start:t.end] == t.value, t
