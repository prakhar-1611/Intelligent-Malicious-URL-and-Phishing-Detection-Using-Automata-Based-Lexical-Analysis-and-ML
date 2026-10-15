"""Defanging: make a URL safe to display, log and share.

Author: Prakhar Tandon (24BCI0222)

    https://evil.example/login  ->  hxxps://evil[.]example/login

The system never resolves or fetches a URL, and every URL the UI shows passes
through ``defang`` and is rendered as plain text, never as a link.
"""
from __future__ import annotations


def defang(url: str) -> str:
    if not url:
        return url
    sep = url.find("://")
    if sep >= 0:
        scheme, rest = url[:sep], url[sep + 3:]
        low = scheme.lower()
        if low.startswith("http"):
            scheme = ("hxxp" if scheme[:4].islower() else "HXXP") + scheme[4:]
        elif low == "ftp":
            scheme = "fxp"
        prefix = scheme + "[://]" if low not in ("http", "https") else scheme + "://"
    else:
        prefix, rest = "", url
    end = len(rest)
    for d in "/?#":
        i = rest.find(d)
        if i >= 0:
            end = min(end, i)
    authority = rest[:end].replace(".", "[.]").replace("@", "[@]")
    return prefix + authority + rest[end:]


def refang(text: str) -> str:
    out = text.replace("[.]", ".").replace("[@]", "@").replace("[://]", "://")
    for a, b in (("hxxps", "https"), ("hxxp", "http"), ("HXXPS", "HTTPS"), ("HXXP", "HTTP"), ("fxp", "ftp")):
        if out.startswith(a):
            out = b + out[len(a):]
    return out
