"""IP decoding, IDN helpers, defanging, symbol table.

Owner: Prakhar Tandon (24BCI0222), symbol table: Ishitwo Khanra (24BCE2975)
"""
import pytest

from lexer.symtab import CorpusSymbolTable, SymbolTable
from security.defang import defang, refang
from security.idn import decode_label, encode_label, is_mixed_script, skeleton
from security.ip_decode import parse_ipv4, to_decimal_form, to_hex_form, to_octal_form


@pytest.mark.parametrize("host,form", [
    ("192.168.1.1", "dotted-decimal"), ("3232235777", "decimal"), ("0xC0A80101", "hex"),
    ("0300.0250.01.01", "octal"), ("0xC0.0250.1.1", "mixed"), ("192.11010305", "short"), ("192.168.257", "short"),
])
def test_ipv4_forms_all_decode_to_same_address(host, form):
    ip = parse_ipv4(host)
    assert ip.dotted == "192.168.1.1" and ip.form == form
    assert ip.obfuscated == (form != "dotted-decimal")


@pytest.mark.parametrize("host", ["example.com", "256.1.1.1", "1.2.3.4.5", "09.1.1.1", "", "0xZZ", "1..2"])
def test_not_an_ip(host):
    assert parse_ipv4(host) is None


def test_ip_form_converters_round_trip():
    for conv in (to_decimal_form, to_hex_form, to_octal_form):
        assert parse_ipv4(conv("10.20.30.40")).dotted == "10.20.30.40"


def test_punycode_round_trip_and_scripts():
    lab = "pаypal"
    enc = encode_label(lab)
    assert enc.startswith("xn--") and decode_label(enc) == lab
    assert is_mixed_script(lab)
    assert not is_mixed_script("пример") and not is_mixed_script("例えば") and not is_mixed_script("münchen")


def test_skeleton():
    assert skeleton("paypa1") == skeleton("paypal") == skeleton("pаypal")
    assert skeleton("arnazon") == "amazon"
    assert skeleton("ｇｏｏｇｌｅ") == "google"  # full-width via NFKC


def test_defang():
    assert defang("https://evil.example/login") == "hxxps://evil[.]example/login"
    assert defang("http://a.b@c.d/x.y") == "hxxp://a[.]b[@]c[.]d/x.y"
    assert refang(defang("https://evil.example/a")) == "https://evil.example/a"


def test_symbol_table_hashing_and_rehash():
    st = SymbolTable(capacity=4)
    for i in range(100):
        st.insert(f"label{i}", "label", "SUBDOMAIN", i)
    st.insert("label7", "label", "BASE_DOMAIN", 500)
    assert len(st) == 100
    s = st.lookup("label7", "label")
    assert s.freq == 2 and s.first == 7 and s.last == 500 and s.token_types == {"SUBDOMAIN", "BASE_DOMAIN"}
    assert st.lookup("label7", "param") is None


def test_corpus_rarity(tmp_path):
    c = CorpusSymbolTable()
    for _ in range(50):
        c.add(["www", "google"], ["www"], {"paypal"})
    c.add(["paypal", "evil"], ["paypal"], {"paypal"})
    assert c.label_rarity("unseen-label") > c.label_rarity("evil") > c.label_rarity("www")
    assert c.brand_subdomain_counts == {"paypal": 1}
    c.save(tmp_path / "c.json")
    assert CorpusSymbolTable.load(tmp_path / "c.json").label_counts == c.label_counts
