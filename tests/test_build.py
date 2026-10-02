import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "src" / "build.py"
spec = importlib.util.spec_from_file_location("builder", MODULE)
builder = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(builder)

class ParserTests(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(builder.canonicalize("Example.COM"), "example.com")

    def test_wildcard_domain(self):
        self.assertEqual(builder.canonicalize("*.ads.example.com"), "ads.example.com")

    def test_adblock_domain(self):
        self.assertEqual(builder.canonicalize("||tracker.example.com^"), "tracker.example.com")

    def test_hosts_domain(self):
        self.assertEqual(builder.canonicalize("0.0.0.0 ads.example.com"), "ads.example.com")

    def test_dnsmasq_domain(self):
        self.assertEqual(builder.canonicalize("address=/ads.example.com/#"), "ads.example.com")

    def test_reject_ip(self):
        self.assertIsNone(builder.canonicalize("1.2.3.4"))

    def test_allow_suffix(self):
        allow = {"example.com"}
        self.assertTrue(builder.is_allowed("a.b.example.com", allow))
        self.assertTrue(builder.is_allowed("example.com", allow))
        self.assertFalse(builder.is_allowed("notexample.com", allow))

if __name__ == "__main__":
    unittest.main()
