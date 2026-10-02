import importlib.util
import unittest
from pathlib import Path

P = Path(__file__).resolve().parents[1] / "src" / "build_firebog_intel_v5.py"
spec = importlib.util.spec_from_file_location("intel", P)
intel = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(intel)

class IntelParserTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(intel.normalize("Example.COM"), "example.com")
    def test_hosts(self):
        self.assertEqual(intel.normalize("0.0.0.0 ads.example.com"), "ads.example.com")
    def test_adblock(self):
        self.assertEqual(intel.normalize("||tracker.example.com^"), "tracker.example.com")
    def test_wildcard(self):
        self.assertEqual(intel.normalize("*.foo.example.com"), "foo.example.com")
    def test_url_rejected(self):
        self.assertIsNone(intel.normalize("https://example.com/path"))
    def test_ip_rejected(self):
        self.assertIsNone(intel.normalize("1.2.3.4"))

if __name__ == "__main__":
    unittest.main()
