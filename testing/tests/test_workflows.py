"""Every workflow file must be valid YAML (an invalid one silently never runs: this has happened twice)."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Workflows(unittest.TestCase):
    def test_all_workflow_files_parse_and_define_jobs(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        files = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(files)
        for path in files:
            with self.subTest(path.name):
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)
                self.assertTrue(data.get("jobs"), "no jobs: GitHub would reject this file")
                self.assertTrue("on" in data or True in data, "no trigger")  # YAML 1.1 parses `on` as True


if __name__ == "__main__":
    unittest.main()
