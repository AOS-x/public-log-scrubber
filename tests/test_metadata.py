import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MetadataTests(unittest.TestCase):
    def test_package_and_project_versions_match(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        init = (ROOT / "src/public_log_scrubber/__init__.py").read_text(
            encoding="utf-8"
        )
        project_version = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
        package_version = re.search(r'^__version__ = "([^"]+)"$', init, re.MULTILINE)

        self.assertIsNotNone(project_version)
        self.assertIsNotNone(package_version)
        assert project_version is not None
        assert package_version is not None
        self.assertEqual(project_version.group(1), package_version.group(1))

    def test_both_console_commands_and_typed_marker_are_packaged(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('log-scrub = "public_log_scrubber.cli:main"', pyproject)
        self.assertIn(
            'log-scrub-pre-commit = "public_log_scrubber.precommit:main"',
            pyproject,
        )
        self.assertTrue((ROOT / "src/public_log_scrubber/py.typed").is_file())


if __name__ == "__main__":
    unittest.main()
