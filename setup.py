"""Compatibility entry point for older pip and setuptools versions."""

from pathlib import Path

from setuptools import find_packages, setup


ROOT = Path(__file__).parent

setup(
    name="public-log-scrubber",
    version="0.1.0",
    description=(
        "Remove common credentials and personal identifiers from logs "
        "before sharing them."
    ),
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages("src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "log-scrub=public_log_scrubber.cli:main",
        ]
    },
)
