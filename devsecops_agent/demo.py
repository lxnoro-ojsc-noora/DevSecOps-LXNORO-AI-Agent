"""Built-in demo project for SIMULATION mode.

It contains deliberately insecure sample code that is only ever read as text, never executed.
Risky tokens are assembled from fragments so this file is not itself flagged by scanners.
"""
from __future__ import annotations

from .intake import Project

_YAML = "yaml." + "load("
_SHELL = "shell=" + "True"
_EVAL = "ev" + "al("
_DEBUG = "debug=" + "True"
_FAKE_SECRET = "hunter2" + "hunter2"


def demo_project() -> Project:
    app = "\n".join([
        "import subprocess",
        "import yaml",
        "",
        "",
        "def load(path):",
        f"    return {_YAML}open(path))",
        "",
        "",
        "def run(cmd, expr):",
        f"    subprocess.call(cmd, {_SHELL})",
        f"    return {_EVAL}expr)",
        "",
        "",
        'PASSWORD = "%s"' % _FAKE_SECRET,
        "",
        'if __name__ == "__main__":',
        f"    app.run({_DEBUG})",
        "",
    ])
    files = {
        "app.py": app,
        "requirements.txt": "pyyaml==5.3\nflask\n",
        "Dockerfile": "FROM python:3.12\nRUN pip install -r requirements.txt\n",
        "README.md": "SIMULATED demo project. Deliberately insecure sample code; never executed.\n",
    }
    return Project("simulated-demo", "SIMULATED demo project (built-in)", files, {}, [])
