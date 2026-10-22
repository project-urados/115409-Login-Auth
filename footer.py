"""Globally configurable site footer.

The footer is defined entirely by `footer_config.json` (or the file named by the
FOOTER_CONFIG environment variable). It is self-contained: it does not depend on
any other module, and every page gets it through a context processor, so there
is nothing to edit in templates to change it.

Set `"enabled": false` in the config to hide it everywhere.
"""

import json
import os
from datetime import date
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("FOOTER_CONFIG", BASE_DIR / "footer_config.json"))

DEFAULTS = {
    "enabled": True,
    "brand": "Local Auth",
    "tagline": "",
    "columns": [],
    "copyright": "",
    "show_year": True,
}


def load_footer_config(path=CONFIG_PATH):
    """Load and sanitize the footer config. Invalid files fall back to defaults."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULTS)
    config = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    columns = []
    for column in config.get("columns") or []:
        if not isinstance(column, dict):
            continue
        links = []
        for link in column.get("links") or []:
            href = str(link.get("href", ""))
            # Only allow same-site paths and http(s) URLs.
            is_site_path = href.startswith("/") and not href.startswith("//")
            if is_site_path or href.startswith(("https://", "http://")):
                links.append({"label": str(link.get("label", href)), "href": href})
        columns.append({"title": str(column.get("title", "")), "links": links})
    config["columns"] = columns
    return config


FOOTER = load_footer_config()


def init_footer(app):
    """Register the footer context for all templates."""
    app.jinja_env.globals["footer"] = FOOTER
    app.jinja_env.globals["footer_year"] = date.today().year
