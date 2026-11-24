"""Test 9/9 — PWA/UI structure smoke tests (accessibility landmarks, design
system tokens, manifest validity, offline shell). Catches broken markup without
a browser."""
import json
import re
import unittest
from pathlib import Path

from tests import REPO_ROOT  # noqa: F401

WEB = REPO_ROOT / "web"


class TestIndexHtml(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (WEB / "index.html").read_text(encoding="utf-8")

    def test_required_views_exist(self):
        for view in ("dashboard", "fleet", "map", "analytics", "safety",
                     "maintenance", "executive", "copilot", "settings"):
            self.assertIn(f'id="view-{view}"', self.html, f"missing view: {view}")

    def test_accessibility_landmarks(self):
        self.assertIn("skip-link", self.html)             # skip to content
        self.assertRegex(self.html, r'<main[^>]*id="main"')
        self.assertIn('aria-label="Primary"', self.html)  # labelled nav
        self.assertIn('aria-live', self.html)             # live regions

    def test_pwa_wiring(self):
        self.assertIn('rel="manifest"', self.html)
        self.assertIn('name="theme-color"', self.html)
        # Service worker registration lives in the boot script.
        self.assertIn("serviceWorker", (WEB / "js" / "app.js").read_text())

    def test_viewport_meta_allows_mobile_scaling(self):
        m = re.search(r'<meta name="viewport" content="([^"]+)"', self.html)
        self.assertIsNotNone(m)
        self.assertIn("width=device-width", m.group(1))

    def test_scripts_are_classic_not_modules(self):
        # ES modules break file:// double-click launch; classic scripts keep the
        # zero-setup promise on every device.
        self.assertNotIn('type="module"', self.html)
        self.assertIn("js/app.js", self.html)


class TestManifest(unittest.TestCase):
    def test_manifest_valid_and_complete(self):
        data = json.loads((WEB / "manifest.webmanifest").read_text())
        for key in ("name", "short_name", "start_url", "display",
                    "background_color", "theme_color", "icons"):
            self.assertIn(key, data)
        self.assertEqual(data["display"], "standalone")
        sizes = {i.get("sizes") for i in data["icons"]}
        self.assertIn("512x512", sizes)

    def test_icon_file_exists(self):
        self.assertTrue((WEB / "icons" / "icon-512.png").is_file())


class TestServiceWorker(unittest.TestCase):
    def test_sw_caches_app_shell(self):
        sw = (WEB / "sw.js").read_text()
        self.assertIn("caches", sw)
        self.assertIn("fetch", sw)
        self.assertIn("index.html", sw)


class TestDesignSystem(unittest.TestCase):
    def test_css_defines_status_palette_and_tokens(self):
        css = (WEB / "css" / "app.css").read_text()
        for token in ("--color-ok", "--color-warn", "--color-attn",
                      "--color-crit", "--color-info", "--bg-0", "--panel",
                      "--font-mono"):
            self.assertIn(token, css)

    def test_css_respects_user_preferences(self):
        css = (WEB / "css" / "app.css").read_text()
        self.assertIn("prefers-reduced-motion", css)
        self.assertIn("prefers-contrast", css)

    def test_js_files_exist(self):
        for name in ("app.js", "charts.js", "state.js", "copilot.js",
                     "views.js", "ui.js"):
            self.assertTrue((WEB / "js" / name).is_file(), f"missing js/{name}")


if __name__ == "__main__":
    unittest.main()
