from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PAGES = ["index.html", "login.html", "setup-owner.html", "dashboard.html", "admin.html"]

class PageInspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.scripts = []
        self._script = None
        self._external = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "script":
            self._external = bool(attrs.get("src"))
            self._script = [] if not self._external else None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            source = "".join(self._script).strip()
            if source:
                self.scripts.append(source)
            self._script = None
            self._external = False

def main():
    checked_scripts = 0
    with tempfile.TemporaryDirectory() as temp:
        for page in PAGES:
            path = ROOT / "public" / page
            if not path.exists():
                raise AssertionError(f"Missing page: {page}")
            parser = PageInspector()
            parser.feed(path.read_text(encoding="utf-8"))
            duplicates = sorted(value for value, count in Counter(parser.ids).items() if count > 1)
            if duplicates:
                raise AssertionError(f"{page}: duplicate HTML id attributes: {', '.join(duplicates)}")
            for index, source in enumerate(parser.scripts):
                script_path = Path(temp) / f"{page.replace('.', '_')}_{index}.js"
                script_path.write_text(source, encoding="utf-8")
                result = subprocess.run(["node", "--check", str(script_path)], capture_output=True, text=True)
                if result.returncode:
                    raise AssertionError(f"{page}: inline script syntax error:\\n{result.stderr}")
                checked_scripts += 1
            print(f"{page}: OK ({len(parser.ids)} IDs, {len(parser.scripts)} inline scripts)")
    print(f"frontend: OK ({checked_scripts} inline scripts checked)")

if __name__ == "__main__":
    main()
