from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PAGES = ["index.html", "login.html", "setup-owner.html", "dashboard.html", "admin.html", "community.html", "owner-inbox.html"]

class PageInspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.scripts = []
        self.asset_refs = []
        self._script = None
        self._external = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        for key in ("src", "href"):
            value = attrs.get(key, "").split("?", 1)[0]
            if value.startswith("/assets/"):
                self.asset_refs.append(value)
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
    worker_source = (ROOT / "src" / "index.js").read_text(encoding="utf-8")
    if '"/assets/cyrus-hero.webp"' not in worker_source:
        raise AssertionError("Worker static allowlist is missing the Cyrus logo/hero image")
    if 'binaryAsset ? "arrayBuffer" : "text"' not in worker_source or '"image/webp"' not in worker_source:
        raise AssertionError("Worker must serve WebP as binary image/webp, not UTF-8 text")
    public_dir = ROOT / "public"
    webp_assets = list(public_dir.rglob("*.webp"))
    if not webp_assets:
        raise AssertionError("No optimized WebP images found in public assets")
    legacy_images = [path for path in public_dir.rglob("*") if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}]
    if legacy_images:
        raise AssertionError("Convert static images to WebP: " + ", ".join(str(path.relative_to(ROOT)) for path in legacy_images))
    for image_path in webp_assets:
        image_bytes = image_path.read_bytes()
        if len(image_bytes) < 16 or image_bytes[:4] != b"RIFF" or image_bytes[8:12] != b"WEBP":
            raise AssertionError(f"Invalid WebP image: {image_path.relative_to(ROOT)}")
    with tempfile.TemporaryDirectory() as temp:
        for page in PAGES:
            path = ROOT / "public" / page
            if not path.exists():
                raise AssertionError(f"Missing page: {page}")
            parser = PageInspector()
            parser.feed(path.read_text(encoding="utf-8"))
            for asset in parser.asset_refs:
                if asset not in worker_source:
                    raise AssertionError(f"{page}: static asset is not allowlisted by the Worker: {asset}")
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
