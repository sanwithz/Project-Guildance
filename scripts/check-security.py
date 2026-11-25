#!/usr/bin/env python3
"""Check the offline manual's CSP hashes and passive-document boundaries."""
import base64
import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path


class Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.policy = ""
        self.referrer = ""
        self.errors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            if attrs.get("http-equiv", "").lower() == "content-security-policy":
                self.policy = attrs.get("content", "")
            if attrs.get("name") == "referrer":
                self.referrer = attrs.get("content", "")
        if tag in {"form", "iframe", "object", "embed", "base", "link"}:
            self.errors.append(f"Unexpected active/resource element: {tag}")
        if tag == "input" and attrs.get("type") != "search":
            self.errors.append("Only local search inputs are permitted")
        if "src" in attrs or "srcset" in attrs:
            self.errors.append(f"Unexpected resource on {tag}")
        if any(key.startswith("on") or key == "style" for key in attrs):
            self.errors.append(f"Unexpected inline handler/style on {tag}")


path = Path(__file__).resolve().parents[1] / "ระบบจัดการทุนการศึกษา/index.html"
html = path.read_text(encoding="utf-8")
doc = Document()
doc.feed(html)
directives = {}
for item in doc.policy.split(";"):
    words = item.split()
    if words:
        directives[words[0]] = words[1:]
for key in ("default-src", "connect-src", "form-action", "base-uri", "object-src"):
    if directives.get(key) != ["'none'"]:
        doc.errors.append(f"{key} must deny all sources")
for tag, directive in (("script", "script-src"), ("style", "style-src")):
    blocks = re.findall(rf"<{tag}>([\s\S]*?)</{tag}>", html)
    expected = []
    for block in blocks:
        digest = base64.b64encode(hashlib.sha256(block.encode()).digest()).decode()
        expected.append(f"'sha256-{digest}'")
    if len(blocks) != 1 or directives.get(directive) != expected:
        doc.errors.append(f"{directive} must match the single inline {tag} hash")
if doc.referrer != "no-referrer":
    doc.errors.append("Missing no-referrer policy")
if doc.errors:
    raise SystemExit("\n".join(doc.errors))
print("PASS: CSP hashes, denied network/forms/resources, local-search-only markup, referrer policy")
