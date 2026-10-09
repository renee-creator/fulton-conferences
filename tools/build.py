"""Builds index.html from src/app.html (the conference app) and src/shim.html (sign-in and server connection).
Run from the repository folder with  python3 tools/build.py"""
import pathlib
root = pathlib.Path(__file__).resolve().parent.parent
app = (root / "src/app.html").read_text()
shim = (root / "src/shim.html").read_text()
marker = '<script>\n"use strict";\n/* ---------- constants'
assert app.count(marker) == 1, "app script marker not found"
head = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n'
        '<meta name="robots" content="noindex,nofollow">\n'
        '<link rel="manifest" href="manifest.json?v=2">\n'
        '<link rel="apple-touch-icon" href="icons/icon-180.png?v=2">\n'
        '<link rel="icon" type="image/png" sizes="32x32" href="icons/icon-32.png?v=2">\n'
        '<meta name="theme-color" content="#2E5B44">\n'
        '<meta name="apple-mobile-web-app-capable" content="yes">\n'
        '<meta name="mobile-web-app-capable" content="yes">\n'
        '<meta name="apple-mobile-web-app-title" content="Conferences">\n'
        '<meta name="apple-mobile-web-app-status-bar-style" content="default">\n'
        '<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}'
        'body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>\n</head>\n<body>\n')
out = head + app.replace(marker, shim + "\n" + marker) + "\n</body>\n</html>\n"
(root / "index.html").write_text(out)
print("index.html", len(out), "bytes")
