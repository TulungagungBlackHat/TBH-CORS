#!/usr/bin/env python3
"""TBH-CORS v3 - CORS misconfiguration detector (authorized testing only)."""
import argparse, json, os, sys, time

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-CORS"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-CORS v3\033[91m - Misconfig Detector   \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-CORS/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if not val:
            raise SystemExit(f"[!] bad -H value: {h!r}")
        s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def grade(acao, acac, origin):
    if acao == origin and acac.lower() == "true":
        return "high", "arbitrary origin reflected with credentials"
    if acao == origin:
        return "medium", "arbitrary origin reflected (no credentials)"
    if acao == "*" and acac.lower() == "true":
        return "high", "wildcard ACAO combined with credentials (spec violation)"
    if acao == "*":
        return "low", "wildcard ACAO without credentials"
    if acao == "null" and acac.lower() == "true":
        return "medium", "null origin allowed with credentials (sandboxed iframe abuse)"
    return "ok", "no dangerous ACAO behavior"

def probe(session, url, origin_header, origin_label, args):
    headers = {}
    if origin_header is not None:
        headers["Origin"] = origin_header
    try:
        r = session.get(url, timeout=args.timeout, headers=headers, allow_redirects=True)
    except requests.RequestException as e:
        return {"origin": origin_label, "error": str(e), "severity": "error"}
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    severity, note = grade(acao, acac, origin_header) if origin_header else ("ok", "baseline")
    return {"origin": origin_label, "sent_origin": origin_header, "status": r.status_code,
            "acao": acao, "acac": acac, "severity": severity, "note": note}

def scan(session, url, args):
    tests = [
        ("https://evil.com", "evil.com"),
        ("https://evil.com", None),  # no Origin: baseline response headers
        (None, "null"),  # send Origin: null below
    ]
    results = []
    for origin, label in tests:
        if label == "null":
            results.append(probe(session, url, "null", "Origin: null", args))
        else:
            results.append(probe(session, url, origin, label, args))
        if args.delay:
            time.sleep(args.delay)
    return {"tool": "TBH-CORS", "version": VERSION, "target": url, "findings": results}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-CORS v{VERSION} - CORS misconfig detector")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-CORS {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only.", use_color))
    print(f"[*] Probing {args.url} with attacker origins")
    try:
        session = build_session(args)
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    report = scan(session, args.url, args)

    worst = "ok"
    order = ["ok", "low", "medium", "high", "error"]
    for f in report["findings"]:
        if "error" in f:
            print(color("90", f"[-] {f['origin']}: {f['error']}", use_color))
            continue
        line = f"ACAO={f['acao'] or '-'} ACAC={f['acac'] or '-'} [{f['severity']}] {f['note']}"
        if f["severity"] in ("high", "medium"):
            print(color("91", f"[!] {f['origin']}: {line}", use_color))
        elif f["severity"] == "low":
            print(color("93", f"[?] {f['origin']}: {line}", use_color))
        else:
            print(color("90", f"[-] {f['origin']}: {line}", use_color))
        if order.index(f["severity"]) > order.index(worst):
            worst = f["severity"]

    if args.json:
        report["summary"] = {"worst_severity": worst}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if worst == "high":
        print(color("91", "[!] High-severity CORS misconfiguration - report with PoC", use_color))
        sys.exit(1)
    if worst in ("medium", "low"):
        print(color("93", "[?] Partial misconfiguration - evaluate impact in context", use_color))
        sys.exit(1)
    print(color("92", "[✓] No dangerous CORS behavior detected", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
