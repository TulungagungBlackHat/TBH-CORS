# TBH-CORS

<p align="center">
  <a href="https://github.com/TulungagungBlackHat/TBH-CORS/actions/workflows/ci.yml"><img src="https://github.com/TulungagungBlackHat/TBH-CORS/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/severity-high-red.svg" alt="Severity">
</p>

CORS misconfiguration detector. Sends an attacker-controlled `Origin` header and inspects what the server echoes back.

Part of the [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) toolset.

## What It Checks

- `Access-Control-Allow-Origin` reflection of `https://evil.com`
- Dangerous `*` combined with `Access-Control-Allow-Credentials: true`
- Both ACAO and ACAC values in the result, for accurate severity rating

| Response | Severity |
|----------|----------|
| ACAO echoes arbitrary origin **+** ACAC true | High — cross-origin credentialed reads |
| ACAO `*` with ACAC true | High (spec-violating, some browsers still unsafe) |
| ACAO `*` without credentials | Low/Info — usually intended for public APIs |
| ACAO allowlist | OK |

## Install

```bash
git clone https://github.com/TulungagungBlackHat/TBH-CORS
cd TBH-CORS
pip install -r requirements.txt
```

## Usage

```
usage: cors.py [-h] -u URL [--json JSON]

options:
  -u, --url URL     Target URL
  --json JSON       Save result as JSON
```

```bash
python3 cors.py -u "https://example.com/api/user" --json result.json
```

## Sample Output

```
[*] Testing https://example.com/api/user dengan Origin: https://evil.com
[!] Vulnerable! ACAO: https://evil.com ACAC: true -> Potensi High, laporkan!
[✓] JSON: result.json
```

## Authorized Use Only

Only against scopes you own or are authorized to test. See [SECURITY.md](SECURITY.md).

## Related Tools

- [TBH-Recon](https://github.com/TulungagungBlackHat/TBH-Recon) — header audit includes CORS-related headers
- [TBH-AllScan](https://github.com/TulungagungBlackHat/TBH-AllScan) — CORS module inside the 10-in-one scan

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
