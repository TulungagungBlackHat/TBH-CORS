#!/usr/bin/env python3
# TBH-CORS - Misconfig Detector
import requests, argparse, json

BANNER = """\033[91m╔════════════════════════════════════╗
\033[91m║ \033[97mTBH-CORS \033[91m- Misconfig Detector     \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404 \033[91m║
\033[91m╚════════════════════════════════════╝\033[0m"""

def check(url):
    origin="https://evil.com"
    try:
        r=requests.get(url,timeout=5,headers={'Origin':origin,'User-Agent':'TBH-CORS/1.0'})
        acao=r.headers.get('Access-Control-Allow-Origin','')
        acac=r.headers.get('Access-Control-Allow-Credentials','')
        vulnerable=acao==origin or acao=="*"
        if acao=="*" and acac=="true": vulnerable=True
        return {"url":url,"acao":acao,"acac":acac,"vulnerable":vulnerable,"status":r.status_code}
    except Exception as e:
        return {"url":url,"error":str(e),"vulnerable":False}

def main():
    print(BANNER)
    print("\033[91m[!] Hanya untuk scope yang diizinkan!\033[0m\n")
    parser=argparse.ArgumentParser(description="CORS")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    args=parser.parse_args()
    print(f"[*] Testing {args.url} dengan Origin: https://evil.com")
    result=check(args.url)
    if result.get("vulnerable"):
        print(f"\033[91m[!] Vulnerable! ACAO: {result['acao']} ACAC: {result['acac']}\033[0m -> Potensi High, laporkan!")
    else:
        print(f"\033[92m[✓] Tidak vulnerable ACAO: {result.get('acao') or 'none'} [{result.get('status')}]\033[0m")
    if args.json:
        open(args.json,'w').write(json.dumps(result,indent=2)); print(f"[✓] JSON: {args.json}")

if __name__=="__main__": main()
