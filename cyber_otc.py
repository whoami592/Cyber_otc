#!/usr/bin/env python3
# ==============================================================================
#  CYBER OTC  —  All-In-One OSINT Reconnaissance Toolkit
#  Coded by: Mr Sabaz Ali Khan (Cyber Security Engineer)
#  Modules : Username Recon | Domain/WHOIS/DNS Recon | Phone OSINT | Dork Gen
# ==============================================================================

import os
import re
import sys
import json
import socket
import datetime
import urllib.request
import urllib.error
import concurrent.futures

# ---------------------------------------------------------------------------
# Optional third-party libs (tool still runs without them, with reduced info)
# ---------------------------------------------------------------------------
try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    import whois as pywhois
    HAVE_WHOIS = True
except ImportError:
    HAVE_WHOIS = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False


# ---------------------------------------------------------------------------
# Banner / Branding
# ---------------------------------------------------------------------------
BANNER = """
\033[1;36m
   ______      __              ____  ______________
  / ____/_  __/ /_  ___  _____/ __ \\/_  __/ ____/ (_)
 / /   / / / / __ \\/ _ \\/ ___/ / / / / / / /   / / /
/ /___/ /_/ / /_/ /  __/ /  / /_/ / / / / /___/ / /
\\____/\\__, /_.___/\\___/_/   \\____/ /_/  \\____/_/_/
     /____/
\033[0m
\033[1;33m          CYBER OTC — All-In-One OSINT Toolkit\033[0m
\033[1;32m   Coded by: Mr Sabaz Ali Khan (Cyber Security Engineer)\033[0m
\033[0;37m   ------------------------------------------------------\033[0m
"""

# Braille-style compact signature used across Mr Sabaz Ali Khan's tools
BRAILLE_TAG = "⠉⠽⠃⠑⠗ ⠕⠞⠉ ⠒ ⠍⠗ ⠎⠁⠃⠁⠵ ⠁⠇⠊ ⠅⠓⠁⠝"

DISCLAIMER = (
    "This tool is for EDUCATIONAL and AUTHORIZED SECURITY RESEARCH only.\n"
    "Only use it against targets you own or have explicit permission to test.\n"
    "The author (Mr Sabaz Ali Khan) assumes no liability for misuse."
)


def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print(f"\033[2m   {BRAILLE_TAG}\033[0m")
    print()
    print("\033[1;31m[!] DISCLAIMER\033[0m")
    print(DISCLAIMER)
    print()


# ---------------------------------------------------------------------------
# Report saving helper
# ---------------------------------------------------------------------------
REPORTS_DIR = "cyberotc_reports"


def save_report(name, data):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
    path = os.path.join(REPORTS_DIR, f"{safe_name}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"\033[1;32m[+] Report saved -> {path}\033[0m")
    return path


# ---------------------------------------------------------------------------
# MODULE 1: Username OSINT  (checks a username across many popular sites)
# ---------------------------------------------------------------------------
USERNAME_SITES = {
    "GitHub":        "https://github.com/{}",
    "GitLab":        "https://gitlab.com/{}",
    "Twitter/X":     "https://x.com/{}",
    "Instagram":     "https://www.instagram.com/{}/",
    "Facebook":      "https://www.facebook.com/{}",
    "TikTok":        "https://www.tiktok.com/@{}",
    "Reddit":        "https://www.reddit.com/user/{}",
    "YouTube":       "https://www.youtube.com/@{}",
    "Telegram":      "https://t.me/{}",
    "Pinterest":     "https://www.pinterest.com/{}/",
    "Medium":        "https://medium.com/@{}",
    "Twitch":        "https://www.twitch.tv/{}",
    "Steam":         "https://steamcommunity.com/id/{}",
    "DevTo":         "https://dev.to/{}",
    "Keybase":       "https://keybase.io/{}",
    "HackerNews":    "https://news.ycombinator.com/user?id={}",
    "Spotify":       "https://open.spotify.com/user/{}",
    "SoundCloud":    "https://soundcloud.com/{}",
    "LinkedIn":      "https://www.linkedin.com/in/{}",
    "Flickr":        "https://www.flickr.com/people/{}",
    "VK":            "https://vk.com/{}",
    "Snapchat":      "https://www.snapchat.com/add/{}",
    "Replit":        "https://replit.com/@{}",
    "ProductHunt":   "https://www.producthunt.com/@{}",
    "Codeforces":    "https://codeforces.com/profile/{}",
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


def _check_single_site(site, url_template, username, timeout=8):
    url = url_template.format(username)
    try:
        if HAVE_REQUESTS:
            resp = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
            status = resp.status_code
        else:
            req = urllib.request.Request(url, headers=HEADERS)
            try:
                resp = urllib.request.urlopen(req, timeout=timeout)
                status = resp.getcode()
            except urllib.error.HTTPError as e:
                status = e.code
        found = status in (200, 301, 302)
        return site, url, found, status
    except Exception as e:
        return site, url, None, f"error: {e}"


def username_osint(username, max_workers=15):
    print(f"\n\033[1;36m[*] Scanning {len(USERNAME_SITES)} platforms for username: {username}\033[0m\n")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(_check_single_site, site, tmpl, username)
            for site, tmpl in USERNAME_SITES.items()
        ]
        for fut in concurrent.futures.as_completed(futures):
            site, url, found, status = fut.result()
            results[site] = {"url": url, "found": found, "status": status}
            if found:
                print(f"\033[1;32m[FOUND]\033[0m   {site:<14} -> {url}")
            elif found is False:
                print(f"\033[0;31m[-]\033[0m        {site:<14} (not found)")
            else:
                print(f"\033[1;33m[ERROR]\033[0m   {site:<14} ({status})")

    hits = sum(1 for v in results.values() if v["found"])
    print(f"\n\033[1;36m[*] Done. {hits}/{len(results)} profiles likely exist for '{username}'.\033[0m")
    save_report(f"username_{username}", {"username": username, "results": results})
    return results


# ---------------------------------------------------------------------------
# MODULE 2: Domain / WHOIS / DNS Recon
# ---------------------------------------------------------------------------
def domain_recon(domain):
    print(f"\n\033[1;36m[*] Running domain recon on: {domain}\033[0m\n")
    report = {"domain": domain}

    # --- DNS resolution ---
    try:
        ip = socket.gethostbyname(domain)
        report["ip_address"] = ip
        print(f"\033[1;32m[+] IP Address:\033[0m {ip}")
    except socket.gaierror as e:
        report["ip_address"] = None
        print(f"\033[0;31m[-] DNS resolution failed: {e}\033[0m")

    # --- Common DNS record lookups via socket/getaddrinfo (stdlib-only path) ---
    try:
        addr_info = socket.getaddrinfo(domain, None)
        ips = sorted(set(a[4][0] for a in addr_info))
        report["resolved_addresses"] = ips
        print(f"\033[1;32m[+] Resolved Addresses:\033[0m {', '.join(ips)}")
    except Exception as e:
        report["resolved_addresses"] = []

    # --- Reverse DNS ---
    if report.get("ip_address"):
        try:
            rev = socket.gethostbyaddr(report["ip_address"])
            report["reverse_dns"] = rev[0]
            print(f"\033[1;32m[+] Reverse DNS:\033[0m {rev[0]}")
        except Exception:
            report["reverse_dns"] = None

    # --- WHOIS lookup ---
    if HAVE_WHOIS:
        try:
            w = pywhois.whois(domain)
            whois_data = {
                "registrar": str(w.get("registrar")),
                "creation_date": str(w.get("creation_date")),
                "expiration_date": str(w.get("expiration_date")),
                "updated_date": str(w.get("updated_date")),
                "name_servers": w.get("name_servers"),
                "emails": w.get("emails"),
                "org": w.get("org"),
                "country": w.get("country"),
            }
            report["whois"] = whois_data
            print("\033[1;32m[+] WHOIS Information:\033[0m")
            for k, v in whois_data.items():
                print(f"      {k:<15}: {v}")
        except Exception as e:
            report["whois"] = {"error": str(e)}
            print(f"\033[1;33m[!] WHOIS lookup failed: {e}\033[0m")
    else:
        print("\033[1;33m[!] 'python-whois' not installed — skipping WHOIS. "
              "Install with: pip install python-whois\033[0m")
        report["whois"] = "skipped (python-whois not installed)"

    # --- HTTP headers / tech fingerprint ---
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            if HAVE_REQUESTS:
                r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
                report["http_status"] = r.status_code
                report["server_header"] = r.headers.get("Server")
                report["final_url"] = r.url
                print(f"\033[1;32m[+] {scheme.upper()} Status:\033[0m {r.status_code}  "
                      f"Server: {r.headers.get('Server')}")
            else:
                req = urllib.request.Request(url, headers=HEADERS)
                r = urllib.request.urlopen(req, timeout=8)
                report["http_status"] = r.getcode()
                report["server_header"] = r.headers.get("Server")
            break
        except Exception as e:
            continue

    save_report(f"domain_{domain}", report)
    return report


# ---------------------------------------------------------------------------
# MODULE 3: Phone Number OSINT
# ---------------------------------------------------------------------------
def phone_osint(number):
    print(f"\n\033[1;36m[*] Analyzing phone number: {number}\033[0m\n")
    report = {"input": number}

    if not HAVE_PHONENUMBERS:
        print("\033[1;33m[!] 'phonenumbers' library not installed. "
              "Install with: pip install phonenumbers\033[0m")
        report["error"] = "phonenumbers library not installed"
        save_report(f"phone_{number}", report)
        return report

    try:
        parsed = phonenumbers.parse(number, None)
        report["valid"] = phonenumbers.is_valid_number(parsed)
        report["possible"] = phonenumbers.is_possible_number(parsed)
        report["country_code"] = parsed.country_code
        report["national_number"] = parsed.national_number
        report["region"] = geocoder.description_for_number(parsed, "en")
        report["carrier"] = carrier.name_for_number(parsed, "en")
        report["timezones"] = list(pn_timezone.time_zones_for_number(parsed))
        report["e164_format"] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )
        report["international_format"] = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        report["number_type"] = str(phonenumbers.number_type(parsed))

        print(f"\033[1;32m[+] Valid:\033[0m        {report['valid']}")
        print(f"\033[1;32m[+] Region:\033[0m       {report['region']}")
        print(f"\033[1;32m[+] Carrier:\033[0m      {report['carrier']}")
        print(f"\033[1;32m[+] Timezones:\033[0m    {', '.join(report['timezones'])}")
        print(f"\033[1;32m[+] E.164:\033[0m        {report['e164_format']}")
        print(f"\033[1;32m[+] Intl Format:\033[0m  {report['international_format']}")
        print(f"\033[1;32m[+] Line Type:\033[0m    {report['number_type']}")
    except phonenumbers.NumberParseException as e:
        report["error"] = str(e)
        print(f"\033[0;31m[-] Could not parse number: {e}\033[0m")

    save_report(f"phone_{number}", report)
    return report


# ---------------------------------------------------------------------------
# MODULE 4: Google Dork Generator (query builder — does not auto-scrape Google)
# ---------------------------------------------------------------------------
DORK_TEMPLATES = {
    "Exposed login panels":        'site:{t} inurl:login',
    "Indexed PDF documents":       'site:{t} filetype:pdf',
    "Indexed Excel/CSV sheets":    'site:{t} (filetype:xls OR filetype:xlsx OR filetype:csv)',
    "Config / env files":          'site:{t} (ext:env OR ext:ini OR ext:conf OR ext:config)',
    "Exposed directory listing":   'site:{t} intitle:"index of /"',
    "SQL error leakage":           'site:{t} intext:"sql syntax near"',
    "Backup files":                'site:{t} (ext:bak OR ext:old OR ext:backup)',
    "Admin / phpMyAdmin panels":   'site:{t} inurl:phpmyadmin',
    "Exposed API keys":            'site:{t} intext:"api_key" filetype:json',
    "Git repo leakage":            'site:{t} inurl:".git"',
    "Pastebin mentions":           'site:pastebin.com "{t}"',
    "LinkedIn employees":          'site:linkedin.com/in "{t}"',
    "Subdomain discovery":         'site:*.{t} -www',
}


def dork_generator(target):
    print(f"\n\033[1;36m[*] Google Dorks generated for: {target}\033[0m\n")
    report = {"target": target, "dorks": {}}
    for label, tmpl in DORK_TEMPLATES.items():
        query = tmpl.format(t=target)
        report["dorks"][label] = query
        print(f"\033[1;33m[{label}]\033[0m\n   {query}\n")
    save_report(f"dorks_{target}", report)
    return report


# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------
def main_menu():
    while True:
        show_banner()
        print("\033[1;36m[1]\033[0m Username OSINT        (scan 25+ platforms)")
        print("\033[1;36m[2]\033[0m Domain / WHOIS / DNS Recon")
        print("\033[1;36m[3]\033[0m Phone Number OSINT")
        print("\033[1;36m[4]\033[0m Google Dork Generator")
        print("\033[1;36m[5]\033[0m Exit")
        choice = input("\n\033[1;35mCYBER-OTC > \033[0m").strip()

        if choice == "1":
            uname = input("Enter username: ").strip()
            if uname:
                username_osint(uname)
        elif choice == "2":
            dom = input("Enter domain (e.g. example.com): ").strip()
            if dom:
                domain_recon(dom)
        elif choice == "3":
            num = input("Enter phone number (E.164, e.g. +923001234567): ").strip()
            if num:
                phone_osint(num)
        elif choice == "4":
            tgt = input("Enter target domain/company for dorks: ").strip()
            if tgt:
                dork_generator(tgt)
        elif choice == "5":
            print("\n\033[1;32m[+] Exiting Cyber OTC. Stay ethical. — Mr Sabaz Ali Khan\033[0m")
            sys.exit(0)
        else:
            print("\033[0;31m[-] Invalid choice.\033[0m")

        input("\n\033[2mPress Enter to return to menu...\033[0m")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Interrupted by user. Exiting.\033[0m")
        sys.exit(0)
