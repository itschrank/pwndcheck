#!/usr/bin/env python3
"""
pwndcheck - prüft E-Mail-Adressen gegen die Have I Been Pwned API (v3).

Liest E-Mail-Adressen zeilenweise aus einer Eingabedatei (Standard: input.txt),
fragt für jede Adresse die HIBP-API ab und schreibt das Ergebnis in eine
Ausgabedatei (Standard: output.txt).

Author:  Crashkid
GitHub:  https://github.com/itschrank
API:     https://haveibeenpwned.com/API/v3
Lizenz:  MIT

Hinweis: Für die Abfrage von E-Mail-Adressen (breachedaccount) benötigt die
HIBP-API einen kostenpflichtigen API-Key: https://haveibeenpwned.com/API/Key
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__author__ = "Crashkid"
__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Hier kannst du deinen HIBP API-Key direkt eintragen (optional).
# Reihenfolge: --api-key (Kommandozeile) > Umgebungsvariable HIBP_API_KEY > API_KEY
# ACHTUNG: Den Key niemals mit eingetragenem Wert auf GitHub veröffentlichen!
# ---------------------------------------------------------------------------
API_KEY = ""

API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
USER_AGENT = "pwndcheck/{} (by Crashkid; https://github.com/itschrank)".format(__version__)
MAX_RETRIES = 5


def read_emails(path):
    """Liest E-Mail-Adressen zeilenweise ein (leere Zeilen und #-Kommentare werden ignoriert)."""
    emails = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            email = line.strip()
            if not email or email.startswith("#"):
                continue
            key = email.lower()
            if key in seen:
                continue
            seen.add(key)
            emails.append(email)
    return emails


def check_email(email, api_key, timeout=15):
    """
    Fragt HIBP für eine E-Mail-Adresse ab.

    Rückgabe: (status, daten)
      status "pwned"  -> daten = Liste der Breach-Namen
      status "clean"  -> daten = []
      status "error"  -> daten = Fehlermeldung (str)
    """
    url = API_URL.format(account=urllib.parse.quote(email, safe="")) + "?truncateResponse=true"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": USER_AGENT,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return "pwned", [b.get("Name", "?") for b in body]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "clean", []
            if e.code == 429:
                # Rate Limit: so lange warten, wie die API es vorgibt
                wait = int(e.headers.get("Retry-After", "5")) + 1
                print("  Rate Limit erreicht, warte {}s (Versuch {}/{})".format(wait, attempt, MAX_RETRIES))
                time.sleep(wait)
                continue
            if e.code == 401:
                return "error", "401 Unauthorized - API-Key ungültig oder fehlt"
            if e.code == 400:
                return "error", "400 Bad Request - ungültige E-Mail-Adresse?"
            if e.code == 403:
                return "error", "403 Forbidden - User-Agent fehlt/ungültig"
            return "error", "HTTP {} {}".format(e.code, e.reason)
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == MAX_RETRIES:
                return "error", "Netzwerkfehler: {}".format(e)
            time.sleep(2 * attempt)
    return "error", "Zu viele Rate-Limit-Antworten"


def main():
    parser = argparse.ArgumentParser(
        prog="pwndcheck",
        description="Prüft E-Mail-Adressen aus einer Datei gegen Have I Been Pwned.",
    )
    parser.add_argument("-i", "--input", default="input.txt", help="Eingabedatei (Standard: input.txt)")
    parser.add_argument("-o", "--output", default="output.txt", help="Ausgabedatei (Standard: output.txt)")
    parser.add_argument("-k", "--api-key", default=os.environ.get("HIBP_API_KEY") or API_KEY,
                        help="HIBP API-Key (oder Umgebungsvariable HIBP_API_KEY, oder API_KEY im Script)")
    parser.add_argument("-d", "--delay", type=float, default=1.6,
                        help="Pause zwischen Anfragen in Sekunden (Standard: 1.6)")
    parser.add_argument("--version", action="version", version="%(prog)s {} by Crashkid".format(__version__))
    args = parser.parse_args()

    if not args.api_key:
        print("Fehler: Kein API-Key angegeben. Nutze --api-key, setze HIBP_API_KEY "
              "oder trage ihn in der Variable API_KEY im Script ein.", file=sys.stderr)
        print("API-Key kaufen: https://haveibeenpwned.com/API/Key", file=sys.stderr)
        return 1

    try:
        emails = read_emails(args.input)
    except FileNotFoundError:
        print("Fehler: Eingabedatei '{}' nicht gefunden.".format(args.input), file=sys.stderr)
        return 1

    if not emails:
        print("Keine E-Mail-Adressen in '{}' gefunden.".format(args.input))
        return 0

    print("pwndcheck by Crashkid - prüfe {} Adresse(n)...".format(len(emails)))

    pwned_count = 0
    error_count = 0

    with open(args.output, "w", encoding="utf-8") as out:
        for idx, email in enumerate(emails, start=1):
            status, data = check_email(email, args.api_key)

            if status == "pwned":
                pwned_count += 1
                line = "[PWNED] {} - {} Breach(es): {}".format(email, len(data), ", ".join(data))
            elif status == "clean":
                line = "[OK]    {} - in keinem bekannten Breach gefunden".format(email)
            else:
                error_count += 1
                line = "[ERROR] {} - {}".format(email, data)

            print("({}/{}) {}".format(idx, len(emails), line))
            out.write(line + "\n")
            out.flush()

            if idx < len(emails):
                time.sleep(args.delay)

        summary = "\n# Zusammenfassung: {} geprüft, {} betroffen, {} Fehler".format(
            len(emails), pwned_count, error_count)
        out.write(summary + "\n")

    print(summary.strip())
    print("Ergebnis gespeichert in '{}'.".format(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
