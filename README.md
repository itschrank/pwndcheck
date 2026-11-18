# pwndcheck

Kleines Python-Tool, das E-Mail-Adressen aus einer Textdatei gegen die
[Have I Been Pwned API v3](https://haveibeenpwned.com/API/v3) prüft und das
Ergebnis in eine Datei schreibt.

**Author:** Crashkid ([github.com/itschrank](https://github.com/itschrank))

## Features

- Liest E-Mail-Adressen zeilenweise aus `input.txt`
- Leere Zeilen, Duplikate und `#`-Kommentare werden ignoriert
- Schreibt Ergebnisse (inkl. Namen der Breaches) nach `output.txt`
- Beachtet das Rate Limit der API (`Retry-After`)
- Keine externen Abhängigkeiten, nur Python 3.7+ Standardbibliothek

## Voraussetzungen

Für die Abfrage von E-Mail-Adressen verlangt HIBP einen **API-Key**
(kostenpflichtig): <https://haveibeenpwned.com/API/Key>

## Benutzung

`input.txt` anlegen, eine Adresse pro Zeile:

```
max@example.com
erika@example.org
```

API-Key setzen und starten:

```bash
# Linux / macOS
export HIBP_API_KEY="dein-key"
python3 pwndcheck.py

# Windows (PowerShell)
$env:HIBP_API_KEY="dein-key"
python pwndcheck.py
```

Alternativ kannst du den Key direkt im Script in der Variable `API_KEY` eintragen
(ganz oben in `pwndcheck.py`). Dann brauchst du keine Umgebungsvariable.
**Wichtig:** Committe das Script dann nicht mit eingetragenem Key auf GitHub.

Die Reihenfolge ist: `--api-key` > `HIBP_API_KEY` > `API_KEY` im Script.

Optionen:

```
-i, --input     Eingabedatei  (Standard: input.txt)
-o, --output    Ausgabedatei  (Standard: output.txt)
-k, --api-key   API-Key (alternativ HIBP_API_KEY)
-d, --delay     Pause zwischen Anfragen in Sekunden (Standard: 1.6)
```

## Beispiel-Ausgabe

```
[PWNED] max@example.com - 2 Breach(es): Adobe, LinkedIn
[OK]    erika@example.org - in keinem bekannten Breach gefunden

# Zusammenfassung: 2 geprüft, 1 betroffen, 0 Fehler
```

## Hinweis

Prüfe nur E-Mail-Adressen, die dir gehören oder für die du eine Erlaubnis hast.
Die Nutzungsbedingungen von HIBP gelten: <https://haveibeenpwned.com/API/v3#AcceptableUse>

## Lizenz

MIT - © Crashkid
