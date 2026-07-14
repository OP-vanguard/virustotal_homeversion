# IOC Extractor — Threat Triage Tool

A full-stack malware/IOC triage tool built in Python and Flask, inspired by VirusTotal-style
lookups. Accepts a file, hash, IP address, domain, or URL and returns a structured threat
report: VirusTotal reputation data, static behavioral analysis (for files), MITRE ATT&CK
technique mapping, and concrete detection/mitigation guidance.

Built as a hands-on project while working through the TryHackMe SOC Level 1 path and
CompTIA Security+ study — the goal was to go beyond "run a lookup" and actually reason
about how a triage tool should combine multiple signals (VT detection consensus + static
behavioral analysis) into one verdict, the way a SOC analyst would.

---

## What it does

Given any of the five supported target types, the tool:

1. **Files** — computes MD5/SHA1/SHA256 hashes, extracts printable strings (ASCII + UTF-16LE
   wide-char), regex-matches for network IOCs (IPs, URLs, domains) and behavioral IOCs
   (suspicious WinAPI imports, registry key writes, suspicious file paths), maps matched
   behavior to MITRE ATT&CK techniques with a confidence-weighted risk score, and attaches
   concrete detection/mitigation guidance per technique.
2. **Hashes** — looks up an existing VirusTotal record without needing the original file.
3. **IPs** — VT reputation lookup: detection ratio, country, ASN, AS owner, network range.
4. **Domains** — VT reputation lookup: detection ratio, registrar, creation date, categories.
5. **URLs** — VT reputation lookup: detection ratio, final redirected URL, page title.

All five paths feed into a single **overall verdict** (CLEAN / SUSPICIOUS / MALICIOUS) computed
from VirusTotal's raw malicious-engine count, so a file with zero suspicious API calls but a
high VT detection count (e.g. a known signature like EICAR) still gets correctly flagged —
static behavioral analysis and real-world engine consensus are two different signals, and the
tool doesn't let one silently override the other.

---

## Architecture

```
vt/
├── modules/
│   ├── hasher.py            # MD5/SHA1/SHA256 hashing
│   ├── string_extractor.py   # ASCII + UTF-16LE string extraction, IOC regex matching
│   ├── vt_client.py           # VirusTotal API v3 client (files, IPs, domains, URLs)
│   ├── mitre_mapper.py         # Static behavior -> MITRE ATT&CK technique mapping
│   ├── remediation.py           # Technique ID -> detection/mitigation guidance
│   └── report.py                 # Combines all module output into one report + verdict
├── ioc_extractor.py            # CLI entry point / run_analysis() core pipeline function
├── app.py                       # Flask web frontend
├── templates/
│   └── index.html                # Single-page dark-themed UI (SOC terminal aesthetic)
└── .env                           # VT_API_KEY=... (not committed to git)
```

**Design note:** `ioc_extractor.py`'s pipeline logic lives in `run_analysis(target) -> dict`,
a pure function with no printing or `sys.exit()` calls, callable from anywhere. `main()` is a
thin CLI wrapper around it, and `app.py`'s `/analyze` route calls the same function — the CLI
and the web app share one core pipeline, so a fix in one place applies everywhere.

Each module was built and tested independently before being chained together
(`test_pipeline.py` was used during development to test the extraction → MITRE mapping →
remediation chain without needing the web layer).

---

## Setup

**Requirements:**
```bash
pip install requests python-dotenv flask --break-system-packages
```

**VirusTotal API key:**

Create a `.env` file in the project root:
```
VT_API_KEY=your_key_here
```
Get a free key at [virustotal.com](https://www.virustotal.com) (free tier: 4 requests/minute).

---

## Usage

**CLI:**
```bash
python3 ioc_extractor.py <file_path | hash | ip | domain | url>
python3 ioc_extractor.py suspicious_file.exe
python3 ioc_extractor.py 44d88612fea8a8f36de82e1278abb02f
python3 ioc_extractor.py 8.8.8.8
python3 ioc_extractor.py example.com
python3 ioc_extractor.py https://example.com/path
```
Outputs a readable terminal report and saves a JSON report (`report_output.json` by default,
override with `-o`).

**Web app:**
```bash
python3 app.py
```
Open `http://127.0.0.1:5000`. Type a hash/IP/domain/URL into the text field, or use the file
picker to upload a file for full static analysis. Results render in a tabbed view: Overview,
Static IOCs, MITRE ATT&CK (click a technique row to expand detection/mitigation steps), and
Raw JSON.

---

## MITRE ATT&CK mapping logic

Static string-level heuristics, not disassembly. `string_extractor.py` extracts printable
strings and regex-matches for suspicious WinAPI import names (`VirtualAllocEx`,
`WriteProcessMemory`, `RegSetValueEx`, etc.), registry key paths, and suspicious file paths.
`mitre_mapper.py` maps matched indicators to specific technique IDs with a per-rule confidence
weight and severity, then computes an aggregate risk score. A technique only reaches the top
verdict tier (via confidence weighting) if at least one HIGH-severity indicator is present —
a single low-confidence match (e.g. one URL string) doesn't alone push a file to a high-risk
verdict.

`remediation.py` attaches 2-3 concrete detection steps (Sysmon event IDs, EDR behavioral
rules, network signatures) and mitigation steps (ASR rules, application allowlisting, egress
filtering) per matched technique — not generic "install antivirus" advice.

---

## Overall verdict logic

```
VT malicious engine count:
  0 detections    -> falls back to MITRE static verdict (file/hash only;
                      ip/domain/url with 0 detections = CLEAN)
  1-5 detections   -> SUSPICIOUS
  6+ detections     -> MALICIOUS
```

VT detection count takes priority over static MITRE analysis when VT has data, since it
reflects real-world consensus across dozens of engines — a file can have zero suspicious API
calls (e.g. a plain test signature like EICAR) and still be universally flagged malicious by
VT's engine consensus.

---

## Known limitations

Documented honestly, not hidden — a triage tool is only useful if its blind spots are known:

- **Regex-based static analysis will under-report on packed/obfuscated binaries.** Packers
  strip or encrypt plaintext API names and strings, so a packed malicious sample may show
  zero suspicious API matches even though it's genuinely malicious. This tool does static
  string analysis, not disassembly or dynamic detonation — it's a triage tool, not a sandbox.
- **The SUSPICIOUS threshold (1+ VT detections) is deliberately low and can false-positive.**
  A single flaky or overly aggressive AV engine can push a genuinely clean file into
  SUSPICIOUS. This is an intentional design choice for a triage tool (over-flag for human
  review rather than risk missing something), not a bug — but it means SUSPICIOUS verdicts
  need human judgment, not automatic action.
- **URL lookups only retrieve existing VT scans.** If VT has never scanned a given URL before,
  the tool reports "no record" rather than submitting the URL for a fresh scan — submitting
  new URLs uses a different VT API endpoint, out of scope for this read-only lookup tool.
- **Threat intelligence has a shelf life.** An IP or domain flagged malicious months ago may
  have since been cleaned up or reassigned to a different owner — always check the
  `last_analysis` timestamp in the report, don't treat any verdict as permanent.
- **Domain/IP/URL reputation lookups don't get MITRE ATT&CK mapping.** MITRE mapping requires
  file behavioral analysis (API calls, registry writes) that doesn't exist for a bare network
  indicator — the report correctly shows this as "not applicable" rather than a fake analysis.

---

## Credentials / context

Built alongside the TryHackMe SOC Level 1 path and CompTIA Security+ SY0-701 study.
Related projects: a five-module CLI version of this tool's IOC extraction core, and a
separate Flask-based attack/defense lab (brute-force, DDoS, and webshell simulation with
MITRE ATT&CK mapping and verified defense logging).
