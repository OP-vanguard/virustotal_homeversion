"""
string_extractor.py
Extracts printable strings from a file -- both ASCII and UTF-16LE (wide) encodings,
the latter being how a large fraction of strings in Windows PE binaries are stored.
Regex-matches extracted strings for network IOCs (IPs, domains, URLs) and behavioral
indicators (suspicious WinAPI imports, registry keys, suspicious file paths).

Known limitations (read this before trusting the output):
  - Regex-based matching produces false positives (e.g. version numbers that look
    like IPs, random hex substrings that look like domains).
  - Packed/obfuscated binaries will show few or no plaintext API names -- this tool
    will under-report on packed malware. It is a triage tool, not a disassembler.
  - This is a triage tool, not a guarantee. Always sanity-check output manually.
"""

import re
import sys
import json
import string
import argparse


PRINTABLE_BYTES = set(bytes(string.printable, "ascii"))
MIN_STRING_LENGTH = 4  # matches default behavior of the `strings` command


def extract_ascii_strings(data: bytes, min_length: int) -> list:
    """Pull runs of printable ASCII characters >= min_length from raw bytes."""
    results = []
    current = []

    for byte in data:
        if byte in PRINTABLE_BYTES:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                results.append("".join(current))
            current = []

    if len(current) >= min_length:
        results.append("".join(current))

    return results


def extract_wide_strings(data: bytes, min_length: int) -> list:
    """
    Pull runs of printable UTF-16LE (wide) characters >= min_length.
    Wide strings are stored as [char][0x00][char][0x00]... -- common in
    Windows PE binaries for API names, paths, and messages. Missing this
    encoding means missing a large share of real IOCs in Windows malware.
    """
    results = []
    current = []
    i = 0
    n = len(data)

    while i < n - 1:
        lo, hi = data[i], data[i + 1]
        if hi == 0x00 and lo in PRINTABLE_BYTES:
            current.append(chr(lo))
            i += 2
        else:
            if len(current) >= min_length:
                results.append("".join(current))
            current = []
            i += 1

    if len(current) >= min_length:
        results.append("".join(current))

    return results


def extract_strings(filepath: str, min_length: int = MIN_STRING_LENGTH) -> list:
    """Read a file in binary mode and extract both ASCII and wide-char strings."""
    with open(filepath, "rb") as f:
        data = f.read()

    ascii_strings = extract_ascii_strings(data, min_length)
    wide_strings = extract_wide_strings(data, min_length)

    # dedup while preserving no particular order -- order doesn't matter downstream
    return list(set(ascii_strings) | set(wide_strings))


# --- Network IOC patterns ---
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# --- Behavioral IOC patterns (non-capturing groups so findall() returns clean strings) ---
SUSPICIOUS_API_PATTERN = re.compile(
    r"\b(?:VirtualAlloc|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|"
    r"NtUnmapViewOfSection|SetWindowsHookEx|GetProcAddress|LoadLibraryA|"
    r"RegSetValueEx|RegCreateKeyEx|WinExec|ShellExecute|URLDownloadToFile|"
    r"InternetOpenUrl|CreateToolhelp32Snapshot|IsDebuggerPresent)\b"
)

REGISTRY_PATTERN = re.compile(
    r"HKEY_[A-Z_]+\\(?:[^\s\"']+)|"
    r"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(?:[^\s\"']*)",
    re.IGNORECASE
)

SUSPICIOUS_PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\(?:Users\\[^\\]+\\AppData\\(?:Roaming|Local)\\[^\s\"']+|"
    r"Windows\\Temp\\[^\s\"']+|ProgramData\\[^\s\"']+)",
    re.IGNORECASE
)


def _is_valid_ip(ip: str) -> bool:
    """Reject regex matches like 999.999.999.999 that aren't real IPs."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_iocs(strings_list: list) -> dict:
    """Regex-match extracted strings for network and behavioral IOCs."""
    ips, urls, domains = set(), set(), set()
    apis, registry_keys, suspicious_paths = set(), set(), set()

    for s in strings_list:
        ips.update(m for m in IP_PATTERN.findall(s) if _is_valid_ip(m))
        urls.update(URL_PATTERN.findall(s))
        domains.update(DOMAIN_PATTERN.findall(s))
        apis.update(SUSPICIOUS_API_PATTERN.findall(s))
        registry_keys.update(REGISTRY_PATTERN.findall(s))
        suspicious_paths.update(SUSPICIOUS_PATH_PATTERN.findall(s))

    # URLs already contain domains -- strip domains that are just substrings of a URL
    domains = {d for d in domains if not any(d in u for u in urls)}

    return {
        "ips": sorted(ips),
        "urls": sorted(urls),
        "domains": sorted(domains),
        "suspicious_apis": sorted(apis),
        "registry_keys": sorted(registry_keys),
        "suspicious_paths": sorted(suspicious_paths),
    }


def analyze_file(filepath: str, min_length: int = MIN_STRING_LENGTH) -> dict:
    """Convenience wrapper: extract strings, then extract IOCs. Called by ioc_extractor.py."""
    strings_list = extract_strings(filepath, min_length)
    iocs = extract_iocs(strings_list)
    iocs["total_strings_found"] = len(strings_list)
    return iocs


def _print_section(title: str, items: list) -> None:
    print(f"\n{title} ({len(items)}):")
    if not items:
        print("  (none)")
        return
    for item in items:
        print(f"  {item}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract ASCII + wide-char strings from a file and flag IOCs "
        "(network + behavioral) via regex matching."
    )
    parser.add_argument("filepath", help="Path to the file to analyze")
    parser.add_argument(
        "--min-length", type=int, default=MIN_STRING_LENGTH,
        help=f"Minimum string length to extract (default: {MIN_STRING_LENGTH})"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print raw JSON instead of the human-readable report"
    )
    args = parser.parse_args()

    try:
        result = analyze_file(args.filepath, args.min_length)
    except FileNotFoundError:
        print(f"[!] File not found: {args.filepath}")
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"Total strings found: {result['total_strings_found']}")
    _print_section("IPs found", result["ips"])
    _print_section("URLs found", result["urls"])
    _print_section("Domains found", result["domains"])
    _print_section("Suspicious APIs found", result["suspicious_apis"])
    _print_section("Registry keys found", result["registry_keys"])
    _print_section("Suspicious paths found", result["suspicious_paths"])


if __name__ == "__main__":
    main()
