"""
ioc_extractor.py
Core pipeline logic lives in run_analysis(), callable from anywhere (CLI, GUI,
tests). main() is a thin CLI wrapper around it -- handles argparse, printing,
and exit codes, but contains no pipeline logic itself.
"""

import os
import sys
import argparse

from modules.hasher import hash_file
from modules.string_extractor import analyze_file
from modules.vt_client import query_vt_auto, identify_target_type, VTClientError
from modules.mitre_mapper import map_to_mitre
from modules.remediation import get_remediation
from modules.report import build_report, print_readable_report, save_report_json


def run_analysis(target: str) -> dict:
    """
    Runs the full IOC extraction pipeline against a target (file path, hash,
    IP, or domain) and returns the finished report dict. Raises ValueError
    if the target can't be identified, VTClientError if VT lookup fails
    for a reason other than a normal 404.
    """
    hash_data = None
    ioc_data = None
    mitre_result = None
    remediation_data = None

    if os.path.isfile(target):
        target_type = "file"
        hash_data = hash_file(target)
        vt_target = hash_data["sha256"]

        ioc_data = analyze_file(target)
        mitre_result = map_to_mitre(ioc_data)
        remediation_data = get_remediation(mitre_result)

    else:
        detected_type = identify_target_type(target)
        if detected_type == "unknown":
            raise ValueError(f"Could not identify '{target}' as a file, hash, IP, or domain.")

        target_type = detected_type
        vt_target = target

        if target_type == "hash":
            hash_data = {"filepath": "N/A (hash-only lookup)", "sha256": target}

    try:
        vt_data = query_vt_auto(vt_target)
    except VTClientError as e:
        vt_data = {"found": False, "message": f"VT lookup error: {e}"}

    report = build_report(target_type, hash_data, ioc_data, vt_data, mitre_result, remediation_data)
    return report


def main():
    """CLI wrapper: parses args, calls run_analysis(), prints + saves the report."""
    parser = argparse.ArgumentParser(
        description="IOC extractor + MITRE ATT&CK mapper + VirusTotal lookup tool. "
        "Accepts a file path, hash, IP address, or domain."
    )
    parser.add_argument("target", help="File path, MD5/SHA1/SHA256 hash, IP address, or domain")
    parser.add_argument(
        "-o", "--output",
        default="report_output.json",
        help="Path to save the JSON report (default: report_output.json)"
    )
    args = parser.parse_args()

    print(f"[*] Analyzing: {args.target}")
    try:
        report = run_analysis(args.target)
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    print_readable_report(report)
    saved_path = save_report_json(report, args.output)
    print(f"[*] Full JSON report saved to: {saved_path}")


if __name__ == "__main__":
    main()
