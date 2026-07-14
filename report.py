"""
report.py
Takes the raw outputs from hasher.py, string_extractor.py, vt_client.py,
mitre_mapper.py, and remediation.py and combines them into one clean report -
both a JSON file (for saving/sharing) and a readable terminal printout
(for quick triage).

Computes one overall verdict per target (file/hash/ip/domain/url) by combining
VirusTotal's raw malicious detection count with MITRE ATT&CK static-behavior
scoring. VT detection count takes priority since it reflects real-world
consensus across dozens of engines:
    0 VT detections   -> falls back to MITRE static verdict (file/hash only;
                          ip/domain/url defaults to CLEAN)
    1-5 VT detections  -> SUSPICIOUS
    6+ VT detections    -> MALICIOUS
"""

import json
from datetime import datetime, timezone


def epoch_to_readable(epoch_seconds):
    """
    VT returns dates as Unix epoch seconds (e.g. 1148301722).
    Convert that into something readable like '2006-05-22 14:22:02 UTC'.
    Returns 'unknown' if the input isn't a valid epoch value.
    """
    if epoch_seconds is None or epoch_seconds == "unknown":
        return "unknown"
    try:
        dt = datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OSError):
        return "unknown"


def compute_overall_verdict(vt_data: dict, mitre_verdict: str, mitre_risk_score: int) -> dict:
    """
    Combines VT malicious detection count with MITRE static-behavior scoring
    into one overall verdict, applied uniformly across all target types
    (file, hash, ip, domain, url).

    Thresholds (based on raw VT malicious engine count, not ratio):
      0 detections    -> falls back to MITRE verdict (file/hash only;
                          ip/domain/url with 0 detections = CLEAN)
      1-5 detections   -> SUSPICIOUS
      6+ detections     -> MALICIOUS

    Known limitation: a single flaky/trigger-happy AV engine can push a
    genuinely clean file into SUSPICIOUS at just 1 detection. This is a
    deliberate low-threshold choice for a triage tool (better to over-flag
    for a human to review than miss something), not a bug.
    """
    vt_malicious = 0
    vt_found = vt_data.get("found", False) if vt_data else False

    if vt_found:
        vt_malicious = vt_data.get("malicious_count", 0)

    if vt_malicious >= 6:
        return {"verdict": "MALICIOUS", "risk_score": max(mitre_risk_score, 9)}
    elif vt_malicious >= 1:
        return {"verdict": "SUSPICIOUS", "risk_score": max(mitre_risk_score, 4)}
    else:
        return {"verdict": mitre_verdict, "risk_score": mitre_risk_score}


def build_report(
    target_type: str,
    hash_data: dict = None,
    ioc_data: dict = None,
    vt_data: dict = None,
    mitre_result: dict = None,
    remediation_data: list = None,
) -> dict:
    """
    Combine all module outputs into one structured report dict.
    target_type       -> 'file', 'hash', 'ip', 'domain', or 'url' -- determines report shape
    hash_data          -> from hasher.hash_file() (file/hash targets only)
    ioc_data           -> from string_extractor.analyze_file() (file targets only)
    vt_data            -> from vt_client.query_vt_auto()
    mitre_result       -> from mitre_mapper.map_to_mitre() (file targets only)
    remediation_data    -> from remediation.get_remediation() (file targets only)
    """
    report = {
        "target_type": target_type,
        "virustotal": {},
    }

    mitre_verdict_for_overall = "CLEAN_NO_TECHNIQUE_MATCH"
    mitre_score_for_overall = 0

    # --- File / hash targets get file_info + static_iocs + mitre_attack ---
    if target_type in ("file", "hash"):
        hash_data = hash_data or {}
        report["file_info"] = {
            "filepath": hash_data.get("filepath", "N/A (hash-only lookup)"),
            "size_bytes": hash_data.get("size_bytes", "unknown"),
            "md5": hash_data.get("md5", "unknown"),
            "sha1": hash_data.get("sha1", "unknown"),
            "sha256": hash_data.get("sha256", "unknown"),
        }

        report["static_iocs"] = {
            "ips": ioc_data.get("ips", []) if ioc_data else [],
            "urls": ioc_data.get("urls", []) if ioc_data else [],
            "domains": ioc_data.get("domains", []) if ioc_data else [],
            "suspicious_apis": ioc_data.get("suspicious_apis", []) if ioc_data else [],
            "registry_keys": ioc_data.get("registry_keys", []) if ioc_data else [],
            "suspicious_paths": ioc_data.get("suspicious_paths", []) if ioc_data else [],
        } if ioc_data else None

        mitre_verdict_for_overall = mitre_result.get("verdict", "NOT_ANALYZED") if mitre_result else "NOT_ANALYZED"
        mitre_score_for_overall = mitre_result.get("risk_score", 0) if mitre_result else 0

        report["mitre_attack"] = {
            "risk_score": mitre_score_for_overall,
            "verdict": mitre_verdict_for_overall,
            "techniques": (
                remediation_data if remediation_data is not None
                else (mitre_result.get("techniques", []) if mitre_result else [])
            ),
        }

    # --- IP / domain / URL targets: reputation lookup only, no file behavior to map ---
    elif target_type in ("ip", "domain", "url"):
        value = "unknown"
        if vt_data:
            value = vt_data.get("ip") or vt_data.get("domain") or vt_data.get("url", "unknown")
        report["network_indicator"] = {
            "value": value,
            "type": target_type,
        }
        report["mitre_attack"] = {
            "note": "MITRE ATT&CK mapping applies to file behavior only -- "
                    "not available for IP/domain/URL reputation lookups."
        }
        # mitre_verdict_for_overall stays at default CLEAN_NO_TECHNIQUE_MATCH,
        # mitre_score_for_overall stays 0 -- overall verdict is driven entirely
        # by VT detection count for these target types.

    # --- VirusTotal section, shape varies by target_type but built the same way ---
    if vt_data and vt_data.get("found"):
        if target_type in ("file", "hash"):
            report["virustotal"] = {
                "detection_ratio": vt_data.get("detection_ratio"),
                "malicious_count": vt_data.get("malicious_count", 0),
                "threat_family": vt_data.get("threat_family"),
                "file_type": vt_data.get("file_type"),
                "reputation": vt_data.get("reputation"),
                "known_filenames": vt_data.get("known_filenames", []),
                "first_submission": epoch_to_readable(vt_data.get("first_submission")),
                "last_analysis": epoch_to_readable(vt_data.get("last_analysis")),
            }
        elif target_type == "ip":
            report["virustotal"] = {
                "detection_ratio": vt_data.get("detection_ratio"),
                "malicious_count": vt_data.get("malicious_count", 0),
                "reputation": vt_data.get("reputation"),
                "country": vt_data.get("country"),
                "asn": vt_data.get("asn"),
                "as_owner": vt_data.get("as_owner"),
                "network": vt_data.get("network"),
                "last_analysis": epoch_to_readable(vt_data.get("last_analysis")),
            }
        elif target_type == "domain":
            report["virustotal"] = {
                "detection_ratio": vt_data.get("detection_ratio"),
                "malicious_count": vt_data.get("malicious_count", 0),
                "reputation": vt_data.get("reputation"),
                "registrar": vt_data.get("registrar"),
                "creation_date": epoch_to_readable(vt_data.get("creation_date")),
                "categories": vt_data.get("categories", []),
                "last_analysis": epoch_to_readable(vt_data.get("last_analysis")),
            }
        elif target_type == "url":
            report["virustotal"] = {
                "detection_ratio": vt_data.get("detection_ratio"),
                "malicious_count": vt_data.get("malicious_count", 0),
                "reputation": vt_data.get("reputation"),
                "final_url": vt_data.get("final_url"),
                "title": vt_data.get("title"),
                "times_submitted": vt_data.get("times_submitted"),
                "last_analysis": epoch_to_readable(vt_data.get("last_analysis")),
            }
    else:
        report["virustotal"] = {
            "found": False,
            "message": vt_data.get("message", "No VT record found.") if vt_data else "No VT lookup performed.",
        }

    # --- Overall verdict: combines VT detection count + MITRE static verdict ---
    overall = compute_overall_verdict(vt_data, mitre_verdict_for_overall, mitre_score_for_overall)
    report["overall_verdict"] = overall["verdict"]
    report["overall_risk_score"] = overall["risk_score"]

    return report


def save_report_json(report: dict, output_path: str = "report_output.json"):
    """Write the report dict to a JSON file for saving/sharing."""
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    return output_path


def _print_ioc_list(label: str, items: list):
    print(f"{label} ({len(items)}): {', '.join(items) if items else 'none'}")


def print_readable_report(report: dict):
    """Print a clean, human-readable version of the report to the terminal."""
    print("=" * 60)
    print("IOC EXTRACTOR - TRIAGE REPORT")
    print("=" * 60)

    target_type = report.get("target_type", "unknown")

    print(f"\nOVERALL VERDICT: {report.get('overall_verdict', 'NOT_ANALYZED')}  "
          f"(Risk Score: {report.get('overall_risk_score', 0)})")

    if target_type in ("file", "hash"):
        fi = report["file_info"]
        print(f"\nFile:     {fi['filepath']}")
        print(f"Size:     {fi['size_bytes']} bytes")
        print(f"MD5:      {fi['md5']}")
        print(f"SHA1:     {fi['sha1']}")
        print(f"SHA256:   {fi['sha256']}")

        if report.get("static_iocs"):
            iocs = report["static_iocs"]
            print(f"\n--- Static IOCs (extracted from strings) ---")
            _print_ioc_list("IPs found", iocs["ips"])
            _print_ioc_list("URLs found", iocs["urls"])
            _print_ioc_list("Domains found", iocs["domains"])
            _print_ioc_list("Suspicious APIs found", iocs.get("suspicious_apis", []))
            _print_ioc_list("Registry keys found", iocs.get("registry_keys", []))
            _print_ioc_list("Suspicious paths found", iocs.get("suspicious_paths", []))

    elif target_type in ("ip", "domain", "url"):
        ni = report["network_indicator"]
        print(f"\n{target_type.upper()}:  {ni['value']}")

    print(f"\n--- VirusTotal Verdict ---")
    vt = report["virustotal"]
    if vt.get("found") is False:
        print(f"  {vt['message']}")
    elif target_type in ("file", "hash"):
        print(f"  Detection ratio:   {vt.get('detection_ratio')}")
        print(f"  Threat family:     {vt.get('threat_family')}")
        print(f"  File type:         {vt.get('file_type')}")
        print(f"  Reputation score:  {vt.get('reputation')}")
        print(f"  First submitted:   {vt.get('first_submission')}")
        print(f"  Last analyzed:     {vt.get('last_analysis')}")
        names = vt.get("known_filenames", [])
        if names:
            print(f"  Known filenames:   {', '.join(names)}")
    elif target_type == "ip":
        print(f"  Detection ratio:   {vt.get('detection_ratio')}")
        print(f"  Reputation score:  {vt.get('reputation')}")
        print(f"  Country:           {vt.get('country')}")
        print(f"  ASN:               {vt.get('asn')}")
        print(f"  AS Owner:          {vt.get('as_owner')}")
        print(f"  Network:           {vt.get('network')}")
        print(f"  Last analyzed:     {vt.get('last_analysis')}")
    elif target_type == "domain":
        print(f"  Detection ratio:   {vt.get('detection_ratio')}")
        print(f"  Reputation score:  {vt.get('reputation')}")
        print(f"  Registrar:         {vt.get('registrar')}")
        print(f"  Creation date:     {vt.get('creation_date')}")
        cats = vt.get("categories", [])
        if cats:
            print(f"  Categories:        {', '.join(cats)}")
        print(f"  Last analyzed:     {vt.get('last_analysis')}")
    elif target_type == "url":
        print(f"  Detection ratio:   {vt.get('detection_ratio')}")
        print(f"  Reputation score:  {vt.get('reputation')}")
        print(f"  Final URL:         {vt.get('final_url')}")
        print(f"  Title:             {vt.get('title')}")
        print(f"  Times submitted:   {vt.get('times_submitted')}")
        print(f"  Last analyzed:     {vt.get('last_analysis')}")

    if target_type in ("file", "hash"):
        ma = report.get("mitre_attack", {})
        print(f"\n--- MITRE ATT&CK Mapping (static behavior only) ---")
        print(f"  Static risk score: {ma.get('risk_score', 0)}")
        print(f"  Static verdict:    {ma.get('verdict', 'NOT_ANALYZED')}")

        techniques = ma.get("techniques", [])
        if not techniques:
            print("  No techniques matched.")
        else:
            for t in techniques:
                print(f"\n  [{t['technique_id']}] {t['technique_name']}  (Tactic: {t['tactic']}, Severity: {t['severity']})")
                print(f"    Matched indicators: {', '.join(t['matched_indicators'])}")
                if "detection_steps" in t:
                    print(f"    Detection:")
                    for step in t["detection_steps"]:
                        print(f"      - {step}")
                if "mitigation_steps" in t:
                    print(f"    Mitigation:")
                    for step in t["mitigation_steps"]:
                        print(f"      - {step}")
    else:
        print(f"\n--- MITRE ATT&CK Mapping ---")
        print(f"  {report.get('mitre_attack', {}).get('note', 'Not applicable for this target type.')}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    fake_hash_data = {
        "filepath": "test.exe",
        "size_bytes": 68,
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    }
    fake_ioc_data = {
        "ips": ["10.0.0.5"],
        "urls": ["http://malicious-site.net/payload.exe"],
        "domains": ["evil-domain.com"],
        "suspicious_apis": ["VirtualAllocEx", "RegSetValueEx"],
        "registry_keys": [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"],
        "suspicious_paths": [r"C:\Users\test\AppData\Roaming\evil.exe"],
    }
    fake_vt_data = {
        "found": True,
        "detection_ratio": "60/74",
        "malicious_count": 60,
        "threat_family": "virus.eicar/test",
        "file_type": "Powershell",
        "reputation": 3786,
        "known_filenames": ["eicar.com-46241", "eicar.com.txt"],
        "first_submission": 1148301722,
        "last_analysis": 1783756080,
    }
    fake_mitre_result = {"risk_score": 8, "verdict": "MALICIOUS", "techniques": []}
    fake_remediation_data = [
        {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion / Privilege Escalation",
            "severity": "HIGH",
            "matched_indicators": ["VirtualAllocEx"],
            "confidence_weight": 3,
            "detection_steps": ["Sysmon Event ID 8 (CreateRemoteThread) monitoring."],
            "mitigation_steps": ["Enable Attack Surface Reduction rules."],
        },
    ]

    test_report = build_report(
        "file", fake_hash_data, fake_ioc_data, fake_vt_data,
        mitre_result=fake_mitre_result,
        remediation_data=fake_remediation_data,
    )
    print_readable_report(test_report)
    path = save_report_json(test_report, "test_report_output.json")
    print(f"\nSaved JSON report to: {path}")
