# mitre_mapper.py — add severity + confidence to each rule

MITRE_RULES = [
    {
        "match_field": "suspicious_apis",
        "match_values": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"},
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "severity": "HIGH",
        "confidence_weight": 3,  # strong signal, low false-positive rate
    },
    {
        "match_field": "suspicious_apis",
        "match_values": {"RegSetValueEx", "RegCreateKeyEx"},
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "MEDIUM",
        "confidence_weight": 2,
    },
    {
        "match_field": "registry_keys",
        "match_values": None,
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "MEDIUM",
        "confidence_weight": 2,
    },
    {
        "match_field": "suspicious_apis",
        "match_values": {"URLDownloadToFile", "InternetOpenUrl", "WinExec"},
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "MEDIUM",
        "confidence_weight": 2,
    },
    {
        "match_field": "urls",
        "match_values": None,
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "severity": "LOW",
        "confidence_weight": 1,  # weak alone — URLs are common in legit files too
    },
    {
        "match_field": "suspicious_apis",
        "match_values": {"IsDebuggerPresent"},
        "technique_id": "T1622",
        "technique_name": "Debugger Evasion",
        "tactic": "Defense Evasion",
        "severity": "HIGH",
        "confidence_weight": 3,
    },
]


def map_to_mitre(ioc_data: dict) -> dict:
    """
    Returns matched techniques plus an aggregate risk verdict.
    """
    hits = {}

    for rule in MITRE_RULES:
        field_data = ioc_data.get(rule["match_field"], [])
        if not field_data:
            continue

        matched = field_data if rule["match_values"] is None else [
            v for v in field_data if v in rule["match_values"]
        ]

        if matched:
            tid = rule["technique_id"]
            if tid not in hits:
                hits[tid] = {
                    "technique_id": tid,
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"],
                    "severity": rule["severity"],
                    "matched_indicators": [],
                    "confidence_weight": rule["confidence_weight"],
                }
            hits[tid]["matched_indicators"].extend(matched)

    technique_list = list(hits.values())

    # Aggregate score: sum of confidence weights, capped verdict tiers
    total_score = sum(t["confidence_weight"] for t in technique_list)
    high_sev_count = sum(1 for t in technique_list if t["severity"] == "HIGH")

    if high_sev_count >= 1 and total_score >= 5:
        verdict = "MALICIOUS"
    elif total_score >= 3:
        verdict = "SUSPICIOUS"
    elif total_score >= 1:
        verdict = "LOW_RISK"
    else:
        verdict = "CLEAN_NO_TECHNIQUE_MATCH"

    return {
        "techniques": sorted(technique_list, key=lambda t: -t["confidence_weight"]),
        "risk_score": total_score,
        "verdict": verdict,
    }
