"""
remediation.py
Maps MITRE ATT&CK technique IDs (from mitre_mapper.py) to concrete defensive
and detection guidance -- what a SOC analyst or engineer would actually do
in response to each finding. Not generic advice; tied to specific technique
mechanics.
"""

REMEDIATION_MAP = {
    "T1055": {
        "technique_name": "Process Injection",
        "detection": [
            "Sysmon Event ID 8 (CreateRemoteThread) -- alert on cross-process "
            "thread creation where source and target images differ from expected pairs.",
            "Sysmon Event ID 10 (ProcessAccess) with GrantedAccess flags "
            "0x1F0FFF or 0x1FFFFF (PROCESS_ALL_ACCESS) -- common precursor to injection.",
            "EDR behavioral rule: flag VirtualAllocEx + WriteProcessMemory + "
            "CreateRemoteThread called in sequence by the same process.",
        ],
        "mitigation": [
            "Enable Attack Surface Reduction rule: 'Block process injections "
            "from Office macros into other processes' if applicable.",
            "Application allowlisting (WDAC/AppLocker) to restrict which "
            "binaries can load into protected processes.",
            "Enable Credential Guard / PPL (Protected Process Light) on "
            "sensitive processes (lsass.exe) to block injection attempts.",
        ],
    },
    "T1547.001": {
        "technique_name": "Registry Run Keys / Startup Folder",
        "detection": [
            "Sysmon Event ID 13 (RegistryEvent) -- alert on writes to "
            "HKCU/HKLM\\...\\CurrentVersion\\Run or RunOnce keys.",
            "Monitor Startup folder writes: "
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup.",
            "Baseline known-good Run key entries per host; alert on any new "
            "unrecognized entry (autoruns.exe or equivalent scheduled scan).",
        ],
        "mitigation": [
            "Restrict write access to Run/RunOnce registry keys via GPO "
            "where feasible for standard users.",
            "Deploy Sysmon config with registry monitoring enabled by default "
            "on all endpoints, not just servers.",
            "Use Windows Defender ASR rule: 'Block persistence through WMI "
            "event subscription' as a related hardening step.",
        ],
    },
    "T1105": {
        "technique_name": "Ingress Tool Transfer",
        "detection": [
            "Network: alert on outbound HTTP/HTTPS to newly-seen or "
            "low-reputation domains immediately followed by a new executable "
            "written to disk (correlate proxy logs + Sysmon Event ID 11).",
            "Sysmon Event ID 11 (FileCreate) for .exe/.dll writes to Temp, "
            "Downloads, or AppData shortly after a network connection event.",
            "Flag WinExec/ShellExecute calls occurring within seconds of "
            "InternetOpenUrl/URLDownloadToFile in the same process.",
        ],
        "mitigation": [
            "Block outbound traffic to known-bad IP/domain reputation lists "
            "at the proxy/firewall (Snort/Suricata IOC-based rules).",
            "Restrict execution from Temp/Downloads/AppData via AppLocker "
            "path rules -- most droppers land and execute from these paths.",
            "Enable SmartScreen / Defender cloud-delivered protection to "
            "flag newly-downloaded unsigned executables.",
        ],
    },
    "T1071.001": {
        "technique_name": "Application Layer Protocol: Web Protocols",
        "detection": [
            "Snort/Suricata signature on beaconing patterns -- fixed-interval "
            "outbound requests to the same host (classic C2 heartbeat).",
            "TLS JA3/JA3S fingerprinting to flag known malware C2 TLS clients.",
            "Proxy log review for User-Agent anomalies or requests to domains "
            "registered in the last 30 days (freshly-registered domain heuristic).",
        ],
        "mitigation": [
            "DNS sinkholing / RPZ for known C2 domains at the resolver level.",
            "Enforce TLS inspection at the perimeter where policy allows, to "
            "catch C2 hiding inside encrypted traffic.",
            "Egress filtering: default-deny outbound, allow only required "
            "ports/destinations per host role.",
        ],
    },
    "T1622": {
        "technique_name": "Debugger Evasion",
        "detection": [
            "Behavioral: flag IsDebuggerPresent/CheckRemoteDebuggerPresent "
            "calls combined with early process exit -- common sandbox-evasion pattern.",
            "Run samples in a sandbox with anti-anti-debug patches (e.g. "
            "Cuckoo with anti-VM evasion countermeasures) to force real behavior.",
        ],
        "mitigation": [
            "Not directly mitigable at the endpoint -- this indicates the "
            "sample is evasion-aware. Prioritize dynamic analysis in a "
            "properly cloaked sandbox instead of relying on static detection alone.",
        ],
    },
}


def get_remediation(mitre_result: dict) -> list:
    """
    Given the output of mitre_mapper.map_to_mitre(), attach detection and
    mitigation guidance for each matched technique. Techniques without a
    mapped entry get a fallback note instead of silently disappearing.
    """
    enriched = []

    for technique in mitre_result.get("techniques", []):
        tid = technique["technique_id"]
        guidance = REMEDIATION_MAP.get(tid)

        if guidance:
            enriched.append({
                **technique,
                "detection_steps": guidance["detection"],
                "mitigation_steps": guidance["mitigation"],
            })
        else:
            enriched.append({
                **technique,
                "detection_steps": ["No specific detection guidance mapped for this technique yet."],
                "mitigation_steps": ["No specific mitigation guidance mapped for this technique yet."],
            })

    return enriched
