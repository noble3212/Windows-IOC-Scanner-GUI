# Windows IOC Scanner

A PowerShell-based Windows malware detection and incident response scanner with a **WPF GUI** and optional **VirusTotal integration**. Designed to identify indicators commonly associated with **RATs, clipboard stealers, persistence malware, and fake system-process malware**.

Built from real-world malware investigation patterns. Focuses on finding suspicious behavior rather than relying only on file hashes or antivirus signatures.

> This tool is a security research / incident response utility. It is not a replacement for Windows Defender, EDR solutions, or professional malware analysis tools.

---

## Quick Start

### GUI Mode (Recommended)

```powershell
# Double-click or run in PowerShell:
.\IOC-Scanner-GUI.ps1
```

### CLI Mode

```powershell
.\MalwareScanner.ps1              # Standard scan
.\MalwareScanner.ps1 -DeepScan    # Includes memory analysis
.\MalwareScanner.ps1 -Silent      # No console output
```

---

## Features

### One-Click WPF GUI

- Dark-themed interface with real-time progress bar
- Severity-coded results (CRITICAL / HIGH / MEDIUM / LOW)
- One-click CSV export
- Deep Scan toggle (16 checks) vs Standard Scan (10 checks)
- VirusTotal file reputation lookup
- API key stored securely via Windows DPAPI

### 16 Detection Categories

| # | Category | Description |
|---|----------|-------------|
| 1 | **Malware File Sizes** | Detects executables matching known malware byte sizes |
| 2 | **System Masquerade** | Finds Windows-named executables in user directories |
| 3 | **Registry Persistence** | Checks Run/RunOnce keys for suspicious entries |
| 4 | **Scheduled Tasks** | Detects malware persistence via Task Scheduler |
| 5 | **Startup Folder** | Flags executables in Startup folders |
| 6 | **COM Hijacking** | Detects abused COM CLSIDs pointing to user dirs |
| 7 | **Process Analysis** | System processes from wrong locations, unsigned processes |
| 8 | **RAT Detection** | AnyDesk, TeamViewer, UltraViewer, Ammyy, DWAgent in Downloads |
| 9 | **Memory-Resident** | Processes with no disk path (fileless malware) |
| 10 | **Process Hollowing** | Loaded module path differs from disk image |
| 11 | **Handle/Thread Abuse** | Unusually high handle or thread counts |
| 12 | **DLL Injection** | Unsigned DLLs loaded by signed processes |
| 13 | **Network Connections** | Non-standard ports, beaconing patterns |
| 14 | **Clipboard Monitoring** | Hidden AppData processes (clipper malware) |

### VirusTotal Integration

1. Click **API Key Settings** in the GUI
2. Enter your free API key from [virustotal.com/community](https://www.virustotal.com/community)
3. Key is encrypted locally using **Windows DPAPI** (tied to your user account)
4. Enable **VirusTotal Lookup** checkbox and run a scan
5. Suspicious executables are automatically checked against 70+ antivirus engines

---

## Severity Ratings

| Severity | Meaning |
|----------|---------|
| CRITICAL | Strong malware indicator |
| HIGH | Very suspicious behavior |
| MEDIUM | Requires investigation |
| LOW | Informational |

---

## Output

- Results displayed in a sortable DataGrid
- CSV export via **Export CSV** button
- Default CLI export: `Downloads\malware-scan-YYYY-MM-DD_HH-MM-SS.csv`

---

## Requirements

- Windows 10 / Windows 11
- PowerShell 5.1+ (built into Windows)
- Administrator privileges recommended for full scan depth
- VirusTotal API key (optional, free tier available)

---

## How This Was Built

Detection logic based on:
- Malware persistence analysis
- Windows forensic investigation
- IOC (Indicator of Compromise) hunting
- Suspicious process behavior analysis
- Registry investigation
- Malware cleanup validation

> "Find the things malware leaves behind."

---

## False Positive Warning

This scanner uses aggressive behavioral detection and **will detect legitimate software** in some situations:

- **AppData applications**: Discord, Steam, VS Code, Electron apps
- **Remote access tools**: IT support software, remote desktop utilities
- **Unsigned applications**: Open-source tools, personal scripts
- **System-like names**: Applications that accidentally use names like RuntimeBroker.exe

The location matters more than the filename. Always review findings before taking action.

---

## Limitations

This tool does not:
- Perform deep memory forensics
- Reverse engineer malware
- Scan encrypted files
- Replace antivirus software
- Guarantee a clean system

A clean scan means "No known indicators detected" -- not "Impossible to have malware."

---

## Future Improvements

- [ ] YARA rule integration
- [ ] Event log analysis (Security, System, PowerShell)
- [ ] PE header analysis
- [ ] Digital certificate reputation scoring
- [ ] JSON/HTML reporting
- [ ] Automated remediation mode
- [ ] Sysmon integration

---

## Disclaimer

Intended for security research, malware analysis education, incident response assistance, and personal system auditing. Use responsibly. Always verify findings before deleting files or modifying system configuration.

**A detection is a lead, not a verdict.**
