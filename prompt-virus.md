Add a new tab "Virus"  that provides a comprehensive "Virus Security Summary" for the user. 


### Data Requirements & Sources:

1. System Protection State & Database Status (Source: WMI)
   - Namespace: root\Microsoft\Windows\Defender
   - Class: MSFT_MpComputerStatus
   - Fields to extract:
     * AntivirusEnabled (bool)
     * RealTimeProtectionEnabled (bool)
     * AntivirusSignatureVersion (string)
     * AntivirusSignatureLastUpdated (DateTime, converted properly from WMI format)
     * QuickScanEndTime (DateTime)
     * FullScanEndTime (DateTime)

2. Historical Threat & Scan Data (Source: Windows Event Logs)
   - Log Path: "Microsoft-Windows-Windows Defender/Operational"
   - Scan Events to parse: Event ID 1000 (Started), 1001 (Completed), 1005 (Failed)
   - Threat Events to parse: Event ID 1116 (Malware detected), 1117 (Remediation successful), 1118 (Remediation failed)

### Technical Constraints & Outputs:
- Use System.Management (for WMI) and System.Diagnostics.Eventing.Reader (for efficient Event Log querying).
- Create strongly-typed DTOs/models to hold this parsed data (e.g., `DefenderStatusSummary`, `ThreatDetectionRecord`, `ScanHistoryRecord`) so they can be easily bound to a UI later.
- Include proper error handling for cases where the user doesn't run the app as Administrator (since accessing these logs/WMI namespaces requires elevated privileges).
- Provide clean asynchronous methods (e.g., `public async Task<DefenderStatusSummary> GetStatusAsync()`) to keep the UI responsive.

### Where to find the information

#### State of System-Wide Protection
Windows tracks whether protection components are active, running, or throttled.
 - Saved Properties: Real-time protection status, cloud-delivered protection status, behavior monitoring, and tamper protection.
 - PowerShell approach: Look at the Get-MpComputerStatus cmdlet.
 - C# / WMI class: root\Microsoft\Windows\Defender:MSFT_MpComputerStatus


#### Defender Database (Definitions) Updates
Windows tracks the exact age and version of the malware signature definitions.  
 - Saved Properties: AntivirusSignatureVersion, AntivirusSignatureLastUpdated, and AntivirusSignatureAge (tracked in days).
 - PowerShell approach: Properties within Get-MpComputerStatus.
 - C# / Event Log approach: Monitor Event ID 2001 (Signature update finished successfully).
 
#### Virus Scan History
Windows retains timestamps for the types of scans completed.

 - Saved Properties: Start and end times for Quick Scans, Full Scans, and Custom Scans.  
 - PowerShell approach: Parsed out of Get-MpComputerStatus.
 - C# / Event Log approach: Querying the Windows Defender operational log for historical events is much more reliable for a timeline graph:
  - Event ID 1000: Scan started  
  - Event ID 1001: Scan completed successfully
  - Event ID 1002: Scan stopped / canceled
  - Event ID 1005: Scan failed  
 
#### Viruses Found (Threat History)
Any dynamic block, heuristic capture, or scan detection is cataloged.
 - Saved Properties: Threat Name, Severity, Resource Path (where the file was found), Execution State, and Remediation Action (quarantined, removed, or allowed).  
 - PowerShell approach: Get-MpThreat (current active/historical threats) or Get-MpThreatDetection (full timeline list).
 - C# / Event Log approach: Parse the following specific 
  - Event IDs:Event ID 1116: Malware or unwanted software detected.  
  - Event ID 1117: Action to protect the system performed successfully (e.g., quarantined).  
  - Event ID 1118: Action to protect the system failed.