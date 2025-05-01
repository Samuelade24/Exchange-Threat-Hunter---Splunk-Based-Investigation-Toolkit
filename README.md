**Project Description**

Splunk investigation report, enhanced with threat modeling, compliance mapping, and detailed technical insights:

## 🔍 SOC Investigation: Exchange Exploits & Lateral Movement

### Option 3: Table Representation
```markdown
## Attack Flow Table

| Stage | Components | 
|-------|------------|
| 1. Initial Access | Phishing, Exploit Public-Facing App |
| 2. Execution | Web Shell, ProxyShell |
| 3. Persistence | Scheduled Tasks, Service Installation |
| 4. Lateral Movement | RDP, WMI, PSExec |
| 5. Privilege Escalation | Credential Dumping |
| 6. Exfiltration | DNS Tunneling, Cloud Storage |
| 7. Impact | Data Breach, Regulatory Fines |

📋 Executive Summary
Investigation Scope: Exchange Server Exploits → Data Exfiltration
Tools: Splunk ES, Sysmon, Windows Event Forwarding

Key Findings:
3 ProxyShell exploit attempts blocked
2 successful web shell installations detected
Lateral movement via RDP and WMI identified

Metrics:
Mean Time to Detect (MTTD): 37 minutes
Mean Time to Respond (MTTR): 1 hour 12 minutes

🔧 Expanded Technical Methodology
1. Detection Engineering
Splunk SPL for ProxyShell:
index=exchange (EventCode=4657 OR EventCode=4662) 
    "ProcessName"="powershell.exe" 
    "CommandLine"="*Autodiscover*"
| stats count by src_ip, user

Sysmon Configuration:
<EventFiltering>
    <RuleGroup name="CredDump Detection">
        <ProcessCreate onmatch="include">
            <CommandLine condition="contains">mimikatz</CommandLine>
            <CommandLine condition="contains">sekurlsa::logonpasswords</CommandLine>
        </ProcessCreate>
    </RuleGroup>
</EventFiltering>

2. Forensic Artifacts Collected
Data Source	Query Example
Windows Security Logs	EventCode=4624 LogonType=3
Sysmon Process Creation	ParentImage=C:\Windows\System32\wbem\wmic.exe
Netflow Data	dest_port=3389 AND bytes_sent>50MB

3. MITRE ATT&CK Mapping
pie
    title ATT&CK Techniques Observed
    "T1190 (Exploit Public-Facing App)" : 35
    "T1078 (Valid Accounts)" : 25
    "T1003 (OS Credential Dumping)" : 40

🛡️ Compliance Impact
NIST 800-53 Controls
Control	Status	Evidence
SI-4 (Monitoring)	✅ Compliant	SPL Queries
IA-2 (Identification/Authentication)	⚠️ Partial	Credential Events

HIPAA Security Rule
§164.308(a)(5)(ii)(B): Log-in monitoring implemented
§164.312(b): Audit controls validated

GDPR Articles
Article 32: Processing security verified
Article 33: 72-hour reporting clock initiated

🎓 Lessons Learned
Detection Improvements
Baseline Normal RDP Activity
Created Splunk lookup table of authorized admin workstations
| inputlookup allowed_rdp_clients.csv 
| eval is_approved=if(match(src_ip, allowed_ips), "YES", "NO")

Enhanced Credential Guard
Implemented LSA protection via Group Policy:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1

Process Optimizations
Reduced false positives by 40% through:
Signal clustering algorithms
Tiered alert severity scoring

🛠️ Remediation Roadmap
Immediate (24h):
Apply Exchange CU23 + disable legacy auth
Reset all service account credentials

Short-Term (1 Week):
Implement JIT access for RDP
Deploy network segmentation for Exchange servers

Long-Term (1 Month):
Conduct purple team exercises
Build custom Splunk ML toolkit

📚 Investigation Artifacts
File	Purpose	Compliance Relevance
ProxyShell_IOCs.csv	Threat Indicators	NIST SI-4
CredDump_Alerts.json	Splunk Alerts	HIPAA §164.312(b)
Timeline.pdf	Attack Reconstruction	GDPR Art 33

graph LR
    A[Exploit] --> B[Web Shell]
    B --> C[Cobalt Strike]
    C --> D[LSASS Dump]
    D --> E[Domain Admin]
    E --> F[Exfiltrate Data]
    style A stroke:#ff0000
    style F stroke:#ff0000

"The absence of evidence is not evidence of absence - layered logging is critical."



