**Project Description:**

Exchange Threat Hunter is a PowerShell-based security tool that automates detection and investigation of Exchange exploit attempts, lateral movement, and persistence mechanisms using Splunk queries. The tool provides SOC analysts with pre-built detection rules and response workflows.

**Key Features:**

Pre-built Splunk queries for Exchange exploit detection
Lateral movement analysis through authentication patterns
Persistence mechanism identification via Sysmon integration
Automated investigation workflows
Threat intelligence integration

**Installation:**

# Install required modules
Install-Module -Name SplunkSharp -Force
Install-Module -Name PSSysmonTools -Force

# Clone repository
git clone https://github.com/yourusername/exchange-threat-hunter.git
cd exchange-threat-hunter

# Configure Splunk connection
.\ETH-Config.ps1

**Usage Examples:**
**Run Exchange exploit detection:**
.\ETH.ps1 -Mode ExchangeExploitDetection

**Analyze lateral movement:**
.\ETH.ps1 -Mode LateralMovement -TimeRange Last7Days

**Check for persistence mechanisms:**
.\ETH.ps1 -Mode PersistenceCheck -Detailed

**Technical Implementation:**
function Get-ExchangeExploitAttempts {
    param(
        [string]$TimeRange = "Last24Hours",
        [switch]$Detailed
    )
    
    # Build Splunk query
    $query = @"
index=exchange (eventcode=4688 OR eventcode=4624) 
| search "powershell" OR "cmd" OR "wmic"
| stats count by host, user, process
"@

    $results = Invoke-SplunkQuery -Query $query -TimeRange $TimeRange
    
    if ($Detailed) {
        $results | Add-ExchangeExploitContext
    }
    
    return $results
}

**Sample Detection Rules:**
# Exchange Exploit Attempts
index=exchange (eventcode=4688 OR eventcode=4624) 
  [search "powershell" OR "cmd" OR "wmic"]
| stats count by host, user, process

# Lateral Movement Detection
index=windows (EventCode=4624 OR EventCode=4625)
  [search LogonType=3 AND NOT user IN ("SYSTEM", "ANONYMOUS LOGON")]
| stats count by src_host, user, dest_host

# Persistence Mechanisms
index=sysmon (EventID=1 OR EventID=12 OR EventID=13)
  [search "schtasks" OR "reg add" OR "Startup"]
| table _time, host, process, detail


**Security Considerations:**
Requires appropriate Splunk permissions
Processes sensitive log data - ensure proper handling
Integrates with existing SIEM workflows
Includes audit logging for all queries

**Roadmap:**
Automated IOC extraction
MITRE ATT&CK mapping
Integration with EDR solutions
Anomaly detection enhancements
