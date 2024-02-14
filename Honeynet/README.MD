## Creating Virtual Machines

### Windows 10

1) Create a resource group, I named mine RG-SOC.
    - Azure Resource Groups are logical 
    grouping of related resources within a project, environment, or application, providing simplified management, governance through policies and RBAC, and aid in cost tracking and allocation. 
2) Name your Windows machine
3) Select your region, I selected East US 2. 
4) No infrastructure redudancy required. 
5) Select the image type: Windows 10 Pro, version 22H2 - x64 Gen2  
- Select (Standard_E2ad_v5 - 2 vcpus, 16 GiB memory)
- Set the admin account name and password

- Networking:
- networking tab: The firewall will be open to the public internet, we will remove the default rules and create new inbound rule that will allow all incoming traffic. Create a new virtual network, I named it SOC-vnet
- Monitoring 
- disable boot diagnostics
- review and create

-- the purpose is to let the VM be discoverable by any means necessary: TCP ping, SYN scan, ICMP ping. 

<p align="center">
<img src="https://i.imgur.com/gwmg2gt.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>
<p align="center">
<img src="https://i.imgur.com/8iaZpsK.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>

### Linux - Ubuntu


### Network Security Groups
- Firewall that acts as a security layer for azure resources within a virtual entwork: controlling inbound/outbound network traffic flow to and from the resources 
- Default inbound and outbound firewall rules: a first rule: RDP it is enabled by default for any port and any IP address
- under inbound security rules: delete RDP rule 
- now add new inbound rule:
    
    We will allow traffic on any port. We do this by using "*" 
    
⚠️ DANGER - EXTREMELY PERMISSIVE RULE ⚠️

Allows unrestricted inbound traffic from any source, any port, to any destination, any port, on any protocol.

This rule is highly permissive and poses significant security risks.

It should only be used temporarily for troubleshooting or in very specific, controlled scenarios with careful monitoring and risk assessment.

Review this rule regularly and remove it as soon as it is no longer absolutely necessary.

Please consider using more restrictive rules whenever possible.

<p align="center">
<img src="https://i.imgur.com/HtNarQw.png[/img]" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>

## RDP - Remote Desktop Protocol

[https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c510d7d7-14f3-479e-9e1e-c376aed3c963]

logs - digitial documentation of actions a coputer/user 

agent - category of software does something on behalf of user or system, software that has automation task that it does for you
    monitor agent takes the logs and going to aggregate to LAW --> microsoft sentinle filter them 

turning off firewall
wf.msc


Edit registry
- Registry Editor
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security
```
unerl


## LAW
Log Analytics Workspace  
Create a law-soc  
creating agents
    download windows agent 64 bit
    microsoft edge in your VM and paste it in the browser, it will download and then run exe  
    download folder  
    connect the agent to azure log analytics  

## Data Collection Rule
```
Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116 or EventID=1117)]]
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall!*[System[(EventID=2003)]]
```
1:30:00 - jan 17 2024

DCR-SOC
RG-SOC
East US2
ALL

next resources
add resources: linuxvm and windowsvm

next collect and deliver:
add data source
    data source: linux syslog - log auth: log debug
    data source: windows event logs : CUSTOM



## Microsoft Sentinel
create microsoft sentinel  
create watchlist -- wwgeoip summarized.csv  
analytics --> creat --> sentinel analytics rule KQL

## Create Storage Account
Diagnostic settings creation

containers --- folder inside container -- diagnostic settings will report data plain logs on this "test" uploaded onto blob storage, view and edit:: this is a way alter document, this would report that the document has been altered, this is testing logs for documentation: since users will be ones who can alter documents 


## NSG Flow Logs
network security group  
NSG Flow logs  


## Microsoft Defender for Cloud


## Monitor
this is where you can view logs under activity logs
export the activity logs


## Key Vault
create a key vault  
diagnostic settings  create one -- DS azure key vault send it to analytic workspace

generate secrets -- this is for one incident -- we will generate by showing secret 11 times



## microsoft sentinel workbooks


## ECAIR FILE
- windows VIM
```
$TOTAL_VIRUSES_TO_MAKE = 1
 
$firsthalf = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
$secondhalf = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
 
$count = 0
 
while ($count -lt $TOTAL_VIRUSES_TO_MAKE) {
 
    Write-Host "Generating: EICAR-$($count).txt"
    "$($firsthalf)$($secondhalf)" | Out-File -FilePath "EICAR-$($count).txt"
    $count++
}
```
this ECAIR file it is a type of file design to tigger antivirus software
    this would detect that there is malware in the VM, unless antivirus removes it  
    need to turn off virus protection   
    open ISE   
    set-location $env:userprofile\desktop

