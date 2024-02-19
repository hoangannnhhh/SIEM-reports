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

<details>
    <summary>Creating WindowsVM image</summary>
    ![creating window vm](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/cfec8d69-e2ba-458f-97fe-a73ba0a82fb9)
</details>

- Networking:
- networking tab: The firewall will be open to the public internet, we will remove the default rules and create new inbound rule that will allow all incoming traffic. Create a new virtual network, I named it SOC-vnet
- Monitoring 
- disable boot diagnostics
- review and create

-- the purpose is to let the VM be discoverable by any means necessary: TCP ping, SYN scan, ICMP ping. 

![Create-a-virtual-machine-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/921012e4-863d-4c5b-b9a0-475a00aa92f6)


<p align="center">
<img src="https://i.imgur.com/gwmg2gt.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>
<p align="center">
<img src="https://i.imgur.com/8iaZpsK.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>

### Linux - Ubuntu
![Create-a-virtual-machine-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/07e51908-8aad-4771-8651-4250c5511b5a)
![2Create-a-virtual-machine-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/2fb935b5-871d-4de5-b08d-1c7bfa265386)


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


## Linux NSG
![delete  ssh LinuxVM-nsg-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/345c0ddb-0cb2-4843-8765-77dc04ee4c78)
![Add-inbound-security-rule-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9a721629-6929-49db-91f9-665ea0e64cbb)


## RDP - Remote Desktop Protocol



https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/dd1ff80c-379e-4c40-88ff-a3b79bc38ed8



logs - digitial documentation of actions a coputer/user 

agent - category of software does something on behalf of user or system, software that has automation task that it does for you
    monitor agent takes the logs and going to aggregate to LAW --> microsoft sentinle filter them 

turning off firewall

https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9887cc34-0fd3-456e-8ef4-1121d5e5ea8a


wf.msc


Edit registry
- Registry Editor
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security
```
unerl


https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/71fab93d-054f-4fca-a58d-e15a644dcf6e



## LAW
Log Analytics Workspace  
Create a law-soc  
creating agents
    download windows agent 64 bit
    microsoft edge in your VM and paste it in the browser, it will download and then run exe  
    download folder  
    connect the agent to azure log analytics  
    


https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/4c5a1811-9008-4403-ab1c-ba7a950b2ffc

### Linux


https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/bc4ad540-ee34-4c82-8f91-5da928a09630


## Data Collection Rule
```
Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116 or EventID=1117)]]
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall!*[System[(EventID=2003)]]
```
1:30:00 - jan 17 2024



https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/819d3212-4915-4b4d-8b9b-20d33535c9ed




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

https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/a9f74906-c33e-4d8b-a6b8-e0d6cd739b7f


create watchlist -- wwgeoip summarized.csv  


https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/e8408e0d-582a-4dfc-acdc-ee37902ef0aa



analytics --> creat --> sentinel analytics rule KQL
![1Microsoft-Sentinel-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/de543732-acfc-48b5-98ee-36bac94a7b1f)

## Create Storage Account

![Create-a-storage-account-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/0acbbf52-9dee-440a-be06-2f8d38feca8a)


Diagnostic settings creation


![1socstorage1-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/7c3f8784-c405-4c7a-8a3e-6bd24e1e713d)
![2socstorage1-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c211be9a-3442-44b3-b3b8-10baee2b0634)
![3Diagnostic-setting-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/232c3d3f-341f-47d3-8a26-5896e0cf17a1)


containers --- folder inside container -- diagnostic settings will report data plain logs on this "test" uploaded onto blob storage, view and edit:: this is a way alter document, this would report that the document has been altered, this is testing logs for documentation: since users will be ones who can alter documents 
![1New-container-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/797cfae7-8fd2-4054-9dc1-9672d2d0bfec)
![2Upload-blob-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/839494fe-3ec9-49de-b663-63695e8734d2)
![3test-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/58f932f7-3c94-430a-8196-9add047884e2)


## NSG Flow Logs
network security group  
NSG Flow logs  
![1Create-a-flow-log-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/621c8954-6500-47ec-8ea6-f71f77f82ec4)
![2Create-a-flow-log-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/ec015c27-b6fb-4feb-ae7b-6561e27af42f)



## Microsoft Defender for Cloud

![1Microsoft-Defender-for-Cloud-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/af45930e-8d0a-4d10-9ea5-412289de9dbc)
![2Settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c9cdb205-690b-40d8-884f-f9572c86a5ad)
![3Settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/83129709-c58a-40ba-b008-abb5785b5de0)
![4Microsoft-Defender-for-Cloud-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/d59d212a-9458-4762-a0a0-a7abf0afa945)
![5Settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/b5c9b7e1-a5cf-4113-9b35-49fe0072b67b)
![6Settings-monitoring-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/ad2f967a-e99b-4327-9b95-ce250a6b7cdf)
![7Auto-provisioning-configuration-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/53849c16-0015-47a1-9e98-90d277ca29a4)
![8Settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/932b6681-981b-49f1-b187-f7675b8491b5)
![9Settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c79a68de-80d0-4923-805d-979cac6fdc00)
![10Settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/0212665a-0c68-4942-99a3-a8ec3bc01805)



## Monitor
this is where you can view logs under activity logs
export the activity logs

![1Monitor-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9fcfe27a-413a-4334-b06a-6da1d8516d40)
![2Diagnostic-settings-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/59621859-dcd4-4e18-9e74-c0eece3f4d3d)
![3Diagnostic-setting-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/a564c58b-b277-4e00-9c56-bfd6fbf57be3)

## Key Vault
create a key vault  
![1Key-vaults-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/ce2e808d-a2b3-4b11-bc31-f4766f18bffb)
![2Create-a-key-vault-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/4f7ef00b-63e3-464d-ba4f-2388692d7945)
![3Create-a-key-vault-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/2cbeb6bc-d608-4347-ba87-104db676f498)


diagnostic settings  create one -- DS azure key vault send it to analytic workspace
![KeyVault-SOC1-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/d426e6a7-552d-454f-9108-ba1aa1b969e2)
![2Diagnostic-setting-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/4e5b3e46-d6a0-43cd-97ec-f12e0761aa17)

generate secrets -- this is for one incident -- we will generate by showing secret 11 times

![1KeyVault-SOC1-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/45f93770-c559-4ee0-a585-c4096c20dc90)
![2Create-a-secret-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9d718be7-c618-448e-9f37-5b528a2a70fb)


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



https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/0a5b0183-132d-4f88-ab57-6e48f6c913d3

