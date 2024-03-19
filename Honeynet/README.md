 # Honeynet Build 

## Overview  
This README provies a step-by-step guide on how to set up a honeynet using Windows 10 and Linux virtual machines on Azure. There will be additional images and videos in each section for references. A honeynet is a network of intentionally vulnerable systems designed to attract and monitor malicious activities, allowing for the analysis of cyber threats in a controlled environment.  

**Disclaimer:** Use this honeynet setup for educational and research purposes only. Engaging in any malicious activities is strictly prohibited.

### Creating Virtual Machines
---
**Configuring Windows 10 VM**  
1) Navigate to the Azure portal, select new Virtual Machine 
2) Create a resource group for streamlined resource management, governance, and cost tracking. 
    <details><summary>More info on Azure Resource Groups</summary>
    <p>Azure Resource Groups are logical 
    grouping of related resources within a project, environment, or application, providing simplified management, governance through policies and RBAC, and aid in cost tracking and allocation. </p></details>
3) Name the Windows machine, select your desired region, no infrastructure redudancy is required.
4) Select the image type: Windows 10 Pro, version 22H2 - x64 Gen2.
- Select the size: Standard_E2ad_v5 - 2 vcpus, 16 GiB memory.
- Set the admin account name and password.
5) Navigate to the Networking tab and create a new virtual network.
    - The firewall will be open to the public internet and we will later remote the default rules and create new inbound rule that will allow all incoming traffic. 
6) Review and Create.
<details>
    <summary>Image: Creating WindowsVM</summary>
    <p align="center">
    <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/cfec8d69-e2ba-458f-97fe-a73ba0a82fb9" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
    <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/921012e4-863d-4c5b-b9a0-475a00aa92f6" height="200%" width="200%" alt="Create-a-virtual-machine-Microsoft-Azure"/>
    </p>
</details>  


<!--
<p align="center">
<img src="https://i.imgur.com/gwmg2gt.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>
<p align="center">
<img src="https://i.imgur.com/8iaZpsK.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>
-->  

**Configuring Linux Ubuntu VM**  
1) Navigate to Azure portal, select new Virtual Machine.
2) Select the same resource group that you had created for WindowsVM.
3) Name the Linux Machine, select the same region, and no infrastructure redudancy is required.
4) Select the image type: Ubuntu Server 20.04 LTS - x64 Gen2.
    - Select the size: Standard_DS1v2 - 1 vcpu, 3.5 GiB memory.
    - Set the admin account name and password.
5) Navigate to the Networking tab and select the same Virtual Network you created with the WindowsVM.
6) Review and Create.
<details>
    <summary>Creating LinuxVM images</summary>
    <p align="center>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/07e51908-8aad-4771-8651-4250c5511b5a" height="200%" width="200%" alt="Creating LinuxVM"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/2fb935b5-871d-4de5-b08d-1c7bfa265386" height="200%" width="200%" alt="Creating LinuxVM"/>
    </p>
</details>

### Network Security Groups
The Firewall acts as a security layer for Azure resources within a virtual network: controlling inbound/outbound network traffic flow to and from the resources.   
The Default inbound and outbound firewall rules: RDP is enabled by default for any port and any IP address.
1) Under inbound security rules: Delete RDP rule 
2) Add new inbound rule:
    - We will allow all traffic on any port. Add "*" to Designated Port Ranges box.
    The purpose of this is to let the VM be discoverable by any means necessary: TCP ping, SYN scan, ICMP ping, etc. 
    <details><summary>⚠️ DANGER - EXTREMELY PERMISSIVE RULE ⚠️</summary>
    <p> This allows unrestricted inbound traffic from any source, any port, to any destination, any port, on any protocol. This rule is highly permissive and poses significant security risks. It should only be used temporarily for troubleshooting or in very specific, controlled scenarios with careful monitoring and risk assessment. Review this rule regularly and remove it as soon as it is no longer absolutely necessary. Please consider using more restrictive rules whenever possible.</p>
    </details>


<details>
    <summary>Image: WindowsVM NSG </summary>
    <p align="center">
    <img src="https://i.imgur.com/HtNarQw.png[/img]" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
    </p>
</details>

<details>
    <summary>Image: LinuxVM NSG </summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/345c0ddb-0cb2-4843-8765-77dc04ee4c78" height="200%" width="200%" alt="Creating LinuxVM"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9a721629-6929-49db-91f9-665ea0e64cbb" height="200%" width="200%" alt="Creating LinuxVM"/>
</details>

<!--
![delete  ssh LinuxVM-nsg-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/345c0ddb-0cb2-4843-8765-77dc04ee4c78)
![Add-inbound-security-rule-Microsoft-Azure](https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9a721629-6929-49db-91f9-665ea0e64cbb)
-->

### RDP - Remote Desktop Protocol 3389
---
**Remote into WindowsVM**
1) We will now remote into the WindowsVM for the first time. If you have windows, you can simply search "Remote Desktop Connection" in the search bar. If you have a Mac, you can download Microsoft Remote Desktop app in the App Store. 
2) Enter in the public IP address of the WindowsVM and enter your credentials you had created when configuring the WindowsVM.
    <details>
    <summary>Video: RDP into WindowsVM</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/dd1ff80c-379e-4c40-88ff-a3b79bc38ed8</p>
    </details>

**Turning off Firewall inside WindowsVM**
1) Search "wf.msc" in the search bar and select the application.
2) Click on "Windows Defender Firewall Properties" and turn off the firewall for the Domain Profile, Private Profile, and Public Profile. 
3) Apply the changes and click save. 

    <details>
    <summary>Turning Off Firewall Video</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9887cc34-0fd3-456e-8ef4-1121d5e5ea8a</p>
    </details>  


**Edit Registry Editor**  
The Registry Editor - Regedit, is a tool in Microsoft Windows OS that allows users to view and edit the Windows Registry, which is a hierachial database that stores configuration settings and options. 
- We will be configuring the security event log by adding the Network Service account full control for the Log Analytics Workspace agent to have access to the registry keys.
1) Navigate to Registry Editor by searching in the search bar.
2) Input the registry key to the registry path and open the properties to access Permissions for Security.
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security
    ```
3) Add a Group - iinput "NETWORK SERVICE" and allow full control. 
4) Apply and save the changes. 
<details>
    <summary>Edit Registry Video</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/71fab93d-054f-4fca-a58d-e15a644dcf6e</p>
</details>

### Log Analytics Workspace
---
The purpose of Log Analytics Workspace (LAW) is to ingest the logs from the virtual machine into Microsoft Sentinel using the LAW agent.  
Logs are digital documentation of actions on a computer/user, the agent is a category of software that does something on behalf of the user/system.   
The monitor agent will take the logs on the VM and will aggregate to LAW and microsoft sentinel will filter the logs. 

1) Navigate to LAW in the Azure portal
2) Create a new LAW and add the workspace in the same resource group you have for the VM. 
3) Name your workspace and place it in the same region. 
4) Review and Create. 

**LAW WindowsVM**  
1) Once the LAW is created, navigate to the Agents section under Settings of the LAW.
2) Under the Windows server there is a Log Analytics agent instruction, copy the link to "Download Windows Agent (64_bit)" and switch to the WindowsVM. 
3) Paste the copied link into a browser and it will automatically download a setup.exe. 
4) Run the downloaded setup.exe and make sure the "Connect the agent to Azure Log Analytics (OHS)" is checked. 
5) The agent setup will ask for the Workspace ID and Workspace Key, which is in the Azure portal
6) Install and Finish. Your agent is now on the WindowsVM.
    <details>
    <summary>Video: Adding LAW Agent to WindowsVM</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/4c5a1811-9008-4403-ab1c-ba7a950b2ffc</p>
    </details>

**LAW LinuxVM**
1) In the Agents section under Settings of LAW, there is a tab for Linux Server. 
2) There is a Log Analytics agent instruction, copy the "Download and onboard agent for Linux". 
3) SSH into the Linux machine via Powershell - "SSH username@PUBLIC_IP_Addr_LinuxVM
4) Enter your password for your LinuxVM and paste the wget information.
5) After the agent has been added, you can enter "exit" to disconnect from you LinuxVM. 
    <details>
    <summary>Video: Adding LAW Agent to LinuxVM</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/bc4ad540-ee34-4c82-8f91-5da928a09630</p>
    </details>


### Data Collection Rules
---
Data Collection Rules are designed to simplify the process of configuring and managing data collection, by defining configurations centrally on how data is collected across multiple resources. 
1) Navigate to the Data Collection Rules and create a new DCR. 
2) Give your DCR a rule name, put the DCR in the same resource group, ensure the region is in the same region, and select "All" for the Platform Type. 
3) Under the Resource tab, select "Add resources" and chose both LinuxVM and WindowsVM. 
4) Under the Collect and Deliver tab, click on "Add data source"
    - Select Linux Syslog under Data source type and only allow Log_Auth to have LOG_DEBUG. All other Facilities can be changed to none. Add the data source.
    - Select Windows Event Logs under Data source type and click on information, Audit sucess, and Audit failure under the basic tab. In the custom tab, add these two custom event logs. Add the data source.
        <details><summary>Custom Event Logs</summary>
        Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1116 or EventID=1117)]]    
        
        Microsoft-Windows-Windows Firewall With Advanced Security/Firewall!*[System[(EventID=2003)]]
        </details>
5) Review and Create the Data Collection Rule.
     <details>
    <summary>Video: Data Collection Rules</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/819d3212-4915-4b4d-8b9b-20d33535c9ed</p>
    </details>


### Microsoft Sentinel
---
Microsoft Sentinel is a cloud-native SIEM (Security Information and Event Mangement) and SOAR (Security, Orchestration, Automation, and Response) solution provided by Microsoft, it is designed to help detect, respond to, and mitigate cyberseucrity threats. 

**Create Microsoft Sentinel**
1) Navigate to Microsoft Sentinel via the search bar. 
2) Click on "Create Microsoft Sentinel"
3) Select the workspace we created earlier. 
4) Click on the Add button at the bottom 
    <details>
     <summary>Video: Creating Microsoft Sentinel</summary>
        <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/a9f74906-c33e-4d8b-a6b8-e0d6cd739b7f</p>
    </details>

**Create Watchlist**  
A watchlist is a list of data you import from external source, the data can be relevant to the security analysis, which in this case we will be able to look at a world map to see the different places in the world via IP address that attempts malicious acivities on the VMs.
1) Nacigate to Watchlist under the Content Management in Microsoft Sentinel. 
2) Create a new watchlist and name the watchlist "geoip" and name the Alias as "geoip".
3) In the source tab: upload the geoip-summarized.csv file and select "network" for the SearchKey
4) Review and Create. 
    <details>
     <summary>Video: Creating Watchlist</summary>
        <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/e8408e0d-582a-4dfc-acdc-ee37902ef0aa</p>
    </details>

**Creating Sentinel Analytics KQL Rules**  
Sentinel Analytics involves using advance analytics, machine learning, and AI to enhance threat detection, response, and investigation capabilities.
1) Within Microsoft Sentinel, navigate to Analytics under the Configuration section. 
2) Select the import option on the top section. 
3) Import the KQL file for the custom alerts. 
    <details>
    <summary>Image: Sentinel Analytics Rule KQL</summary>
    <p align="center">
    <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/de543732-acfc-48b5-98ee-36bac94a7b1f" height="200%" width="200%" alt="Sentinel Analytics Rule KQL"/>
    </p>
    </details>

### Storage Account
---
Azure storage account is a highly durable, available, and scalable cloud storage solution. The account is the container for storage services and acts as a unique namespace for the data it holds.  
In this project, we will utilize the storage account for blob storage, which is designed for storing massive amounts of unstructured data - specifically logs from the VMs. 

**Creating Storage Account**
1) In the search bar, search for Storage Accounts.
2) Click on Create a Storage Account. 
3) Add the same resource group we have been using, name the storage account, and place the storage account in the same region. 
4) Review and Create. 
    <details>
        <summary>Image: Creating Storage Account</summary>
        <p align="center">
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/0acbbf52-9dee-440a-be06-2f8d38feca8a" height="200%" width="200%" alt="Creating Storage Account"/>
        </p>
    </details>

**Diagnostic Settings Creation**
The Diagnostic Settings for a storage account allows you to configure and route diagnostic data from the storage account to a different destination for monitoring, analysis, and troubleshooting. Diagnostic Settings help you capture telemetry and logs related to the performance, operations, and security of your Azure Storage account.
1) In the storage account, navigate to Diagnostic Settings under Monitoring and select the blob storage account. 
2) Click on Add diagnostic settings.
3) Name the Diagnostic Setting, click on audit, select the Log Analytics Workspace that we created earlier, and save the configuration. 
    <details>
    <summary>Images: Creating Diagnostics Settings</summary>
            <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/7c3f8784-c405-4c7a-8a3e-6bd24e1e713d" height="200%" width="200%" alt="1socstorage1-Microsoft-Azure"/>
            <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c211be9a-3442-44b3-b3b8-10baee2b0634" height="200%" width="200%" alt="2socstorage1-Microsoft-Azure"/>
            <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/232c3d3f-341f-47d3-8a26-5896e0cf17a1" height="200%" width="200%" alt="3Diagnostic-setting-Microsoft-Azure"/>
    </details>

**Creating Containers**
Containers in Azure Blob Storageare used to organize and manage sets of blobs which are the basic units of data storage. 
1) In the storage account, navigate to containers under Data Storage. 
2) Add a container, give the container a name, and create the container. 
3) In the newly created container, upload a test file. 
4) Now view/edit the file a few times. This will trigger an alert in Microsoft Sentinel because we had uploaded a custom KQL query to notify us if a document has been altered x amount of times. 
    <details>
        <summary>Images: Creating Containers</summary>
            <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/797cfae7-8fd2-4054-9dc1-9672d2d0bfec" height="200%" width="200%" alt="1New-container-Microsoft-Azure"/>
            <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/839494fe-3ec9-49de-b663-63695e8734d2" height="200%" width="200%" alt="2Upload-blob-Microsoft-Azure"/>
            <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/58f932f7-3c94-430a-8196-9add047884e2" height="200%" width="200%" alt="3test-Microsoft-Azure"/>
    </details>


### Network Security Group Flow Logs
---
NSG Flow logs provide a way to capture information about network traffic flowing through NSG. The flow logs offer detailed visibility into the network traffic that is processed by NSGs aiding in monitoring, troubleshooting, and security analysis.  

**Creating NSG Flow Logs**
1) Navigate to Network Security groups, select NSG flow logs under monitoring in the Linux VM NSG. 
2) Click on create new NSG Flow logs.
3) Select the LinuxVM and WindowsVM nsg resources and make sure the retention is 0. 
4) Under the analytics tab, select version 2, enable traffic analytics, select traffic analysis processing interval every 10 minutes, and make sure the LAW is the same workspace we created earlier. 
5) Review and Create. 
    <details>
    <summary>Images: Creating NSG Flow Logs</summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/621c8954-6500-47ec-8ea6-f71f77f82ec4" height="200%" width="200%" alt="1Create-a-flow-log-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/ec015c27-b6fb-4feb-ae7b-6561e27af42f" height="200%" width="200%" alt="2Create-a-flow-log-Microsoft-Azure"/>
    </details>

### Microsoft Defender for Cloud
---
Microsoft Defender for Cloud is a multicloud security solution that provides native CSPM cabailities for Azure, AWS, and GCP environemtns and support threat protection across these platforms. 
1) In the search bar, search for Microsoft Defender for Cloud. 
2) Select the Environment Settings under Management in Microsoft Defender for Cloud. 
3) Click the dropdown for Azure subscription we have been using and select the Log Analytics Workspace to edit the settings. 
4) In the Defender plans under settings, turn on the Servers and SQL servers on machines and Save the settings. 
5) In the Data collection under settings, select All Events and save the settings. 
6) Return back to the environment settings in Microsoft Defender for Cloud and select to edit settings in the Azure subscription. 
7) In the Defender plans under settings, turn on Servers, Databases, Storage, and Key Vault. Then click on the settings in the Servers plan. 
8) Click on Edit Configuration under the Log Analytics agent
9) Select the custom workspace and select the LAW we created earlier, select all events, apply the changes, and save the configuration. 
10) Select Continuous export under the settings and chose Log Analytics workspace as the Event hub, click on security recommendations, secure score, and security alerts, make this will be under the same resource group, select the LAW we created before to the target workspace, and then save the configuration. 
    <details>
    <summary>Images: Microsoft Defender for Cloud</summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/af45930e-8d0a-4d10-9ea5-412289de9dbc" height="200%" width="200%" alt="1Microsoft-Defender-for-Cloud-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c9cdb205-690b-40d8-884f-f9572c86a5ad" height="200%" width="200%" alt="2Settings-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/83129709-c58a-40ba-b008-abb5785b5de0" height="200%" width="200%" alt="3Settings-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/d59d212a-9458-4762-a0a0-a7abf0afa945" height="200%" width="200%" alt="4Microsoft-Defender-for-Cloud-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/b5c9b7e1-a5cf-4113-9b35-49fe0072b67b" height="200%" width="200%" alt="5Settings-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/ad2f967a-e99b-4327-9b95-ce250a6b7cdf" height="200%" width="200%" alt="6Settings-monitoring-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/53849c16-0015-47a1-9e98-90d277ca29a4" height="200%" width="200%" alt="7Auto-provisioning-configuration-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/932b6681-981b-49f1-b187-f7675b8491b5" height="200%" width="200%" alt="8Settings-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/c79a68de-80d0-4923-805d-979cac6fdc00" height="200%" width="200%" alt="9Settings-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/0212665a-0c68-4942-99a3-a8ec3bc01805" height="200%" width="200%" alt="10Settings-Microsoft-Azure"/>
    </details>

### Monitor
---
Azure Monitor is a comprehensive set of services in Azure designed to provide visibility into performance, health, and operation of resources within Azure environment. This is where you can view logs under the activity logs and export the logs.  
**Configure Monitor**
1) Navigate to Monitor by searching in the search bar.
2) Click on Activity log and chose to export Activity logs.
3) Click on Add diagnostic setting, name the diagnostic setting, make sure all the categories for logs are checked and the destination details are sent to the log analytics workspace we created earlier. 
4) Save the configuration. 
    <details>
        <summary>Images: Configuring Monitor-Activity logs</summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9fcfe27a-413a-4334-b06a-6da1d8516d40" height="200%" width="200%" alt="1Monitor-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/59621859-dcd4-4e18-9e74-c0eece3f4d3d" height="200%" width="200%" alt="2Diagnostic-settings-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/a564c58b-b277-4e00-9c56-bfd6fbf57be3" height="200%" width="200%" alt="3Diagnostic-setting-Microsoft-Azure"/>
    </details>


### Key Vault
---
A Key Vault is enable secure storage and management of sensitive information such as secrets, encryption keys and certificates. Key Vault helps securley store and control access of sensitive data used by applications and services. Key Vault helps organizations meet compliance requirements and ensure that sensitive data is stored and accessed in a secure and controlled manner. 

**Creating Key Vault**
1) Search for Key Vault in the search bar and click on Create Key Vault. 
2) Select the same resource group from before, name the keyvault, choose the same region, and make sure the purge protection is disabled. 
3) In Access Configuration tab, select vault access policy. 
4) Review and Create. 
    <details>
    <summary>Images: Creating Key Vault</summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/ce2e808d-a2b3-4b11-bc31-f4766f18bffb" height="200%" width="200%" alt="1Key-vaults-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/4f7ef00b-63e3-464d-ba4f-2388692d7945" height="200%" width="200%" alt="2Create-a-key-vault-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/2cbeb6bc-d608-4347-ba87-104db676f498" height="200%" width="200%" alt="3Create-a-key-vault-Microsoft-Azure"/>
    </details>

**Creating Diagnostic Settings**
Diagnostic settings in Azure Key Vault allows you to route platform metrics, resource logs, and activity logs to different destination for monitoring and analysis. Essentially, it helps you gain insights on how your Key Vault is performing and troubleshoot any issues. 
1) In Key Vault, select diagnostic settings under monitoring and add a diagnostic settings. 
2) Name the diagnostic setting, select audit under logs, select send to LAW under destination details, and then save the setting. 
    <details>
    <summary>Images: Creating Diagnostic Settings Azure Key Vault</summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/d426e6a7-552d-454f-9108-ba1aa1b969e2" height="200%" width="200%" alt="1KeyVault-SOC1-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/4e5b3e46-d6a0-43cd-97ec-f12e0761aa17" height="200%" width="200%" alt="2Diagnostic-setting-Microsoft-Azure"/>
    </details>

**Generating Secrets**
Azure Key Vault Secrets are sensitive information you want to tightly control access and keep secure.  
1) In Key Vault, select secrets under Objects and click on generate/import.
2) Name the secret, type in a secret value, and click on create. 
3) We can generate an alert in Microsoft Sentinel from one of our custom alerts by showing the secret value >10 times. 
    <details>
    <summary>Images: Generating Secrets</summary>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/45f93770-c559-4ee0-a585-c4096c20dc90" height="200%" width="200%" alt="1KeyVault-SOC1-Microsoft-Azure"/>
        <img src="https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/9d718be7-c618-448e-9f37-5b528a2a70fb" height="200%" width="200%" alt="2Create-a-secret-Microsoft-Azure"/>
    </details>

### microsoft sentinel workbooks


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




<details>
    <summary>ECAIR File Video</summary>
    <p>https://github.com/hoangannnhhh/SIEM-reports/assets/117109586/0a5b0183-132d-4f88-ab57-6e48f6c913d3</p>
</details>
