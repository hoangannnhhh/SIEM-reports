


## Creating Virtual Machine

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

<details>
<summary>Image</summary>
<p align="center">
<img src="https://i.imgur.com/gwmg2gt.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>
<p align="center">
<img src="https://i.imgur.com/8iaZpsK.png" height="200%" width="200%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>
</details>

### Network Security Groups
- Firewall that acts as a security layer for azure resources within a virtual entwork: controlling inbound/outbound network traffic flow to and from the resources 
- Default inbound and outbound firewall rules: a
-first rule: RDP it is enabled by default for any port and any IP address
- under inbound security rules: delete RDP rule 
- now add new inbound rule:
    
    We will allow traffic on any port. We do this by using "*" 
    
⚠️ DANGER - EXTREMELY PERMISSIVE RULE ⚠️

Allows unrestricted inbound traffic from any source, any port, to any destination, any port, on any protocol.

This rule is highly permissive and poses significant security risks.

It should only be used temporarily for troubleshooting or in very specific, controlled scenarios with careful monitoring and risk assessment.

Review this rule regularly and remove it as soon as it is no longer absolutely necessary.

Please consider using more restrictive rules whenever possible.
