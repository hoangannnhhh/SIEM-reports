


<h3>Creating Virtual Machine</h3>
<p>- Create a resource group <br>

- Azure Resource Groups are logical 
grouping of related resources within a project, environment, or application, providing simplified management, governance through policies and RBAC, and aid in cost tracking and allocation. 

- Name your Windows machine, I named mine WindowsVM. 
- Select your region, I selected East US 2. 
- No infrastructure redudancy required. 
- Select the image type: Windows 10 Pro, version 22H2 - x64 Gen2  
- Select (Standard_E2ad_v5 - 2 vcpus, 16 GiB memory)
- Set the admin account name and password

- Networking:
- networking tab: The firewall will be open to the public internet, we will remove the default rules and create new inbound rule that will allow all incoming traffic. Create a new virtual network, I named it SOC-vnet
- Monitoring 
- disable boot diagnostics
- review and create

-- the purpose is to let the VM be discoverable by any means necessary: TCP ping, SYN scan, ICMP ping. 

<p align="center">
<img src="https://i.imgur.com/c9rE9QA.png" height="85%" width="85%" alt="Creating Windows VM part 1 - Basics tab"/>
</p>