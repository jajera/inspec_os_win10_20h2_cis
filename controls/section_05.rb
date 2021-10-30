#
# Profile:: inspec_os_win10_20h2_cis
# Control:: section_05
#
# Copyright:: 2021, The Authors, All Rights Reserved.

control '5.1_L2_Ensure_Bluetooth_Audio_Gateway_Service_BTAGService_is_set_to_Disabled' do
  title "(L2) Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'"
  desc  "
    Service supporting the audio gateway role of the Bluetooth Handsfree Profile.

    The recommended state for this setting is: Disabled .

    Rationale: Bluetooth technology has inherent security risks - especially prior to the v2.1 standard. Wireless Bluetooth traffic is not well encrypted (if at all), so in a high-security environment, it should not be permitted, in spite of the added inconvenience of not being able to use Bluetooth devices.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BTAGService') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.2_L2_Ensure_Bluetooth_Support_Service_bthserv_is_set_to_Disabled' do
  title "(L2) Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'"
  desc  "
    The Bluetooth service supports discovery and association of remote Bluetooth devices.

    The recommended state for this setting is: Disabled .

    Rationale: Bluetooth technology has inherent security risks - especially prior to the v2.1 standard. Wireless Bluetooth traffic is not well encrypted (if at all), so in a high-security environment, it should not be permitted, in spite of the added inconvenience of not being able to use Bluetooth devices.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bthserv') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.3_L1_Ensure_Computer_Browser_Browser_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Maintains an updated list of computers on the network and supplies this list to computers designated as browsers.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** In Windows 8.1 and Windows 10, this service is bundled with the **SMB 1.0/CIFS File Sharing Support** optional feature. As a result, removing that feature (highly recommended unless backward compatibility is needed to XP/2003 and older Windows OSes - see [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/) ) will also remediate this recommendation. The feature is not installed by default starting with Windows 10 R1709.

    Rationale: This is a legacy service - its sole purpose is to maintain a list of computers and their network shares in the environment (i.e. \"Network Neighborhood\"). If enabled, it generates a lot of unnecessary traffic, including \"elections\" to see who gets to be the \"master browser\". This noisy traffic could also aid malicious attackers in discovering online machines, because the service also allows anyone to \"browse\" for shared resources without any authentication. This service used to be running by default in older Windows versions (e.g. Windows XP), but today it only remains for backward compatibility for very old software that requires it.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Browser') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Browser') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.4_L2_Ensure_Downloaded_Maps_Manager_MapsBroker_is_set_to_Disabled' do
  title "(L2) Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'"
  desc  "
    Windows service for application access to downloaded maps. This service is started on-demand by application accessing downloaded maps.

    Rationale: Mapping technologies can unwillingly reveal your location to attackers and other software that picks up the information. In addition, automatic downloads of data from 3rd-party sources should be minimized when not needed. Therefore this service should not be needed in high security environments.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MapsBroker') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.5_L2_Ensure_Geolocation_Service_lfsvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'"
  desc  "
    This service monitors the current location of the system and manages geofences (a geographical location with associated events).

    The recommended state for this setting is: Disabled .

    Rationale: This setting affects the location feature (e.g. GPS or other location tracking). From a security perspective, it&#x2019;s not a good idea to reveal your location to software in most cases, but there are legitimate uses, such as mapping software. However, they should not be used in high security environments.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\lfsvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.6_L1_Ensure_IIS_Admin_Service_IISADMIN_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Enables the server to administer the IIS metabase. The IIS metabase stores configuration for the SMTP and FTP services.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Internet Information Services** ).

    **Note #2:** An organization may choose to selectively grant exceptions to web developers to allow IIS (or another web server) on their workstation, in order for them to locally test  develop web pages. However, the organization should track those machines and ensure the security controls and mitigations are kept up to date, to reduce risk of compromise.

    Rationale: Hosting a website from a workstation is an increased security risk, as the attack surface of that workstation is then greatly increased. If proper security mitigations are not followed, the chance of successful attack increases significantly.

    **Note:** This security concern applies to **any** web server application installed on a workstation, not just IIS.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\IISADMIN') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\IISADMIN') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.7_L1_Ensure_Infrared_monitor_service_irmon_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Detects other Infrared devices that are in range and launches the file transfer application.

    The recommended state for this setting is: Disabled or Not Installed .

    Rationale: Infrared connections can potentially be a source of data compromise - especially via the automatic \"file transfer application\" functionality. Enterprise-managed systems should utilize a more secure method of connection than infrared.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\irmon') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\irmon') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.8_L1_Ensure_Internet_Connection_Sharing_ICS_SharedAccess_is_set_to_Disabled' do
  title "(L1) Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled'"
  desc  "
    Provides network access translation, addressing, name resolution and/or intrusion prevention services for a home or small office network.

    The recommended state for this setting is: Disabled .

    Rationale: Internet Connection Sharing (ICS) is a feature that allows someone to \"share\" their Internet connection with other machines on the network - it was designed for home or small office environments where only one machine has Internet access - it effectively turns that machine into an Internet router. This feature causes the  bridging of networks and likely bypassing other, more secure pathways. It should not be used on any enterprise-managed system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.9_L2_Ensure_Link-Layer_Topology_Discovery_Mapper_lltdsvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'"
  desc  "
    Creates a Network Map, consisting of PC and device topology (connectivity) information, and metadata describing each PC and device.

    The recommended state for this setting is: Disabled .

    Rationale: The feature that this service enables could potentially be used for unauthorized discovery and connection to network devices. Disabling the service helps to prevent responses to requests for network topology discovery in high security environments.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\lltdsvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.10_L1_Ensure_LxssManager_LxssManager_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    The LXSS Manager service supports running native ELF binaries. The service provides the infrastructure necessary for ELF binaries to run on Windows.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Windows Subsystem for Linux** ).

    Rationale: The Linux SubSystem (LXSS) Manager allows full system access to Linux applications on Windows, including the file system. While this can certainly have some functionality and performance benefits for running those applications, it also creates new security risks in the event that a hacker injects malicious code into a Linux application. For best security, it is preferred to run Linux applications on Linux, and Windows applications on Windows.
  "
  impact 1.0
  describe.one do
    describe "SCAP oval resource registry_test could not be loaded: Don't understand SCAP::OVAL::Objects: registry_object/behaviors" do
      skip "SCAP oval resource registry_test could not be loaded: Don't understand SCAP::OVAL::Objects: registry_object/behaviors"
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LxssManager') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.11_L1_Ensure_Microsoft_FTP_Service_FTPSVC_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Enables the server to be a File Transfer Protocol (FTP) server.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Internet Information Services - FTP Server** ).

    Rationale: Hosting an FTP server (especially a non-secure FTP server) from a workstation is an increased security risk, as the attack surface of that workstation is then greatly increased.

    **Note:** This security concern applies to **any** FTP server application installed on a workstation, not just IIS.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\FTPSVC') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\FTPSVC') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.12_L2_Ensure_Microsoft_iSCSI_Initiator_Service_MSiSCSI_is_set_to_Disabled' do
  title "(L2) Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'"
  desc  "
    Manages Internet SCSI (iSCSI) sessions from this computer to remote target devices.

    The recommended state for this setting is: Disabled .

    Rationale: This service is critically necessary in order to directly attach to an iSCSI device. However, iSCSI itself uses a very weak authentication protocol (CHAP), which means that the passwords for iSCSI communication are easily exposed, unless all of the traffic is isolated and/or encrypted using another technology like IPsec. This service is generally more appropriate for servers in a controlled environment then on workstations requiring high security.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MSiSCSI') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.13_L1_Ensure_OpenSSH_SSH_Server_sshd_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but it is installed by enabling an optional Windows feature ( **OpenSSH Server** ).

    Rationale: Hosting an SSH server from a workstation is an increased security risk, as the attack surface of that workstation is then greatly increased.

    **Note:** This security concern applies to **any** SSH server application installed on a workstation, not just the one supplied with Windows.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\sshd') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\sshd') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.14_L2_Ensure_Peer_Name_Resolution_Protocol_PNRPsvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'"
  desc  "
    Enables serverless peer name resolution over the Internet using the Peer Name Resolution Protocol (PNRP).

    The recommended state for this setting is: Disabled .

    Rationale: Peer Name Resolution Protocol is a distributed and (mostly) serverless way to handle name resolution of clients with each other. In a high security environment, it is more secure to rely on centralized name resolution methods maintained by authorized staff.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PNRPsvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.15_L2_Ensure_Peer_Networking_Grouping_p2psvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'"
  desc  "
    Enables multi-party communication using Peer-to-Peer Grouping.

    The recommended state for this setting is: Disabled .

    Rationale: Peer Name Resolution Protocol is a distributed and (mostly) serverless way to handle name resolution of clients with each other. In a high security environment, it is more secure to rely on centralized name resolution methods maintained by authorized staff.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\p2psvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.16_L2_Ensure_Peer_Networking_Identity_Manager_p2pimsvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'"
  desc  "
    Provides identity services for the Peer Name Resolution Protocol (PNRP) and Peer-to-Peer Grouping services.

    The recommended state for this setting is: Disabled .

    Rationale: Peer Name Resolution Protocol is a distributed and (mostly) serverless way to handle name resolution of clients with each other. In a high security environment, it is more secure to rely on centralized name resolution methods maintained by authorized staff.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\p2pimsvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.17_L2_Ensure_PNRP_Machine_Name_Publication_Service_PNRPAutoReg_is_set_to_Disabled' do
  title "(L2) Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'"
  desc  "
    This service publishes a machine name using the Peer Name Resolution Protocol. Configuration is managed via the netsh context &#x2018;p2p pnrp peer&#x2019;.

    The recommended state for this setting is: Disabled .

    Rationale: Peer Name Resolution Protocol is a distributed and (mostly) serverless way to handle name resolution of clients with each other. In a high security environment, it is more secure to rely on centralized name resolution methods maintained by authorized staff.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PNRPAutoReg') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.18_L2_Ensure_Problem_Reports_and_Solutions_Control_Panel_Support_wercplsupport_is_set_to_Disabled' do
  title "(L2) Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'"
  desc  "
    This service provides support for viewing, sending and deletion of system-level problem reports for the Problem Reports and Solutions control panel.

    The recommended state for this setting is: Disabled .

    Rationale: This service is involved in the process of displaying/reporting issues  solutions to/from Microsoft. In a high security environment, preventing this information from being sent can help reduce privacy concerns for sensitive corporate information.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wercplsupport') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.19_L2_Ensure_Remote_Access_Auto_Connection_Manager_RasAuto_is_set_to_Disabled' do
  title "(L2) Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'"
  desc  "
    Creates a connection to a remote network whenever a program references a remote DNS or NetBIOS name or address.

    The recommended state for this setting is: Disabled .

    Rationale: The function of this service is to provide a \"demand dial\" type of functionality. In a high security environment, it is preferred that any remote \"dial\" connections (whether they be legacy dial-in POTS or VPN) are initiated by the **user** , **not** automatically by the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RasAuto') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.20_L2_Ensure_Remote_Desktop_Configuration_SessionEnv_is_set_to_Disabled' do
  title "(L2) Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'"
  desc  "
    Remote Desktop Configuration service (RDCS) is responsible for all Remote Desktop related configuration and session maintenance activities that require SYSTEM context. These include per-session temporary folders, RD themes, and RD certificates.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security environment, Remote Desktop access is an increased security risk. For these environments, only local console access should be permitted.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SessionEnv') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.21_L2_Ensure_Remote_Desktop_Services_TermService_is_set_to_Disabled' do
  title "(L2) Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'"
  desc  "
    Allows users to connect interactively to a remote computer. Remote Desktop and Remote Desktop Session Host Server depend on this service.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security environment, Remote Desktop access is an increased security risk. For these environments, only local console access should be permitted.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.22_L2_Ensure_Remote_Desktop_Services_UserMode_Port_Redirector_UmRdpService_is_set_to_Disabled' do
  title "(L2) Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'"
  desc  "
    Allows the redirection of Printers/Drives/Ports for RDP connections.

    The recommended state for this setting is: Disabled .

    Rationale: In a security-sensitive environment, it is desirable to reduce the possible attack surface - preventing the redirection of COM, LPT and PnP ports will reduce the number of unexpected avenues for data exfiltration and/or malicious code transfer within an RDP session.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\UmRdpService') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.23_L1_Ensure_Remote_Procedure_Call_RPC_Locator_RpcLocator_is_set_to_Disabled' do
  title "(L1) Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'"
  desc  "
    In Windows 2003 and older versions of Windows, the Remote Procedure Call (RPC) Locator service manages the RPC name service database. In Windows Vista and newer versions of Windows, this service does not provide any functionality and is present for application compatibility.

    The recommended state for this setting is: Disabled .

    Rationale: This is a legacy service that has no value or purpose other than application compatibility for very old software. It should be disabled unless there is a specific old application still in use on the system that requires it.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RpcLocator') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.24_L2_Ensure_Remote_Registry_RemoteRegistry_is_set_to_Disabled' do
  title "(L2) Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'"
  desc  "
    Enables remote users to modify registry settings on this computer.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security environment, exposing the registry to remote access is an increased security risk.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.25_L1_Ensure_Routing_and_Remote_Access_RemoteAccess_is_set_to_Disabled' do
  title "(L1) Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'"
  desc  "
    Offers routing services to businesses in local area and wide area network environments.

    The recommended state for this setting is: Disabled .

    Rationale: This service's main purpose is to provide Windows router functionality - this is not an appropriate use of workstations in an enterprise managed environment.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RemoteAccess') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.26_L2_Ensure_Server_LanmanServer_is_set_to_Disabled' do
  title "(L2) Ensure 'Server (LanmanServer)' is set to 'Disabled'"
  desc  "
    Supports file, print, and named-pipe sharing over the network for this computer. If this service is stopped, these functions will be unavailable.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security environment, a secure workstation should only be a **client** , not a server. Sharing workstation resources for remote access increases security risk as the attack surface is notably higher.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.27_L1_Ensure_Simple_TCPIP_Services_simptcp_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Supports the following TCP/IP services: Character Generator, Daytime, Discard, Echo, and Quote of the Day.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Simple TCPIP services (i.e. echo, daytime etc)** ).

    Rationale: The Simple TCP/IP Services have very little purpose in a modern enterprise environment - allowing them might increase exposure and risk for attack.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\simptcp') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\simptcp') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.28_L2_Ensure_SNMP_Service_SNMP_is_set_to_Disabled_or_Not_Installed' do
  title "(L2) Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Enables Simple Network Management Protocol (SNMP) requests to be processed by this computer.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Simple Network Management Protocol (SNMP)** ).

    Rationale: Features that enable inbound network connections increase the attack surface. In a high security environment, management of secure workstations should be handled locally.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SNMP') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SNMP') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.29_L1_Ensure_Special_Administration_Console_Helper_sacsvr_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    This service allows administrators to remotely access a command prompt using Emergency Management Services.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but it is installed by enabling an optional Windows capability ( **Windows Emergency Management Services and Serial Console** ).

    Rationale: Allowing the use of a remotely accessible command prompt that provides the ability to perform remote management tasks on a computer is a security risk.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\sacsvr') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\sacsvr') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.30_L1_Ensure_SSDP_Discovery_SSDPSRV_is_set_to_Disabled' do
  title "(L1) Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'"
  desc  "
    Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices. Also announces SSDP devices and services running on the local computer.

    The recommended state for this setting is: Disabled .

    Rationale: Universal Plug n Play (UPnP) is a real security risk - it allows automatic discovery and attachment to network devices. Note that UPnP is different than regular Plug n Play (PnP). Workstations should not be advertising their services (or automatically discovering and connecting to networked services) in a security-conscious enterprise managed environment.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SSDPSRV') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.31_L1_Ensure_UPnP_Device_Host_upnphost_is_set_to_Disabled' do
  title "(L1) Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'"
  desc  "
    Allows UPnP devices to be hosted on this computer.

    The recommended state for this setting is: Disabled .

    Rationale: Universal Plug n Play (UPnP) is a real security risk - it allows automatic discovery and attachment to network devices. Notes that UPnP is different than regular Plug n Play (PnP). Workstations should not be advertising their services (or automatically discovering and connecting to networked services) in a security-conscious enterprise managed environment.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\upnphost') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.32_L1_Ensure_Web_Management_Service_WMSvc_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    The Web Management Service enables remote and delegated management capabilities for administrators to manage for the Web server, sites and applications present on the machine.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Internet Information Services - Web Management Tools - IIS Management Service** ).

    Rationale: Remote web administration of IIS on a workstation is an increased security risk, as the attack surface of that workstation is then greatly increased. If proper security mitigations are not followed, the chance of successful attack increases significantly.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WMSvc') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WMSvc') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.33_L2_Ensure_Windows_Error_Reporting_Service_WerSvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'"
  desc  "
    Allows errors to be reported when programs stop working or responding and allows existing solutions to be delivered. Also allows logs to be generated for diagnostic and repair services.

    The recommended state for this setting is: Disabled .

    Rationale: If a Windows Error occurs in a secure, enterprise managed environment, the error should be reported directly to IT staff for troubleshooting and remediation. There is no benefit to the corporation to report these errors directly to Microsoft, and there is some risk of unknowingly exposing sensitive data as part of the error.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WerSvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.34_L2_Ensure_Windows_Event_Collector_Wecsvc_is_set_to_Disabled' do
  title "(L2) Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'"
  desc  "
    This service manages persistent subscriptions to events from remote sources that support WS-Management protocol. This includes Windows Vista event logs, hardware and IPMI-enabled event sources. The service stores forwarded events in a local Event Log.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security environment, remote connections to secure workstations should be minimized, and management functions should be done locally.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Wecsvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.35_L1_Ensure_Windows_Media_Player_Network_Sharing_Service_WMPNetworkSvc_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Shares Windows Media Player libraries to other networked players and media devices using Universal Plug and Play.

    The recommended state for this setting is: Disabled or Not Installed .

    Rationale: Network sharing of media from Media Player has no place in an enterprise managed environment.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WMPNetworkSvc') do
      it { should_not have_property 'Start' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WMPNetworkSvc') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
  end
end

control '5.36_L1_Ensure_Windows_Mobile_Hotspot_Service_icssvc_is_set_to_Disabled' do
  title "(L1) Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'"
  desc  "
    Provides the ability to share a cellular data connection with another device.

    The recommended state for this setting is: Disabled .

    Rationale: The capability to run a mobile hotspot from a domain-connected computer could easily expose the internal network to wardrivers or other hackers.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.37_L2_Ensure_Windows_Push_Notifications_System_Service_WpnService_is_set_to_Disabled' do
  title "(L2) Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'"
  desc  "
    This service runs in session 0 and hosts the notification platform and connection provider which handles the connection between the device and WNS server.

    The recommended state for this setting is: Disabled .

    **Note:** In the first two releases of Windows 10 (R1507  R1511), the display name of this service was initially named **Windows Push Notifications Service** - but it was renamed to ** Windows Push Notifications **System** Service ** starting with Windows 10 R1607.

    Rationale: Windows Push Notification Services (WNS) is a mechanism to receive 3rd-party notifications and updates from the cloud/Internet. In a high security environment, external systems, especially those hosted outside the organization, should be prevented from having an impact on the secure workstations.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WpnService') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.38_L2_Ensure_Windows_PushToInstall_Service_PushToInstall_is_set_to_Disabled' do
  title "(L2) Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'"
  desc  "
    This service manages Apps that are pushed to the device from the Microsoft Store App running on other devices or the web.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security managed environment, application installations should be managed centrally by IT staff, not by end users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PushToInstall') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.39_L2_Ensure_Windows_Remote_Management_WS-Management_WinRM_is_set_to_Disabled' do
  title "(L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'"
  desc  "
    Windows Remote Management (WinRM) service implements the WS-Management protocol for remote management. WS-Management is a standard web services protocol used for remote software and hardware management. The WinRM service listens on the network for WS-Management requests and processes them.

    The recommended state for this setting is: Disabled .

    Rationale: Features that enable inbound network connections increase the attack surface. In a high security environment, management of secure workstations should be handled locally.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinRM') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.40_L1_Ensure_World_Wide_Web_Publishing_Service_W3SVC_is_set_to_Disabled_or_Not_Installed' do
  title "(L1) Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'"
  desc  "
    Provides Web connectivity and administration through the Internet Information Services Manager.

    The recommended state for this setting is: Disabled or Not Installed .

    **Note:** This service is not installed by default. It is supplied with Windows, but is installed by enabling an optional Windows feature ( **Internet Information Services - World Wide Web Services** ).

    **Note #2:** An organization may choose to selectively grant exceptions to web developers to allow IIS (or another web server) on their workstation, in order for them to locally test  develop web pages. However, the organization should track those machines and ensure the security controls and mitigations are kept up to date, to reduce risk of compromise.

    Rationale: Hosting a website from a workstation is an increased security risk, as the attack surface of that workstation is then greatly increased. If proper security mitigations are not followed, the chance of successful attack increases significantly.

    **Note:** This security concern applies to **any** web server application installed on a workstation, not just IIS.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W3SVC') do
      it { should have_property 'Start' }
      its('Start') { should cmp == 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W3SVC') do
      it { should_not have_property 'Start' }
    end
  end
end

control '5.41_L1_Ensure_Xbox_Accessory_Management_Service_XboxGipSvc_is_set_to_Disabled' do
  title "(L1) Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'"
  desc  "
    This service manages connected Xbox Accessories.

    The recommended state for this setting is: Disabled .

    Rationale: Xbox Live is a gaming service and has no place in an enterprise managed environment (perhaps unless it is a gaming company).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\XboxGipSvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.42_L1_Ensure_Xbox_Live_Auth_Manager_XblAuthManager_is_set_to_Disabled' do
  title "(L1) Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'"
  desc  "
    Provides authentication and authorization services for interacting with Xbox Live.

    The recommended state for this setting is: Disabled .

    Rationale: Xbox Live is a gaming service and has no place in an enterprise managed environment (perhaps unless it is a gaming company).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\XblAuthManager') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.43_L1_Ensure_Xbox_Live_Game_Save_XblGameSave_is_set_to_Disabled' do
  title "(L1) Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'"
  desc  "
    This service syncs save data for Xbox Live save enabled games.

    The recommended state for this setting is: Disabled .

    Rationale: Xbox Live is a gaming service and has no place in an enterprise managed environment (perhaps unless it is a gaming company).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\XblGameSave') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '5.44_L1_Ensure_Xbox_Live_Networking_Service_XboxNetApiSvc_is_set_to_Disabled' do
  title "(L1) Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'"
  desc  "
    This service supports the Windows.Networking.XboxLive application programming interface.

    The recommended state for this setting is: Disabled .

    Rationale: Xbox Live is a gaming service and has no place in an enterprise managed environment (perhaps unless it is a gaming company).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\XboxNetApiSvc') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end
