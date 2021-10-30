#
# Profile:: inspec_os_win10_21h1_cis
# Control:: section_18
#
# Copyright:: 2021, The Authors, All Rights Reserved.

bitlocker = powershell(<<-EOH
  try {
    if(Get-Disk | Where-Object {$_.bustype -ne "USB"} | `
      Get-Partition | Where-Object { $_.DriveLetter } | `
      Select-Object -ExpandProperty DriveLetter | `
      Get-BitLockerVolume | Where-Object {$_.ProtectionStatus -eq 'Off'})
      {
        return 'off'
      }
    else
    {
      return 'on'
    }
  }
  catch {
    return 'error'
  }
EOH
                      ).stdout.strip

control '18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc  "
    Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.

    The recommended state for this setting is: Enabled.

    Rationale: Disabling the lock screen camera extends the protection afforded by the lock screen to camera features.
  "
  impact 1.0
  tag cce: 'CCE-35799-6'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should have_property 'NoLockScreenCamera' }
    its('NoLockScreenCamera') { should cmp == 1 }
  end
end

control '18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc  "
    Disables the lock screen slide show settings in PC Settings and prevents a slide show from playing on the lock screen.

    The recommended state for this setting is: Enabled.

    Rationale: Disabling the lock screen slide show extends the protection afforded by the lock screen to slide show contents.
  "
  impact 1.0
  tag cce: 'CCE-35800-2'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should have_property 'NoLockScreenSlideshow' }
    its('NoLockScreenSlideshow') { should cmp == 1 }
  end
end

control '18.1.2.1_L1_Ensure_Allow_Input_Personalization_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow Input Personalization' is set to 'Disabled'"
  desc  "
    This policy enables the automatic learning component of input personalization that includes speech, inking, and typing. Automatic learning enables the collection of speech and handwriting patterns, typing history, contacts, and recent calendar information. It is required for the use of Cortana. Some of this collected information may be stored on the user's OneDrive, in the case of inking and typing; some of the information will be uploaded to Microsoft to personalize speech.

    The recommended state for this setting is: Disabled

    Rationale: If this setting is Enabled sensitive information could be stored in the cloud or sent to Microsoft.
  "
  impact 1.0
  tag cce: 'CCE-41387-2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization') do
    it { should have_property 'AllowInputPersonalization' }
    its('AllowInputPersonalization') { should cmp == 0 }
  end
end

control '18.1.3_L2_Ensure_Allow_Online_Tips_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow Online Tips' is set to 'Disabled'"
  desc  "
    This policy setting configures the retrieval of online tips and help for the Settings app.

    The recommended state for this setting is: Disabled .

    Rationale: Due to privacy concerns, data should never be sent to any 3rd party since this data could contain sensitive information.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'AllowOnlineTips' }
    its('AllowOnlineTips') { should cmp == 0 }
  end
end

control '18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed' do
  title '(L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed'
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.

    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}') do
    it { should have_property 'DllName' }
    its('DllName') { should eq 'C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll' }
  end
end

control '18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

    The recommended state for this setting is: Enabled.

    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.

    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'PwdExpirationProtectionEnabled' }
    its('PwdExpirationProtectionEnabled') { should cmp == 1 }
  end
end

control '18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled' do
  title "(L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

    The recommended state for this setting is: Enabled.

    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.

    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'AdmPwdEnabled' }
    its('AdmPwdEnabled') { should cmp == 1 }
  end
end

control '18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters' do
  title "(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

    The recommended state for this setting is: Enabled: Large letters + small letters + numbers + special characters.

    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.

    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'PasswordComplexity' }
    its('PasswordComplexity') { should cmp == 4 }
  end
end

control '18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more' do
  title "(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

    The recommended state for this setting is: Enabled: 15 or more.

    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.

    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'PasswordLength' }
    its('PasswordLength') { should cmp >= 15 }
  end
end

control '18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer' do
  title "(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.

    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.

    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.

    The recommended state for this setting is: Enabled: 30 or fewer.

    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.

    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd') do
    it { should have_property 'PasswordAgeDays' }
    its('PasswordAgeDays') { should cmp <= 30 }
  end
end

control '18.3.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled' do
  title "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
  desc  "
    This setting controls whether local accounts can be used for remote administration via network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.

    **Enabled:** Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy registry value to 0 . This is the default behavior for Windows.

    **Disabled:** Allows local accounts to have full administrative rights when authenticating via network logon, by configuring the LocalAccountTokenFilterPolicy registry value to 1 .

    For more information about local accounts and credential theft, review the \" [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036) \" documents.

    For more information about LocalAccountTokenFilterPolicy , see Microsoft Knowledge Base article 951016: [Description of User Account Control and remote restrictions in Windows Vista](https://support.microsoft.com/en-us/kb/951016) .

    The recommended state for this setting is: Enabled .

    Rationale: Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Ensuring this policy is Enabled significantly reduces that risk.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'LocalAccountTokenFilterPolicy' }
    its('LocalAccountTokenFilterPolicy') { should cmp == 0 }
  end
end

control '18.3.2_L1_Ensure_Configure_SMB_v1_client_driver_is_set_to_Enabled_Disable_driver_recommended' do
  title "(L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
  desc  "
    This setting configures the start type for the Server Message Block version 1 (SMBv1) client driver service ( MRxSmb10 ), which is recommended to be disabled.

    The recommended state for this setting is: Enabled: Disable driver (recommended) .

    **Note:** Do not, **under any circumstances** , configure this overall setting as Disabled , as doing so will delete the underlying registry entry altogether, which will cause serious problems.

    Rationale: Since September 2016, Microsoft has strongly encouraged that SMBv1 be disabled and no longer used on modern networks, as it is a 30 year old design that is much more vulnerable to attacks then much newer designs such as SMBv2 and SMBv3.

    More information on this can be found at the following links:

    [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

    [Disable SMB v1 in Managed Environments with Group Policy &#x2013; \"Stay Safe\" Cyber Security Blog](https://blogs.technet.microsoft.com/staysafe/2017/05/17/disable-smb-v1-in-managed-environments-with-ad-group-policy/)

    [Disabling SMBv1 through Group Policy &#x2013; Microsoft Security Guidance blog](https://blogs.technet.microsoft.com/secguide/2017/06/15/disabling-smbv1-through-group-policy/)
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10') do
    it { should have_property 'Start' }
    its('Start') { should cmp == 4 }
  end
end

control '18.3.3_L1_Ensure_Configure_SMB_v1_server_is_set_to_Disabled' do
  title "(L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
  desc  "
    This setting configures the server-side processing of the Server Message Block version 1 (SMBv1) protocol.

    The recommended state for this setting is: Disabled .

    Rationale: Since September 2016, Microsoft has strongly encouraged that SMBv1 be disabled and no longer used on modern networks, as it is a 30 year old design that is much more vulnerable to attacks then much newer designs such as SMBv2 and SMBv3.

    More information on this can be found at the following links:

    [Stop using SMB1 | Storage at Microsoft](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

    [Disable SMB v1 in Managed Environments with Group Policy &#x2013; \"Stay Safe\" Cyber Security Blog](https://blogs.technet.microsoft.com/staysafe/2017/05/17/disable-smb-v1-in-managed-environments-with-ad-group-policy/)

    [Disabling SMBv1 through Group Policy &#x2013; Microsoft Security Guidance blog](https://blogs.technet.microsoft.com/secguide/2017/06/15/disabling-smbv1-through-group-policy/)
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    it { should have_property 'SMB1' }
    its('SMB1') { should cmp == 0 }
  end
end

control '18.3.4_L1_Ensure_Enable_Structured_Exception_Handling_Overwrite_Protection_SEHOP_is_set_to_Enabled' do
  title "(L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
  desc  "
    Windows includes support for Structured Exception Handling Overwrite Protection (SEHOP). We recommend enabling this feature to improve the security profile of the computer.

    The recommended state for this setting is: Enabled .

    Rationale: This feature is designed to block exploits that use the Structured Exception Handler (SEH) overwrite technique. This protection mechanism is provided at run-time. Therefore, it helps protect applications regardless of whether they have been compiled with the latest improvements, such as the /SAFESEH option.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel') do
    it { should have_property 'DisableExceptionChainValidation' }
    its('DisableExceptionChainValidation') { should cmp == 0 }
  end
end

control '18.3.5_L1_Ensure_NetBT_NodeType_configuration_is_set_to_Enabled_P-node_recommended' do
  title "(L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
  desc  "
    This setting determines which method NetBIOS over TCP/IP (NetBT) uses to register and resolve names. The available methods are:

    * The B-node (broadcast) method only uses broadcasts.
    * The P-node (point-to-point) method only uses name queries to a name server (WINS).
    * The M-node (mixed) method broadcasts first, then queries a name server (WINS) if broadcast failed.
    * The H-node (hybrid) method queries a name server (WINS) first, then broadcasts if the query failed.
    The recommended state for this setting is: Enabled: P-node (recommended) (point-to-point).

    **Note:** Resolution through LMHOSTS or DNS follows these methods. If the NodeType registry value is present, it overrides any DhcpNodeType registry value. If neither NodeType nor DhcpNodeType is present, the computer uses B-node (broadcast) if there are no WINS servers configured for the network, or H-node (hybrid) if there is at least one WINS server configured.

    Rationale: In order to help mitigate the risk of NetBIOS Name Service (NBT-NS) poisoning attacks, setting the node type to P-node (point-to-point) will prevent the system from sending out NetBIOS broadcasts.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    it { should have_property 'NodeType' }
    its('NodeType') { should cmp == 2 }
  end
end

control '18.3.6_L1_Ensure_WDigest_Authentication_is_set_to_Disabled' do
  title "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc  "
    When WDigest authentication is enabled, Lsass.exe retains a copy of the user's plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.

    For more information about local accounts and credential theft, review the \" [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036) \" documents.

    For more information about UseLogonCredential , see Microsoft Knowledge Base article 2871997: [Microsoft Security Advisory Update to improve credentials protection and management May 13, 2014](https://support.microsoft.com/en-us/kb/2871997) .

    The recommended state for this setting is: Disabled .

    Rationale: Preventing the plaintext storage of credentials in memory may reduce opportunity for credential theft.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest') do
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should cmp == 0 }
  end
end

control '18.4.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled' do
  title "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc  "
    This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group.

    For additional information, see Microsoft Knowledge Base article 324737: [How to turn on automatic logon in Windows](https://support.microsoft.com/en-us/kb/324737) .

    The recommended state for this setting is: Disabled .

    Rationale: If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks that the computer is connected to. Also, if you enable automatic logon, the password is stored in the registry in plaintext. The specific registry key that stores this setting is remotely readable by the Authenticated Users group. As a result, this entry is appropriate only if the computer is physically secured and if you ensure that untrusted users cannot remotely see the registry.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'AutoAdminLogon' }
    its('AutoAdminLogon') { should eq '0' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should_not have_property 'DefaultPassword' }
  end
end

control '18.4.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled' do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should follow through the network.

    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled .

    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

control '18.4.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled' do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should take through the network. It is recommended to configure this setting to Not Defined for enterprise environments and to Highest Protection for high security environments to completely disable source routing.

    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled .

    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

control '18.4.4_L2_Ensure_MSS_DisableSavePassword_Prevent_the_dial-up_password_from_being_saved_is_set_to_Enabled' do
  title "(L2) Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'"
  desc  "
    When you dial a phonebook or VPN entry in Dial-Up Networking, you can use the \"Save Password\" option so that your Dial-Up Networking password is cached and you will not need to enter it on successive dial attempts. For security, administrators may want to prevent users from caching passwords.

    The recommended state for this setting is: Enabled .

    Rationale: An attacker who steals a mobile user's computer could automatically connect to the organization's network if the **Save This Password** check box is selected for the dial-up or VPN networking entry used to connect to your organization's network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\RasMan\\Parameters') do
    it { should have_property 'disablesavepassword' }
    its('disablesavepassword') { should cmp == 1 }
  end
end

control '18.4.5_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled' do
  title "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc  "
    Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host routes. These routes override the Open Shortest Path First (OSPF) generated routes.

    The recommended state for this setting is: Disabled .

    Rationale: This behavior is expected. The problem is that the 10 minute time-out period for the ICMP redirect-plumbed routes temporarily creates a network situation in which traffic will no longer be routed properly for the affected host. Ignoring such ICMP redirects will limit the system's exposure to attacks that will impact its ability to participate on the network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'EnableICMPRedirect' }
    its('EnableICMPRedirect') { should cmp == 0 }
  end
end

control '18.4.6_L2_Ensure_MSS_KeepAliveTime_How_often_keep-alive_packets_are_sent_in_milliseconds_is_set_to_Enabled_300000_or_5_minutes_recommended' do
  title "(L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
  desc  "
    This value controls how often TCP attempts to verify that an idle connection is still intact by sending a keep-alive packet. If the remote computer is still reachable, it acknowledges the keep-alive packet.

    The recommended state for this setting is: Enabled: 300,000 or 5 minutes (recommended) .

    Rationale: An attacker who is able to connect to network applications could establish numerous connections to cause a DoS condition.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'KeepAliveTime' }
    its('KeepAliveTime') { should cmp == 300000 }
  end
end

control '18.4.7_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled' do
  title "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc  "
    NetBIOS over TCP/IP is a network protocol that among other things provides a way to easily resolve NetBIOS names that are registered on Windows-based systems to the IP addresses that are configured on those systems. This setting determines whether the computer releases its NetBIOS name when it receives a name-release request.

    The recommended state for this setting is: Enabled .

    Rationale: The NetBT protocol is designed not to use authentication, and is therefore vulnerable to spoofing. Spoofing makes a transmission appear to come from a user other than the user who performed the action. A malicious user could exploit the unauthenticated nature of the protocol to send a name-conflict datagram to a target computer, which would cause the computer to relinquish its name and not respond to queries.

    An attacker could send a request over the network and query a computer to release its NetBIOS name. As with any change that could affect applications, it is recommended that you test this change in a non-production environment before you change the production environment.

    The result of such an attack could be to cause intermittent connectivity issues on the target computer, or even to prevent the use of Network Neighborhood, domain logons, the NET SEND command, or additional NetBIOS name resolution.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    it { should have_property 'nonamereleaseondemand' }
    its('nonamereleaseondemand') { should cmp == 1 }
  end
end

control '18.4.8_L2_Ensure_MSS_PerformRouterDiscovery_Allow_IRDP_to_detect_and_configure_Default_Gateway_addresses_could_lead_to_DoS_is_set_to_Disabled' do
  title "(L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
  desc  "
    This setting is used to enable or disable the Internet Router Discovery Protocol (IRDP), which allows the system to detect and configure default gateway addresses automatically as described in RFC 1256 on a per-interface basis.

    The recommended state for this setting is: Disabled .

    Rationale: An attacker who has gained control of a computer on the same network segment could configure a computer on the network to impersonate a router. Other computers with IRDP enabled would then attempt to route their traffic through the already compromised computer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'PerformRouterDiscovery' }
    its('PerformRouterDiscovery') { should cmp == 0 }
  end
end

control '18.4.9_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled' do
  title "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc  "
    The DLL search order can be configured to search for DLLs that are requested by running processes in one of two ways:

    * Search folders specified in the system path first, and then search the current working folder.
    * Search current working folder first, and then search the folders specified in the system path.
    When enabled, the registry value is set to 1 . With a setting of 1 , the system first searches the folders that are specified in the system path and then searches the current working folder. When disabled the registry value is set to 0 and the system first searches the current working folder and then searches the folders that are specified in the system path.

    Applications will be forced to search for DLLs in the system path first. For applications that require unique versions of these DLLs that are included with the application, this entry could cause performance or stability problems.

    The recommended state for this setting is: Enabled .

    **Note:** More information on how Safe DLL search mode works is available at this link: [Dynamic-Link Library Search Order - Windows applications | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

    Rationale: If a user unknowingly executes hostile code that was packaged with additional files that include modified versions of system DLLs, the hostile code could load its own versions of those DLLs and potentially increase the type and degree of damage the code can render.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    it { should have_property 'SafeDllSearchMode' }
    its('SafeDllSearchMode') { should cmp == 1 }
  end
end

control '18.4.10_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds' do
  title "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc  "
    Windows includes a grace period between when the screen saver is launched and when the console is actually locked automatically when screen saver locking is enabled.

    The recommended state for this setting is: Enabled: 5 or fewer seconds .

    Rationale: The default grace period that is allowed for user movement before the screen saver lock takes effect is five seconds. If you leave the default grace period configuration, your computer is vulnerable to a potential attack from someone who could approach the console and attempt to log on to the computer before the lock takes effect. An entry to the registry can be made to adjust the length of the grace period.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'ScreenSaverGracePeriod' }
    its('ScreenSaverGracePeriod') { should cmp <= 5 }
  end
end

control '18.4.11_L2_Ensure_MSS_TcpMaxDataRetransmissions_IPv6_How_many_times_unacknowledged_data_is_retransmitted_is_set_to_Enabled_3' do
  title "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc  "
    This setting controls the number of times that TCP retransmits an individual data segment (non-connect segment) before the connection is aborted. The retransmission time-out is doubled with each successive retransmission on a connection. It is reset when responses resume. The base time-out value is dynamically determined by the measured round-trip time on the connection.

    The recommended state for this setting is: Enabled: 3 .

    Rationale: A malicious user could exhaust a target computer's resources if it never sent any acknowledgment messages for data that was transmitted by the target computer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should cmp == 3 }
  end
end

control '18.4.12_L2_Ensure_MSS_TcpMaxDataRetransmissions_How_many_times_unacknowledged_data_is_retransmitted_is_set_to_Enabled_3' do
  title "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
  desc  "
    This setting controls the number of times that TCP retransmits an individual data segment (non-connect segment) before the connection is aborted. The retransmission time-out is doubled with each successive retransmission on a connection. It is reset when responses resume. The base time-out value is dynamically determined by the measured round-trip time on the connection.

    The recommended state for this setting is: Enabled: 3 .

    Rationale: A malicious user could exhaust a target computer's resources if it never sent any acknowledgment messages for data that was transmitted by the target computer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    it { should have_property 'tcpmaxdataretransmissions' }
    its('tcpmaxdataretransmissions') { should cmp == 3 }
  end
end

control '18.4.13_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less' do
  title "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc  "
    This setting can generate a security audit in the Security event log when the log reaches a user-defined threshold.

    The recommended state for this setting is: Enabled: 90% or less .

    **Note:** If log settings are configured to Overwrite events as needed or Overwrite events older than x days, this event will not be generated.

    Rationale: If the Security log reaches 90 percent of its capacity and the computer has not been configured to overwrite events as needed, more recent events will not be written to the log. If the log reaches its capacity and the computer has been configured to shut down when it can no longer record events to the Security log, the computer will shut down and will no longer be available to provide network services.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
    it { should have_property 'WarningLevel' }
    its('WarningLevel') { should cmp <= 90 }
  end
end

control '18.5.4.1_L1_Ensure_Turn_off_multicast_name_resolution_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
  desc  "
    LLMNR is a secondary name resolution protocol. With LLMNR, queries are sent using multicast over a local network link on a single subnet from a client computer to another client computer on the same subnet that also has LLMNR enabled. LLMNR does not require a DNS server or DNS client configuration, and provides name resolution in scenarios in which conventional DNS name resolution is not possible.

    The recommended state for this setting is: Enabled .

    Rationale: An attacker can listen on a network for these LLMNR (UDP/5355) or NBT-NS (UDP/137) broadcasts and respond to them, tricking the host into thinking that it knows the location of the requested system.

    **Note:** To completely mitigate local name resolution poisoning, in addition to this setting, the properties of each installed NIC should also be set to Disable NetBIOS over TCP/IP (on the WINS tab in the NIC properties). Unfortunately, there is no global setting to achieve this that automatically applies to all NICs - it is a per-NIC setting that varies with different NIC hardware installations.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient') do
    it { should have_property 'EnableMulticast' }
    its('EnableMulticast') { should cmp == 0 }
  end
end

control '18.5.5.1_L2_Ensure_Enable_Font_Providers_is_set_to_Disabled' do
  title "(L2) Ensure 'Enable Font Providers' is set to 'Disabled'"
  desc  "
    This policy setting determines whether Windows is allowed to download fonts and font catalog data from an online font provider.

    The recommended state for this setting is: Disabled .

    Rationale: In an enterprise managed environment the IT department should be managing the changes to the system configuration, to ensure all changes are tested and approved.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableFontProviders' }
    its('EnableFontProviders') { should cmp == 0 }
  end
end

control '18.5.8.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled' do
  title "(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
  desc  "
    This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.

    The recommended state for this setting is: Disabled .

    Rationale: Insecure guest logons are used by file servers to allow unauthenticated access to shared folders.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation') do
    it { should have_property 'AllowInsecureGuestAuth' }
    its('AllowInsecureGuestAuth') { should cmp == 0 }
  end
end

control '18.5.9.1_L2_Ensure_Turn_on_Mapper_IO_LLTDIO_driver_is_set_to_Disabled' do
  title "(L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
  desc  "
    This policy setting changes the operational behavior of the Mapper I/O network protocol driver.

    LLTDIO allows a computer to discover the topology of a network it's connected to. It also allows a computer to initiate Quality-of-Service requests such as bandwidth estimation and network health analysis.

    The recommended state for this setting is: Disabled .

    Rationale: To help protect from potentially discovering and connecting to unauthorized devices, this setting should be disabled to prevent responding to network traffic for network topology discovery.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowLLTDIOOnDomain' }
    its('AllowLLTDIOOnDomain') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'ProhibitLLTDIOOnPrivateNet' }
    its('ProhibitLLTDIOOnPrivateNet') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'EnableLLTDIO' }
    its('EnableLLTDIO') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowLLTDIOOnPublicNet' }
    its('AllowLLTDIOOnPublicNet') { should cmp == 0 }
  end
end

control '18.5.9.2_L2_Ensure_Turn_on_Responder_RSPNDR_driver_is_set_to_Disabled' do
  title "(L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
  desc  "
    This policy setting changes the operational behavior of the Responder network protocol driver.

    The Responder allows a computer to participate in Link Layer Topology Discovery requests so that it can be discovered and located on the network. It also allows a computer to participate in Quality-of-Service activities such as bandwidth estimation and network health analysis.

    The recommended state for this setting is: Disabled .

    Rationale: To help protect from potentially discovering and connecting to unauthorized devices, this setting should be disabled to prevent responding to network traffic for network topology discovery.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowRspndrOnDomain' }
    its('AllowRspndrOnDomain') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'ProhibitRspndrOnPrivateNet' }
    its('ProhibitRspndrOnPrivateNet') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'EnableRspndr' }
    its('EnableRspndr') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD') do
    it { should have_property 'AllowRspndrOnPublicNet' }
    its('AllowRspndrOnPublicNet') { should cmp == 0 }
  end
end

control '18.5.10.2_L2_Ensure_Turn_off_Microsoft_Peer-to-Peer_Networking_Services_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
  desc  "
    The Peer Name Resolution Protocol (PNRP) allows for distributed resolution of a name to an IPv6 address and port number. The protocol operates in the context of **clouds** . A cloud is a set of peer computers that can communicate with each other by using the same IPv6 scope.

    Peer-to-Peer protocols allow for applications in the areas of RTC, collaboration, content distribution and distributed processing.

    The recommended state for this setting is: Enabled .

    Rationale: This setting enhances the security of the environment and reduces the overall risk exposure related to peer-to-peer networking.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Peernet') do
    it { should have_property 'Disabled' }
    its('Disabled') { should cmp == 1 }
  end
end

control '18.5.11.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled' do
  title "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc  "
    You can use this procedure to control a user's ability to install and configure a Network Bridge.

    The recommended state for this setting is: Enabled .

    Rationale: The Network Bridge setting, if enabled, allows users to create a Layer 2 Media Access Control (MAC) bridge, enabling them to connect two or more physical network segments together. A Network Bridge thus allows a computer that has connections to two different networks to share data between those networks.

    In an enterprise managed environment, where there is a need to control network traffic to only authorized paths, allowing users to create a Network Bridge increases the risk and attack surface from the bridged network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_AllowNetBridge_NLA' }
    its('NC_AllowNetBridge_NLA') { should cmp == 0 }
  end
end

control '18.5.11.3_L1_Ensure_Prohibit_use_of_Internet_Connection_Sharing_on_your_DNS_domain_network_is_set_to_Enabled' do
  title "(L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
  desc  "
    Although this \"legacy\" setting traditionally applied to the use of Internet Connection Sharing (ICS) in Windows 2000, Windows XP  Server 2003, this setting now freshly applies to the Mobile Hotspot feature in Windows 10  Server 2016.

    The recommended state for this setting is: Enabled .

    Rationale: Non-administrators should not be able to turn on the Mobile Hotspot feature and open their Internet connectivity up to nearby mobile devices.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_ShowSharedAccessUI' }
    its('NC_ShowSharedAccessUI') { should cmp == 0 }
  end
end

control '18.5.11.4_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled' do
  title "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc  "
    This policy setting determines whether to require domain users to elevate when setting a network's location.

    The recommended state for this setting is: Enabled .

    Rationale: Allowing regular users to set a network location increases the risk and attack surface.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_StdDomainUserSetLocation' }
    its('NC_StdDomainUserSetLocation') { should cmp == 1 }
  end
end

control '18.5.14.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares' do
  title "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc  "
    This policy setting configures secure access to UNC paths.

    The recommended state for this setting is: Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares .

    **Note:** If the environment exclusively contains Windows 8.0 / Server 2012 (non-R2) or newer systems, then the \" Privacy \" setting may (optionally) also be set to enable SMB encryption. However, using SMB encryption will render the targeted share paths completely inaccessible by older OSes, so only use this additional option with caution and thorough testing.

    Rationale: In February 2015, Microsoft released a new control mechanism to mitigate a security risk in Group Policy as part of the [MS15-011](https://technet.microsoft.com/library/security/MS15-011) / [MSKB 3000483](https://support.microsoft.com/en-us/kb/3000483) security update. This mechanism requires both the installation of the new security update and also the deployment of specific group policy settings to all computers on the domain from Windows Vista / Server 2008 (non-R2) or newer (the associated security patch to enable this feature was not released for Server 2003). A new group policy template ( NetworkProvider.admx/adml ) was also provided with the security update.

    Once the new GPO template is in place, the following are the minimum requirements to remediate the Group Policy security risk:

    \\\\*\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1

    \\\\*\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1

    **Note:** A reboot may be required after the setting is applied to a client machine to access the above paths.

    Additional guidance on the deployment of this security setting is available from the Microsoft Premier Field Engineering (PFE) Platforms TechNet Blog here: [Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx) .
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    it { should have_property '\\\\*\\NETLOGON' }
    its('\\\\*\\NETLOGON') { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    it { should have_property '\\\\*\\SYSVOL' }
    its('\\\\*\\SYSVOL') { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
end

control '18.5.19.2.1_L2_Disable_IPv6_Ensure_TCPIP6_Parameter_DisabledComponents_is_set_to_0xff_255' do
  title "(L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
  desc  "
    Internet Protocol version 6 (IPv6) is a set of protocols that computers use to exchange information over the Internet and over home and business networks. IPv6 allows for many more IP addresses to be assigned than IPv4 did. Older networking, hosts and operating systems may not support IPv6 natively.

    The recommended state for this setting is: DisabledComponents - 0xff (255)

    Rationale: Since the vast majority of private enterprise managed networks have no need to utilize IPv6 (because they have access to private IPv4 addressing), disabling IPv6 components removes a possible attack surface that is also harder to monitor the traffic on. As a result, we recommend configuring IPv6 to a Disabled state when it is not needed.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    it { should have_property 'DisabledComponents' }
    its('DisabledComponents') { should cmp == 255 }
  end
end

control '18.5.20.1_L2_Ensure_Configuration_of_wireless_settings_using_Windows_Connect_Now_is_set_to_Disabled' do
  title "(L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
  desc  "
    This policy setting allows the configuration of wireless settings using Windows Connect Now (WCN). The WCN Registrar enables the discovery and configuration of devices over Ethernet (UPnP) over in-band 802.11 Wi-Fi through the Windows Portable Device API (WPD) and via USB Flash drives. Additional options are available to allow discovery and configuration over a specific medium.

    The recommended state for this setting is: Disabled .

    Rationale: This setting enhances the security of the environment and reduces the overall risk exposure related to user configuration of wireless settings.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'EnableRegistrars' }
    its('EnableRegistrars') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableWPDRegistrar' }
    its('DisableWPDRegistrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableFlashConfigRegistrar' }
    its('DisableFlashConfigRegistrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableInBand802DOT11Registrar' }
    its('DisableInBand802DOT11Registrar') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    it { should have_property 'DisableUPnPRegistrar' }
    its('DisableUPnPRegistrar') { should cmp == 0 }
  end
end

control '18.5.20.2_L2_Ensure_Prohibit_access_of_the_Windows_Connect_Now_wizards_is_set_to_Enabled' do
  title "(L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
  desc  "
    This policy setting prohibits access to Windows Connect Now (WCN) wizards.

    The recommended state for this setting is: Enabled .

    Rationale: Allowing standard users to access the Windows Connect Now wizard increases the risk and attack surface.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\UI') do
    it { should have_property 'DisableWcnUi' }
    its('DisableWcnUi') { should cmp == 1 }
  end
end

control '18.5.21.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled_3__Prevent_Wi-Fi_when_on_Ethernet' do
  title "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'"
  desc  "
    This policy setting prevents computers from establishing multiple simultaneous connections to either the Internet or to a Windows domain.

    The recommended state for this setting is: Enabled: 3 = Prevent Wi-Fi when on Ethernet .

    Rationale: Preventing bridged network connections can help prevent a user unknowingly allowing traffic to route between internal and external networks, which risks exposure to sensitive internal data.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should have_property 'fMinimizeConnections' }
    its('fMinimizeConnections') { should cmp == 3 }
  end
end

control '18.5.21.2_L1_Ensure_Prohibit_connection_to_non-domain_networks_when_connected_to_domain_authenticated_network_is_set_to_Enabled' do
  title "(L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
  desc  "
    This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.

    The recommended state for this setting is: Enabled .

    Rationale: The potential concern is that a user would unknowingly allow network traffic to flow between the insecure public network and the enterprise managed network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    it { should have_property 'fBlockNonDomain' }
    its('fBlockNonDomain') { should cmp == 1 }
  end
end

control '18.5.23.2.1_L1_Ensure_Allow_Windows_to_automatically_connect_to_suggested_open_hotspots_to_networks_shared_by_contacts_and_to_hotspots_offering_paid_services_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users can enable the following WLAN settings: \"Connect to suggested open hotspots,\" \"Connect to networks shared by my contacts,\" and \"Enable paid services\".

    * \"Connect to suggested open hotspots\" enables Windows to automatically connect users to open hotspots it knows about by crowdsourcing networks that other people using Windows have connected to.
    * \"Connect to networks shared by my contacts\" enables Windows to automatically connect to networks that the user's contacts have shared with them, and enables users on this device to share networks with their contacts.
    * \"Enable paid services\" enables Windows to temporarily connect to open hotspots to determine if paid services are available.
    The recommended state for this setting is: Disabled .

    **Note:** These features are also known by the name \" **Wi-Fi Sense** \".

    Rationale: Automatically connecting to an open hotspot or network can introduce the system to a rogue network with malicious intent.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config') do
    it { should have_property 'AutoConnectAllowedOEM' }
    its('AutoConnectAllowedOEM') { should cmp == 0 }
  end
end

control '18.7.1.1_L2_Ensure_Turn_off_notifications_network_usage_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'"
  desc  "
    This policy setting blocks applications from using the network to send notifications to update tiles, tile badges, toast, or raw notifications. This policy setting turns off the connection between Windows and the Windows Push Notification Service (WNS). This policy setting also stops applications from being able to poll application services to update tiles.

    The recommended state for this setting is: Enabled .

    Rationale: Windows Push Notification Services (WNS) is a mechanism to receive 3rd-party notifications and updates from the cloud/Internet. In a high security environment, external systems, especially those hosted outside the organization, should be prevented from having an impact on the secure workstations.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications') do
    it { should have_property 'NoCloudApplicationNotification' }
    its('NoCloudApplicationNotification') { should cmp == 1 }
  end
end

control '18.8.3.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled' do
  title "(L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
  desc  "
    This policy setting determines what information is logged in security audit events when a new process has been created.

    The recommended state for this setting is: Disabled .

    **Note:** This feature that this setting controls is not normally supported in OSes older than Windows 8.1. However, in February 2015 Microsoft added support for the feature to  Windows 7 and Windows 8 via a special update - [KB3004375](https://support.microsoft.com/en-us/help/3004375/microsoft-security-advisory-update-to-improve-windows-command-line-aud) . Therefore, this setting is also important to set on those older OSes in the event that the update is installed on them.

    Rationale: When this policy setting is enabled, any user who has read access to the security events can read the command-line arguments for any successfully created process. Command-line arguments may contain sensitive or private information such as passwords or user data.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit') do
    it { should have_property 'ProcessCreationIncludeCmdLine_Enabled' }
    its('ProcessCreationIncludeCmdLine_Enabled') { should cmp == 0 }
  end
end

control '18.8.4.1_L1_Ensure_Encryption_Oracle_Remediation_is_set_to_Enabled_Force_Updated_Clients' do
  title "(L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"
  desc  "
    Some versions of the CredSSP protocol that is used by some applications (such as Remote Desktop Connection) are vulnerable to an encryption oracle attack against the client. This policy controls compatibility with vulnerable clients and servers and allows you to set the level of protection desired for the encryption oracle vulnerability.

    The recommended state for this setting is: Enabled: Force Updated Clients .

    Rationale: This setting is important to mitigate the CredSSP encryption oracle vulnerability, for which information was published by Microsoft on 03/13/2018 in [CVE-2018-0886 | CredSSP Remote Code Execution Vulnerability](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0886) . All versions of Windows from Windows Vista onwards are affected by this vulnerability, and will be compatible with this recommendation provided that they have been patched at least through May 2018 (or later).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters') do
    it { should have_property 'AllowEncryptionOracle' }
    its('AllowEncryptionOracle') { should cmp == 0 }
  end
end

control '18.8.4.2_L1_Ensure_Remote_host_allows_delegation_of_non-exportable_credentials_is_set_to_Enabled' do
  title "(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
  desc  "
    Remote host allows delegation of non-exportable credentials. When using credential delegation, devices provide an exportable version of credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host. The Restricted Admin Mode and Windows Defender Remote Credential Guard features are two options to help protect against this risk.

    The recommended state for this setting is: Enabled .

    **Note:** More detailed information on Windows Defender Remote Credential Guard and how it compares to Restricted Admin Mode can be found at this link: [Protect Remote Desktop credentials with Windows Defender Remote Credential Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/access-protection/remote-credential-guard)

    Rationale: **Restricted Admin Mode** was designed to help protect administrator accounts by ensuring that reusable credentials are not stored in memory on remote devices that could potentially be compromised. **Windows Defender Remote Credential Guard** helps you protect your credentials over a Remote Desktop connection by redirecting Kerberos requests back to the device that is requesting the connection.
    Both features should be enabled and supported, as they reduce the chance of credential theft.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation') do
    it { should have_property 'AllowProtectedCreds' }
    its('AllowProtectedCreds') { should cmp == 1 }
  end
end

control '18.8.14.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical' do
  title "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc  "
    This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:

    * Good : The driver has been signed and has not been tampered with.
    * Bad : The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
    * Bad, but required for boot : The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
    * Unknown : This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.
    If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.

    If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.

    The recommended state for this setting is: Enabled: Good, unknown and bad but critical .

    Rationale: This policy setting helps reduce the impact of malware that has already infected your system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch') do
    it { should have_property 'DriverLoadPolicy' }
    its('DriverLoadPolicy') { should cmp == 3 }
  end
end

control '18.8.21.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE' do
  title "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc  "
    The \"Do not apply during periodic background processing\" option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart.

    The recommended state for this setting is: Enabled: FALSE (unchecked).

    Rationale: Setting this option to false (unchecked) will ensure that domain policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoBackgroundPolicy' }
    its('NoBackgroundPolicy') { should cmp == 0 }
  end
end

control '18.8.21.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE' do
  title "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc  "
    The \"Process even if the Group Policy objects have not changed\" option updates and reapplies policies even if the policies have not changed.

    The recommended state for this setting is: Enabled: TRUE (checked).

    Rationale: Setting this option to true (checked) will ensure unauthorized changes that might have been configured locally are forced to match the domain-based Group Policy settings again.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should cmp == 0 }
  end
end

control '18.8.21.4_L1_Ensure_Continue_experiences_on_this_device_is_set_to_Disabled' do
  title "(L1) Ensure 'Continue experiences on this device' is set to 'Disabled'"
  desc  "
    This policy setting determines whether the Windows device is allowed to participate in cross-device experiences (continue experiences).

    The recommended state for this setting is: Disabled .

    Rationale: A cross-device experience is when a system can access app and send messages to other devices. In an enterprise managed environment only trusted systems should be communicating within the network. Access to any other system should be prohibited.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableCdp' }
    its('EnableCdp') { should cmp == 0 }
  end
end

control '18.8.21.5_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc  "
    This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users and Domain Controllers.

    The recommended state for this setting is: Disabled .

    Rationale: This setting ensures that group policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should_not have_property 'DisableBkGndGroupPolicy' }
  end
end

control '18.8.22.1.1_L2_Ensure_Turn_off_access_to_the_Store_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off access to the Store' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether to use the Store service for finding an application to open a file with an unhandled file type or protocol association. When a user opens a file type or protocol that is not associated with any applications on the computer, the user is given the choice to select a local application or use the Store service to find an application.

    The recommended state for this setting is: Enabled .

    Rationale: The Store service is a retail outlet built into Windows, primarily for consumer use. In an enterprise managed environment the IT department should be managing the installation of all applications to reduce the risk of the installation of vulnerable software.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoUseStoreOpenWith' }
    its('NoUseStoreOpenWith') { should cmp == 1 }
  end
end

control '18.8.22.1.2_L1_Ensure_Turn_off_downloading_of_print_drivers_over_HTTP_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
  desc  "
    This policy setting controls whether the computer can download print driver packages over HTTP. To set up HTTP printing, printer drivers that are not available in the standard operating system installation might need to be downloaded over HTTP.

    The recommended state for this setting is: Enabled .

    Rationale: Users might download drivers that include malicious code.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableWebPnPDownload' }
    its('DisableWebPnPDownload') { should cmp == 1 }
  end
end

control '18.8.22.1.3_L2_Ensure_Turn_off_handwriting_personalization_data_sharing_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
  desc  "
    This setting turns off data sharing from the handwriting recognition personalization tool.

    The handwriting recognition personalization tool enables Tablet PC users to adapt handwriting recognition to their own writing style by providing writing samples. The tool can optionally share user writing samples with Microsoft to improve handwriting recognition in future versions of Windows. The tool generates reports and transmits them to Microsoft over a secure connection.

    The recommended state for this setting is: Enabled .

    Rationale: A person's handwriting is Personally Identifiable Information (PII), especially when it comes to your signature. As such, it is unacceptable in many environments to automatically upload PII to a website without explicit approval by the user.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TabletPC') do
    it { should have_property 'PreventHandwritingDataSharing' }
    its('PreventHandwritingDataSharing') { should cmp == 1 }
  end
end

control '18.8.22.1.4_L2_Ensure_Turn_off_handwriting_recognition_error_reporting_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
  desc  "
    Turns off the handwriting recognition error reporting tool.

    The handwriting recognition error reporting tool enables users to report errors encountered in Tablet PC Input Panel. The tool generates error reports and transmits them to Microsoft over a secure connection. Microsoft uses these error reports to improve handwriting recognition in future versions of Windows.

    The recommended state for this setting is: Enabled .

    Rationale: A person's handwriting is Personally Identifiable Information (PII), especially when it comes to your signature. As such, it is unacceptable in many environments to automatically upload PII to a website without explicit approval by the user.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports') do
    it { should have_property 'PreventHandwritingErrorReports' }
    its('PreventHandwritingErrorReports') { should cmp == 1 }
  end
end

control '18.8.22.1.5_L2_Ensure_Turn_off_Internet_Connection_Wizard_if_URL_connection_is_referring_to_Microsoft.com_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether the Internet Connection Wizard can connect to Microsoft to download a list of Internet Service Providers (ISPs).

    The recommended state for this setting is: Enabled .

    Rationale: In an enterprise managed environment we want to lower the risk of a user unknowingly exposing sensitive data.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Internet Connection Wizard') do
    it { should have_property 'ExitOnMSICW' }
    its('ExitOnMSICW') { should cmp == 1 }
  end
end

control '18.8.22.1.6_L1_Ensure_Turn_off_Internet_download_for_Web_publishing_and_online_ordering_wizards_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
  desc  "
    This policy setting controls whether Windows will download a list of providers for the Web publishing and online ordering wizards.

    The recommended state for this setting is: Enabled .

    Rationale: Although the risk is minimal, enabling this setting will reduce the possibility of a user unknowingly downloading malicious content through this feature.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoWebServices' }
    its('NoWebServices') { should cmp == 1 }
  end
end

control '18.8.22.1.7_L2_Ensure_Turn_off_printing_over_HTTP_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
  desc  "
    This policy setting allows you to disable the client computer's ability to print over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.

    The recommended state for this setting is: Enabled .

    **Note:** This control affects printing over **both** HTTP and HTTPS.

    Rationale: Information that is transmitted over HTTP through this capability is not protected and can be intercepted by malicious users. For this reason, it is not often used in enterprise managed environments.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should cmp == 1 }
  end
end

control '18.8.22.1.8_L2_Ensure_Turn_off_Registration_if_URL_connection_is_referring_to_Microsoft.com_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether the Windows Registration Wizard connects to Microsoft.com for online registration.

    The recommended state for this setting is: Enabled .

    Rationale: Users in an enterprise managed environment should not be registering their own copies of Windows, providing their own PII in the process.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Registration Wizard Control') do
    it { should have_property 'NoRegistration' }
    its('NoRegistration') { should cmp == 1 }
  end
end

control '18.8.22.1.9_L2_Ensure_Turn_off_Search_Companion_content_file_updates_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether Search Companion should automatically download content updates during local and Internet searches.

    The recommended state for this setting is: Enabled .

    Rationale: There is a small risk that users will unknowingly reveal sensitive information because of the topics they are searching for. This risk is very low because even if this setting is enabled users still must submit search queries to the desired search engine in order to perform searches.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SearchCompanion') do
    it { should have_property 'DisableContentFileUpdates' }
    its('DisableContentFileUpdates') { should cmp == 1 }
  end
end

control '18.8.22.1.10_L2_Ensure_Turn_off_the_Order_Prints_picture_task_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off the \"Order Prints\" picture task' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether the \"Order Prints Online\" task is available from Picture Tasks in Windows folders.

    The Order Prints Online Wizard is used to download a list of providers and allow users to order prints online.

    The recommended state for this setting is: Enabled .

    Rationale: In an enterprise managed environment we want to lower the risk of a user unknowingly exposing sensitive data.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoOnlinePrintsWizard' }
    its('NoOnlinePrintsWizard') { should cmp == 1 }
  end
end

control '18.8.22.1.11_L2_Ensure_Turn_off_the_Publish_to_Web_task_for_files_and_folders_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off the \"Publish to Web\" task for files and folders' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether the tasks Publish this file to the Web, Publish this folder to the Web, and Publish the selected items to the Web are available from File and Folder Tasks in Windows folders. The Web Publishing wizard is used to download a list of providers and allow users to publish content to the Web.

    The recommended state for this setting is: Enabled .

    Rationale: Users may publish confidential or sensitive information to a public service outside of the control of the organization.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoPublishingWizard' }
    its('NoPublishingWizard') { should cmp == 1 }
  end
end

control '18.8.22.1.12_L2_Ensure_Turn_off_the_Windows_Messenger_Customer_Experience_Improvement_Program_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether the Windows Customer Experience Improvement Program can collect anonymous information about how Windows is used.

    Microsoft uses information collected through the Windows Customer Experience Improvement Program to improve features that are most used and to detect flaws so that they can be corrected more quickly. Enabling this setting will reduce the amount of data Microsoft is able to gather for this purpose. The recommended state for this setting is: Enabled .

    Rationale: Large enterprise managed environments may not want to have information collected by Microsoft from managed client computers.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Messenger\\Client') do
    it { should have_property 'CEIP' }
    its('CEIP') { should cmp == 2 }
  end
end

control '18.8.22.1.13_L2_Ensure_Turn_off_Windows_Customer_Experience_Improvement_Program_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether Windows Messenger can collect anonymous information about how the Windows Messenger software and service is used.

    Microsoft uses information collected through the Windows Customer Experience Improvement Program to detect software flaws so that they can be corrected more quickly, enabling this setting will reduce the amount of data Microsoft is able to gather for this purpose. The recommended state for this setting is: Enabled .

    Rationale: Large enterprise managed environments may not want to have information collected by Microsoft from managed client computers.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows') do
    it { should have_property 'CEIPEnable' }
    its('CEIPEnable') { should cmp == 0 }
  end
end

control '18.8.22.1.14_L2_Ensure_Turn_off_Windows_Error_Reporting_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
  desc  "
    This policy setting controls whether or not errors are reported to Microsoft.

    Error Reporting is used to report information about a system or application that has failed or has stopped responding and is used to improve the quality of the product.

    The recommended state for this setting is: Enabled .

    Rationale: If a Windows Error occurs in a secure, enterprise managed environment, the error should be reported directly to IT staff for troubleshooting and remediation. There is no benefit to the corporation to report these errors directly to Microsoft, and there is some risk of unknowingly exposing sensitive data as part of the error.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting') do
    it { should have_property 'Disabled' }
    its('Disabled') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting') do
    it { should have_property 'DoReport' }
    its('DoReport') { should cmp == 0 }
  end
end

control '18.8.25.1_L2_Ensure_Support_device_authentication_using_certificate_is_set_to_Enabled_Automatic' do
  title "(L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
  desc  "
    This policy setting allows you to set support for Kerberos to attempt authentication using the certificate for the device to the domain.

    Support for device authentication using certificate will require connectivity to a DC in the device account domain which supports certificate authentication for computer accounts.

    The recommended state for this setting is: Enabled: Automatic .

    Rationale: Having stronger device authentication with the use of certificates is strongly encouraged over standard username and password authentication. Having this set to Automatic will allow certificate based authentication to be used whenever possible.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should have_property 'DevicePKInitBehavior' }
    its('DevicePKInitBehavior') { should cmp == 0 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    it { should have_property 'DevicePKInitEnabled' }
    its('DevicePKInitEnabled') { should cmp == 1 }
  end
end

control '18.8.27.1_L2_Ensure_Disallow_copying_of_user_input_methods_to_the_system_account_for_sign-in_is_set_to_Enabled' do
  title "(L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
  desc  "
    This policy prevents automatic copying of user input methods to the system account for use on the sign-in screen. The user is restricted to the set of input methods that are enabled in the system account.

    The recommended state for this setting is: Enabled .

    Rationale: This is a way to increase the security of the system account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International') do
    it { should have_property 'BlockUserInputMethodsForSignIn' }
    its('BlockUserInputMethodsForSignIn') { should cmp == 1 }
  end
end

control '18.8.28.1_L1_Ensure_Block_user_from_showing_account_details_on_sign-in_is_set_to_Enabled' do
  title "(L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
  desc  "
    This policy prevents the user from showing account details (email address or user name) on the sign-in screen.

    The recommended state for this setting is: Enabled .

    Rationale: An attacker with access to the console (for example, someone with physical access or someone who is able to connect to the workstation through Remote Desktop Services) could view the name of the last user who logged on to the server. The attacker could then try to guess the password, use a dictionary, or use a brute-force attack to try and log on.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'BlockUserFromShowingAccountDetailsOnSignin' }
    its('BlockUserFromShowingAccountDetailsOnSignin') { should cmp == 1 }
  end
end

control '18.8.28.2_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control whether anyone can interact with available networks UI on the logon screen.

    The recommended state for this setting is: Enabled .

    Rationale: An unauthorized user could disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should cmp == 1 }
  end
end

control '18.8.28.3_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc  "
    This policy setting prevents connected users from being enumerated on domain-joined computers.

    The recommended state for this setting is: Enabled .

    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DontEnumerateConnectedUsers' }
    its('DontEnumerateConnectedUsers') { should cmp == 1 }
  end
end

control '18.8.28.4_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled' do
  title "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc  "
    This policy setting allows local users to be enumerated on domain-joined computers.

    The recommended state for this setting is: Disabled .

    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnumerateLocalUsers' }
    its('EnumerateLocalUsers') { should cmp == 0 }
  end
end

control '18.8.28.5_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting allows you to prevent app notifications from appearing on the lock screen.

    The recommended state for this setting is: Enabled .

    Rationale: App notifications might display sensitive business or personal data.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DisableLockScreenAppNotifications' }
    its('DisableLockScreenAppNotifications') { should cmp == 1 }
  end
end

control '18.8.28.6_L1_Ensure_Turn_off_picture_password_sign-in_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control whether a domain user can sign in using a picture password.

    The recommended state for this setting is: Enabled .

    **Note:** If the picture password feature is permitted, the user's domain password is cached in the system vault when using it.

    Rationale: Picture passwords bypass the requirement for a typed complex password. In a shared work environment, a simple shoulder surf where someone observed the on-screen gestures would allow that person to gain access to the system without the need to know the complex password. Vertical monitor screens with an image are much more visible at a distance than horizontal key strokes, increasing the likelihood of a successful observation of the mouse gestures.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'BlockDomainPicturePassword' }
    its('BlockDomainPicturePassword') { should cmp == 1 }
  end
end

control '18.8.28.7_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc  "
    This policy setting allows you to control whether a domain user can sign in using a convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security properties. To configure Passport for domain users, use the policies under Computer Configuration\\Administrative Templates\\Windows Components\\Microsoft Passport for Work.

    **Note:** The user's domain password will be cached in the system vault when using this feature.

    The recommended state for this setting is: Disabled .

    Rationale: A PIN is created from a much smaller selection of characters than a password, so in most cases a PIN will be much less robust than a password.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'AllowDomainPINLogon' }
    its('AllowDomainPINLogon') { should cmp == 0 }
  end
end

control '18.8.31.1_L2_Ensure_Allow_Clipboard_synchronization_across_devices_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
  desc  "
    This setting determines whether Clipboard contents can be synchronized across devices.

    The recommended state for this setting is: Disabled .

    Rationale: In high security environments, clipboard data should stay local to the system and not synced across devices, as it may contain very sensitive information that must be contained locally.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'AllowCrossDeviceClipboard' }
    its('AllowCrossDeviceClipboard') { should cmp == 0 }
  end
end

control '18.8.31.2_L2_Ensure_Allow_upload_of_User_Activities_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'"
  desc  "
    This policy setting determines whether published User Activities can be uploaded to the cloud.

    The recommended state for this setting is: Disabled .

    Rationale: Due to privacy concerns, data should never be sent to any 3rd party since this data could contain sensitive information.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'UploadUserActivities' }
    its('UploadUserActivities') { should cmp == 0 }
  end
end

control '18.8.34.6.1_L1_Ensure_Allow_network_connectivity_during_connected-standby_on_battery_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
  desc  "
    This policy setting allows you to control the network connectivity state in standby on modern standby-capable systems.

    The recommended state for this setting is: Disabled .

    Rationale: Disabling this setting ensures that the computer will not be accessible to attackers over a WLAN network while left unattended, on battery and in a sleep state.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should cmp == 0 }
  end
end

control '18.8.34.6.2_L1_Ensure_Allow_network_connectivity_during_connected-standby_plugged_in_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
  desc  "
    This policy setting allows you to control the network connectivity state in standby on modern standby-capable systems.

    The recommended state for this setting is: Disabled .

    Rationale: Disabling this setting ensures that the computer will not be accessible to attackers over a WLAN network while left unattended, plugged in and in a sleep state.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should cmp == 0 }
  end
end

control '18.8.34.6.3_BL_Ensure_Allow_standby_states_S1-S3_when_sleeping_on_battery_is_set_to_Disabled' do
  title "(BL) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled'"
  desc  "
    This policy setting manages whether or not Windows is allowed to use standby states when putting the computer in a sleep state.

    The recommended state for this setting is: Disabled .

    Rationale: System sleep states (S1-S3) keep power to the RAM which may contain secrets, such as the BitLocker volume encryption key. An attacker finding a computer in sleep states (S1-S3) could directly attack the memory of the computer and gain access to the secrets through techniques such as RAM reminisce and direct memory access (DMA).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\bfc2519-3608-4c2a-94ea-171b0ed546ab') do
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.8.34.6.4_BL_Ensure_Allow_standby_states_S1-S3_when_sleeping_on_battery_is_set_to_Disabled' do
  title "(BL) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled'"
  desc  "
    This policy setting manages whether or not Windows is allowed to use standby states when putting the computer in a sleep state.

    The recommended state for this setting is: Disabled .

    Rationale: System sleep states (S1-S3) keep power to the RAM which may contain secrets, such as the BitLocker volume encryption key. An attacker finding a computer in sleep states (S1-S3) could directly attack the memory of the computer and gain access to the secrets through techniques such as RAM reminisce and direct memory access (DMA).
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab') do
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.8.34.6.5_L1_Ensure_Require_a_password_when_a_computer_wakes_on_battery_is_set_to_Enabled' do
  title "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
  desc  "
    Specifies whether or not the user is prompted for a password when the system resumes from sleep.

    The recommended state for this setting is: Enabled .

    Rationale: Enabling this setting ensures that anyone who wakes an unattended computer from sleep state will have to provide logon credentials before they can access the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should have_property 'DCSettingIndex' }
    its('DCSettingIndex') { should cmp == 1 }
  end
end

control '18.8.34.6.6_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled' do
  title "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
  desc  "
    Specifies whether or not the user is prompted for a password when the system resumes from sleep.

    The recommended state for this setting is: Enabled .

    Rationale: Enabling this setting ensures that anyone who wakes an unattended computer from sleep state will have to provide logon credentials before they can access the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    it { should have_property 'ACSettingIndex' }
    its('ACSettingIndex') { should cmp == 1 }
  end
end

control '18.8.36.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled' do
  title "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.

    Help desk and support personnel will not be able to proactively offer assistance, although they can still respond to user assistance requests.

    The recommended state for this setting is: Disabled .

    Rationale: A user might be tricked and accept an unsolicited Remote Assistance offer from a malicious user.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fAllowUnsolicited' }
    its('fAllowUnsolicited') { should cmp == 0 }
  end
end

control '18.8.36.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled' do
  title "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.

    The recommended state for this setting is: Disabled .

    Rationale: There is slight risk that a rogue administrator will gain access to another user's desktop session, however, they cannot connect to a user's computer unannounced or control it without permission from the user. When an expert tries to connect, the user can still choose to deny the connection or give the expert view-only privileges. The user must explicitly click the Yes button to allow the expert to remotely control the workstation.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fAllowToGetHelp' }
    its('fAllowToGetHelp') { should cmp == 0 }
  end
end

control '18.8.37.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled' do
  title "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
  desc  "
    This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call they are making contains authentication information. The Endpoint Mapper Service on computers running Windows NT4 (all service packs) cannot process authentication information supplied in this manner. This policy setting can cause a specific issue with **1-way** forest trusts if it is applied to the **trusting** domain DCs (see Microsoft [KB3073942](https://support.microsoft.com/en-us/kb/3073942) ), so we do not recommend applying it to Domain Controllers.

    **Note:** This policy will not in effect until the system is rebooted.

    The recommended state for this setting is: Enabled .

    Rationale: Anonymous access to RPC services could result in accidental disclosure of information to unauthenticated users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should have_property 'EnableAuthEpResolution' }
    its('EnableAuthEpResolution') { should cmp == 1 }
  end
end

control '18.8.37.2_L1_Ensure_Restrict_Unauthenticated_RPC_clients_is_set_to_Enabled_Authenticated' do
  title "(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
  desc  "
    This policy setting controls how the RPC server runtime handles unauthenticated RPC clients connecting to RPC servers.

    This policy setting impacts all RPC applications. In a domain environment this policy setting should be used with caution as it can impact a wide range of functionality including group policy processing itself. Reverting a change to this policy setting can require manual intervention on each affected machine. **This policy setting should never be applied to a Domain Controller.**

    A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically requested to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy setting.

    -- \" **None** \" allows all RPC clients to connect to RPC Servers running on the machine on which the policy setting is applied.

    -- \" **Authenticated** \" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. Exemptions are granted to interfaces that have requested them.

    -- \" **Authenticated without exceptions** \" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. No exceptions are allowed. **This value has the potential to cause serious problems and is not recommended.**

    **Note:** This policy setting will not be applied until the system is rebooted.

    The recommended state for this setting is: Enabled: Authenticated .

    Rationale: Unauthenticated RPC communication can create a security vulnerability.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should cmp == 1 }
  end
end

control '18.8.47.5.1_L2_Ensure_Microsoft_Support_Diagnostic_Tool_Turn_on_MSDT_interactive_communication_with_support_provider_is_set_to_Disabled' do
  title "(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
  desc  "
    This policy setting configures Microsoft Support Diagnostic Tool (MSDT) interactive communication with the support provider. MSDT gathers diagnostic data for analysis by support professionals.

    The recommended state for this setting is: Disabled .

    Rationale: Due to privacy concerns, data should never be sent to any 3rd party since this data could contain sensitive information.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy') do
    it { should have_property 'DisableQueryRemoteServer' }
    its('DisableQueryRemoteServer') { should cmp == 0 }
  end
end

control '18.8.47.11.1_L2_Ensure_EnableDisable_PerfTrack_is_set_to_Disabled' do
  title "(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether to enable or disable tracking of responsiveness events.

    The recommended state for this setting is: Disabled .

    Rationale: When enabled the aggregated data of a given event will be transmitted to Microsoft. The option exists to restrict this feature for a specific user, set the consent level, and designate specific programs for which error reports could be sent. However, centrally restricting the ability to execute PerfTrack to limit the potential for unauthorized or undesired usage, data leakage, or unintentional communications is highly recommended.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}') do
    it { should have_property 'ScenarioExecutionEnabled' }
    its('ScenarioExecutionEnabled') { should cmp == 0 }
  end
end

control '18.8.49.1_L2_Ensure_Turn_off_the_advertising_ID_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'"
  desc  "
    This policy setting turns off the advertising ID, preventing apps from using the ID for experiences across apps.

    The recommended state for this setting is: Enabled .

    Rationale: Tracking user activity for advertising purposes, even anonymously, may be a privacy concern. In an enterprise managed environment, applications should not need or require tracking for targeted advertising.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo') do
    it { should have_property 'DisabledByGroupPolicy' }
    its('DisabledByGroupPolicy') { should cmp == 1 }
  end
end

control '18.8.52.1.1_L2_Ensure_Enable_Windows_NTP_Client_is_set_to_Enabled' do
  title "(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether the Windows NTP Client is enabled. Enabling the Windows NTP Client allows your computer to synchronize its computer clock with other NTP servers. You might want to disable this service if you decide to use a third-party time provider.

    The recommended state for this setting is: Enabled .

    Rationale: A reliable and accurate account of time is important for a number of services and security requirements, including but not limited to distributed applications, authentication services, multi-user databases and logging services. The use of an NTP client (with secure operation) establishes functional accuracy and is a focal point when reviewing security relevant events.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp == 1 }
  end
end

control '18.8.52.1.2_L2_Ensure_Enable_Windows_NTP_Server_is_set_to_Disabled' do
  title "(L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
  desc  "
    This policy setting allows you to specify whether the Windows NTP Server is enabled.

    The recommended state for this setting is: Disabled .

    Rationale: The configuration of proper time synchronization is critically important in an enterprise managed environment both due to the sensitivity of Kerberos authentication timestamps and also to ensure accurate security logging.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpServer') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp == 0 }
  end
end

control '18.9.4.1_L2_Ensure_Allow_a_Windows_app_to_share_application_data_between_users_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
  desc  "
    Manages a Windows app's ability to share data between users who have installed the app. Data is shared through the SharedLocal folder. This folder is available through the Windows.Storage API.

    The recommended state for this setting is: Disabled .

    Rationale: Users of a system could accidentally share sensitive data with other users on the same system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateManager') do
    it { should have_property 'AllowSharedLocalAppData' }
    its('AllowSharedLocalAppData') { should cmp == 0 }
  end
end

control '18.9.4.2_L1_Ensure_Prevent_non-admin_users_from_installing_packaged_Windows_apps_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled'"
  desc  "
    This setting manages non-Administrator users' ability to install Windows app packages.

    The recommended state for this setting is: Enabled .

    Rationale: In a corporate managed environment, application installations should be managed centrally by IT staff, not by end users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Appx') do
    it { should have_property 'BlockNonAdminUserInstall' }
    its('BlockNonAdminUserInstall') { should cmp == 1 }
  end
end

control '18.9.5.1_L1_Ensure_Let_Windows_apps_activate_with_voice_while_the_system_is_locked_is_set_to_Enabled_Force_Deny' do
  title "(L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny'"
  desc  "
    This policy setting specifies whether Windows apps can be activated by voice (apps and Cortana) while the system is locked.

    The recommended state for this setting is: Enabled: Force Deny .

    Rationale: Access to any computer resource should not be allowed when the device is locked.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy') do
    it { should have_property 'LetAppsActivateWithVoiceAboveLock' }
    its('LetAppsActivateWithVoiceAboveLock') { should cmp == 2 }
  end
end

control '18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled' do
  title "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc  "
    This policy setting lets you control whether Microsoft accounts are optional for Windows Store apps that require an account to sign in. This policy only affects Windows Store apps that support it.

    The recommended state for this setting is: Enabled .

    Rationale: Enabling this setting allows an organization to use their enterprise user accounts instead of using their Microsoft accounts when accessing Windows store apps. This provides the organization with greater control over relevant credentials. Microsoft accounts cannot be centrally managed and as such enterprise credential security policies cannot be applied to them, which could put any information accessed by using Microsoft accounts at risk.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'MSAOptional' }
    its('MSAOptional') { should cmp == 1 }
  end
end

control '18.9.6.2_L2_Ensure_Block_launching_Universal_Windows_apps_with_Windows_Runtime_API_access_from_hosted_content._is_set_to_Enabled' do
  title "(L2) Ensure 'Block launching Universal Windows apps with Windows Runtime API access from hosted content.' is set to 'Enabled'"
  desc  "
    This policy setting controls whether Microsoft Store apps with Windows Runtime API access directly from web content can be launched.

    The recommended state for this setting is: Enabled .

    Rationale: Blocking apps from the web with direct access to the Windows API can prevent malicious apps from being run on a system. Only system administrators should be installing approved applications.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'BlockHostedAppAccessWinRT' }
    its('BlockHostedAppAccessWinRT') { should cmp == 1 }
  end
end

control '18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled' do
  title "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc  "
    This policy setting disallows AutoPlay for MTP devices like cameras or phones.

    The recommended state for this setting is: Enabled .

    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should cmp == 1 }
  end
end

control '18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands' do
  title "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc  "
    This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.

    The recommended state for this setting is: Enabled: Do not execute any autorun commands .

    Rationale: Prior to Windows Vista, when media containing an autorun command is inserted, the system will automatically execute the program without user intervention. This creates a major security concern as code may be executed without user's knowledge. The default behavior starting with Windows Vista is to prompt the user whether autorun command is to be run. The autorun command is represented as a handler in the Autoplay dialog.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should cmp == 1 }
  end
end

control '18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives' do
  title "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc  "
    Autoplay starts to read from a drive as soon as you insert media in the drive, which causes the setup file for programs or audio media to start immediately. An attacker could use this feature to launch a program to damage the computer or data on the computer. Autoplay is disabled by default on some removable drive types, such as floppy disk and network drives, but not on CD-ROM drives.

    **Note:** You cannot use this policy setting to enable Autoplay on computer drives in which it is disabled by default, such as floppy disk and network drives.

    The recommended state for this setting is: Enabled: All drives .

    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoDriveTypeAutoRun' }
    its('NoDriveTypeAutoRun') { should cmp == 255 }
  end
end

control '18.9.10.1.1_L1_Ensure_Configure_enhanced_anti-spoofing_is_set_to_Enabled' do
  title "(L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
  desc  "
    This policy setting determines whether enhanced anti-spoofing is configured for devices which support it.

    The recommended state for this setting is: Enabled .

    Rationale: Enterprise managed environments are now supporting a wider range of mobile devices, increasing the security on these devices will help protect against unauthorized access on your network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures') do
    it { should have_property 'EnhancedAntiSpoofing' }
    its('EnhancedAntiSpoofing') { should cmp == 1 }
  end
end

control '18.9.11.1.1_BL_Ensure_Allow_access_to_BitLocker-protected_fixed_data_drives_from_earlier_versions_of_Windows_is_set_to_Disabled' do
  title "(BL) Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled'"
  desc  "
    This policy setting configures whether or not fixed data drives formatted with the FAT file system can be unlocked and viewed on computers running Windows Server 2008 (non-R2), Windows Vista, Windows XP with Service Pack 3 (SP3), or Windows XP with Service Pack 2 (SP2) operating systems.

    **Note:** This policy setting does not apply to drives that are formatted with the NTFS file system.

    The recommended state for this setting is: Disabled .

    Rationale: By default BitLocker virtualizes FAT formatted drives to permit access via the BitLocker To Go Reader on previous versions of Windows. Additionally the BitLocker To Go Reader application is applied to the unencrypted portion of the drive.

    The BitLocker To Go Reader application, like any other application, is subject to spoofing and could be a mechanism to propagate malware.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVDiscoveryVolumeType' }
    its('FDVDiscoveryVolumeType') { should eq '<none>' }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.2_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_is_set_to_Enabled' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    The \"Allow data recovery agent\" check box is used to specify whether a Data Recovery Agent can be used with BitLocker-protected fixed data drives. Before a Data Recovery Agent can be used it must be added from the Public Key Policies item in either the Group Policy Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption Deployment Guide on Microsoft TechNet for more information about adding Data Recovery Agents.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    Select \"Omit recovery options from the BitLocker setup wizard\" to prevent users from specifying recovery options when they enable BitLocker on a drive. This means that you will not be able to specify which recovery option to use when you enable BitLocker, instead BitLocker recovery options for the drive are determined by the policy setting.

    In \"Save BitLocker recovery information to Active Directory Domain Services\" choose which BitLocker recovery information to store in AD DS for fixed data drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. Storing the key package supports recovering data from a drive that has been physically corrupted. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    Select the \"Do not enable BitLocker until recovery information is stored in AD DS for fixed data drives\" check box if you want to prevent users from enabling BitLocker unless the computer is connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

    **Note:** If the \"Do not enable BitLocker until recovery information is stored in AD DS for fixed data drives\" check box is selected, a recovery password is automatically generated.

    The recommended state for this setting is: Enabled .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVRecovery' }
    its('FDVRecovery') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.3_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Allow_data_recovery_agent_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    The \"Allow data recovery agent\" check box is used to specify whether a Data Recovery Agent can be used with BitLocker-protected fixed data drives. Before a Data Recovery Agent can be used it must be added from the Public Key Policies item in either the Group Policy Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption Deployment Guide on Microsoft TechNet for more information about adding Data Recovery Agents.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVManageDRA' }
    its('FDVManageDRA') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.4_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Recovery_Password_is_set_to_Enabled_Allow_48-digit_recovery_password' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    The recommended state for this setting is: Enabled: Allow 48-digit recovery password .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVRecoveryPassword' }
    its('FDVRecoveryPassword') { should cmp == 2 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.5_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Recovery_Key_is_set_to_Enabled_Allow_256-bit_recovery_key' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    The recommended state for this setting is: Enabled: Allow 256-bit recovery key .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVRecoveryKey' }
    its('FDVRecoveryKey') { should cmp == 2 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.6_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Omit_recovery_options_from_the_BitLocker_setup_wizard_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    Select \"Omit recovery options from the BitLocker setup wizard\" to prevent users from specifying recovery options when they enable BitLocker on a drive. This means that you will not be able to specify which recovery option to use when you enable BitLocker, instead BitLocker recovery options for the drive are determined by the policy setting.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVHideRecoveryPage' }
    its('FDVHideRecoveryPage') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.7_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Save_BitLocker_recovery_information_to_AD_DS_for_fixed_data_drives_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Save BitLocker recovery information to Active Directory Domain Services\" choose which BitLocker recovery information to store in AD DS for fixed data drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. Storing the key package supports recovering data from a drive that has been physically corrupted. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVActiveDirectoryBackup' }
    its('FDVActiveDirectoryBackup') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.8_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Configure_storage_of_BitLocker_recovery_information_to_AD_DS_is_set_to_Enabled_Backup_recovery_passwords_and_key_packages' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Save BitLocker recovery information to Active Directory Domain Services\" choose which BitLocker recovery information to store in AD DS for fixed data drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. Storing the key package supports recovering data from a drive that has been physically corrupted. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    The recommended state for this setting is: Enabled: Backup recovery passwords and key packages .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVActiveDirectoryInfoToStore' }
    its('FDVActiveDirectoryInfoToStore') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.9_BL_Ensure_Choose_how_BitLocker-protected_fixed_drives_can_be_recovered_Do_not_enable_BitLocker_until_recovery_information_is_stored_to_AD_DS_for_fixed_data_drives_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'"
  desc  "
    This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    Select the \"Do not enable BitLocker until recovery information is stored in AD DS for fixed data drives\" check box if you want to prevent users from enabling BitLocker unless the computer is connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

    **Note:** If the \"Do not enable BitLocker until recovery information is stored in AD DS for fixed data drives\" check box is selected, a recovery password is automatically generated.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker, a Data Recovery Agent will need to be configured for fixed drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVRequireActiveDirectoryBackup' }
    its('FDVRequireActiveDirectoryBackup') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.10_BL_Ensure_Configure_use_of_hardware-based_encryption_for_fixed_data_drives_is_set_to_Disabled' do
  title "(BL) Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage BitLocker's use of hardware-based encryption on fixed data drives and specify which encryption algorithms it can use with hardware-based encryption. Using hardware-based encryption can improve performance of drive operations that involve frequent reading or writing of data to the drive.

    You can specify additional options that control whether BitLocker software-based encryption is used instead of hardware-based encryption on computers that do not support hardware-based encryption and whether you want to restrict the encryption algorithms and cipher suites used with hardware-based encryption.

    **Note:** The \"Choose drive encryption method and cipher strength\" policy setting does not apply to hardware-based encryption. The encryption algorithm used by hardware-based encryption is set when the drive is partitioned. By default, BitLocker uses the algorithm configured on the drive to encrypt the drive. The \"Restrict encryption algorithms and cipher suites allowed for hardware-based encryption\" option enables you to restrict the encryption algorithms that BitLocker can use with hardware encryption. If the algorithm set for the drive is not available, BitLocker will disable the use of hardware-based encryption.

    Encryption algorithms are specified by object identifiers (OID). For example:

    * AES 128 in CBC mode OID: 2.16.840.1.101.3.4.1.2
    * AES 256 in CBC mode OID: 2.16.840.1.101.3.4.1.42
    The recommended state for this setting is: Disabled .

    Rationale: From a strict security perspective the hardware-based encryption may offer the same, greater, or less protection than what is provided by BitLocker's software-based encryption depending on how the algorithms and key lengths compare.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVHardwareEncryption' }
    its('FDVHardwareEncryption') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.11_BL_Ensure_Configure_use_of_passwords_for_fixed_data_drives_is_set_to_Disabled' do
  title "(BL) Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether a password is required to unlock BitLocker-protected fixed data drives.

    **Note:** This setting is enforced when turning on BitLocker, not when unlocking a volume. BitLocker will allow unlocking a drive with any of the protectors available on the drive.

    The recommended state for this setting is: Disabled .

    Rationale: Using a dictionary-style attack, passwords can be guessed or discovered by repeatedly attempting to unlock a drive. Since this type of BitLocker password does include anti-dictionary attack protections provided by a TPM, for example, there is no mechanism to slow down rapid brute-force attacks against them.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVPassphrase' }
    its('FDVPassphrase') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.12_BL_Ensure_Configure_use_of_smart_cards_on_fixed_data_drives_is_set_to_Enabled' do
  title "(BL) Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled'"
  desc  "
    This policy setting allows you to specify whether smart cards can be used to authenticate user access to the BitLocker-protected fixed data drives on a computer.

    Smart cards can be used to authenticate user access to the drive. You can require smart card authentication by selecting the \"Require use of smart cards on fixed data drives\" check box.

    **Note:** This setting is enforced when turning on BitLocker, not when unlocking a drive. BitLocker will allow unlocking a drive with any of the protectors available on the drive.

    The recommended state for this setting is: Enabled .

    Rationale: A drive can be compromised by guessing or finding the authentication information used to access the drive. For example, a password could be guessed, or a drive set to automatically unlock could be lost or stolen with the computer it automatically unlocks with.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVAllowUserCert' }
    its('FDVAllowUserCert') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.1.13_BL_Ensure_Configure_use_of_smart_cards_on_fixed_data_drives_Require_use_of_smart_cards_on_fixed_data_drives_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to specify whether smart cards **must** be used to authenticate user access to the BitLocker-protected fixed data drives on a computer.

    Smart cards can be used to authenticate user access to the drive. You can require a smart card authentication by selecting the \"Require use of smart cards on fixed data drives\" check box.

    **Note:** This setting is enforced when turning on BitLocker, not when unlocking a drive. BitLocker will allow unlocking a drive with any of the protectors available on the drive.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: A drive can be compromised by guessing or finding the authentication information used to access the drive. For example, a password could be guessed, or a drive set to automatically unlock could be lost or stolen with the computer it automatically unlocks with.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'FDVEnforceUserCert' }
    its('FDVEnforceUserCert') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.1_BL_Ensure_Allow_enhanced_PINs_for_startup_is_set_to_Enabled' do
  title "(BL) Ensure 'Allow enhanced PINs for startup' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure whether or not enhanced startup PINs are used with BitLocker.

    Enhanced startup PINs permit the use of characters including uppercase and lowercase letters, symbols, numbers, and spaces. This policy setting is applied when you turn on BitLocker.

    The recommended state for this setting is: Enabled .

    Rationale: A numeric-only PIN provides less entropy than a PIN that is alpha-numeric. When not using enhanced PIN for startup, BitLocker requires the use of the function keys [F1-F10] for PIN entry since the PIN is entered in the pre-OS environment before localization support is available. This limits each PIN digit to one of ten possibilities. The TPM has an anti-hammering feature that includes a mechanism to exponentially increase the delay for PIN retry attempts; however, an attacker is able to more effectively mount a brute force attack using a domain of 10 digits of the function keys.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'UseEnhancedPin' }
    its('UseEnhancedPin') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.2_BL_Ensure_Allow_Secure_Boot_for_integrity_validation_is_set_to_Enabled' do
  title "(BL) Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure whether Secure Boot will be allowed as the platform integrity provider for BitLocker operating system drives.

    Secure Boot ensures that the PC's pre-boot environment only loads firmware that is digitally signed by authorized software publishers. Secure Boot also provides more flexibility for managing pre-boot configuration than legacy BitLocker integrity checks.

    Secure Boot requires a system that meets the UEFI 2.3.1 Specifications for Class 2 and Class 3 computers.

    When this policy is enabled and the hardware is capable of using Secure Boot for BitLocker scenarios, the \"Use enhanced Boot Configuration Data validation profile\" group policy setting is ignored and Secure Boot verifies BCD settings according to the Secure Boot policy setting, which is configured separately from BitLocker.

    **Note:** If the group policy setting \"Configure TPM platform validation profile for native UEFI firmware configurations\" is enabled and has PCR 7 omitted, BitLocker will be prevented from using Secure Boot for platform or Boot Configuration Data (BCD) integrity validation.

    The recommended state for this setting is: Enabled .

    Rationale: Secure Boot ensures that only firmware digitally signed by authorized software publishers is loaded during computer startup, which reduces the risk of rootkits and other types of malware from gaining control of the system. It also helps provide protection against malicious users booting from an alternate operating system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSAllowSecureBootForIntegrity' }
    its('OSAllowSecureBootForIntegrity') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.3_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_is_set_to_Enabled' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    The \"Allow certificate-based data recovery agent\" check box is used to specify whether a Data Recovery Agent can be used with BitLocker-protected operating system drives. Before a Data Recovery Agent can be used it must be added from the Public Key Policies item in either the Group Policy Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption Deployment Guide on Microsoft TechNet for more information about adding Data Recovery Agents.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    Select \"Omit recovery options from the BitLocker setup wizard\" to prevent users from specifying recovery options when they enable BitLocker on a drive. This means that you will not be able to specify which recovery option to use when you enable BitLocker, instead BitLocker recovery options for the drive are determined by the policy setting.

    In \"Save BitLocker recovery information to Active Directory Domain Services\", choose which BitLocker recovery information to store in AD DS for operating system drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. Storing the key package supports recovering data from a drive that has been physically corrupted. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    Select the \"Do not enable BitLocker until recovery information is stored in AD DS for operating system drives\" check box if you want to prevent users from enabling BitLocker unless the computer is connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

    **Note:** If the \"Do not enable BitLocker until recovery information is stored in AD DS for operating system drives\" check box is selected, a recovery password is automatically generated.

    The recommended state for this setting is: Enabled .

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSRecovery' }
    its('OSRecovery') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.4_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Allow_data_recovery_agent_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    The \"Allow certificate-based data recovery agent\" check box is used to specify whether a Data Recovery Agent can be used with BitLocker-protected operating system drives. Before a Data Recovery Agent can be used it must be added from the Public Key Policies item in either the Group Policy Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption Deployment Guide on Microsoft TechNet for more information about adding Data Recovery Agents.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSManageDRA' }
    its('OSManageDRA') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.5_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Recovery_Password_is_set_to_Enabled_Require_48-digit_recovery_password' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    The recommended state for this setting is: Enabled: Require 48-digit recovery password .

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSRecoveryPassword' }
    its('OSRecoveryPassword') { should cmp == 2 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.6_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Recovery_Key_is_set_to_Enabled_Do_not_allow_256-bit_recovery_key' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    The recommended state for this setting is: Enabled: Do not allow 256-bit recovery key .

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSRecoveryKey' }
    its('OSRecoveryKey') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.7_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Omit_recovery_options_from_the_BitLocker_setup_wizard_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    Select \"Omit recovery options from the BitLocker setup wizard\" to prevent users from specifying recovery options when they enable BitLocker on a drive. This means that you will not be able to specify which recovery option to use when you enable BitLocker, instead BitLocker recovery options for the drive are determined by the policy setting.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSHideRecoveryPage' }
    its('OSHideRecoveryPage') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.8_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Save_BitLocker_recovery_information_to_AD_DS_for_operating_system_drives_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    In \"Save BitLocker recovery information to Active Directory Domain Services\", choose which BitLocker recovery information to store in AD DS for operating system drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. Storing the key package supports recovering data from a drive that has been physically corrupted. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSActiveDirectoryBackup' }
    its('OSActiveDirectoryBackup') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.9_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Configure_storage_of_BitLocker_recovery_information_to_AD_DS_is_set_to_Enabled_Store_recovery_passwords_and_key_packages' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    In \"Save BitLocker recovery information to Active Directory Domain Services\", choose which BitLocker recovery information to store in AD DS for operating system drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. Storing the key package supports recovering data from a drive that has been physically corrupted. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    The recommended state for this setting is: Enabled: Store recovery passwords and key packages .

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSActiveDirectoryInfoToStore' }
    its('OSActiveDirectoryInfoToStore') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.10_BL_Ensure_Choose_how_BitLocker-protected_operating_system_drives_can_be_recovered_Do_not_enable_BitLocker_until_recovery_information_is_stored_to_AD_DS_for_operating_system_drives_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected operating system drives are recovered in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker.

    Select the \"Do not enable BitLocker until recovery information is stored in AD DS for operating system drives\" check box if you want to prevent users from enabling BitLocker unless the computer is connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

    **Note:** If the \"Do not enable BitLocker until recovery information is stored in AD DS for operating system drives\" check box is selected, a recovery password is automatically generated.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Should a user lose their primary means for accessing an encrypted OS volume, or should the system not pass its boot time integrity checks, the system will go into recovery mode. If the recovery key has not been backed up to Active Directory, the user would need to have saved the recovery key to another location such as a USB flash drive, or have printed the recovery password, and now have access to one of those in order to recovery the system. If the user is unable to produce the recovery key, then the user will be denied access to the encrypted volume and subsequently any data that is stored there.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSRequireActiveDirectoryBackup' }
    its('OSRequireActiveDirectoryBackup') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.11_BL_Ensure_Configure_use_of_hardware-based_encryption_for_operating_system_drives_is_set_to_Disabled' do
  title "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage BitLocker's use of hardware-based encryption on operating system drives and specify which encryption algorithms it can use with hardware-based encryption. Using hardware-based encryption can improve performance of drive operations that involve frequent reading or writing of data to the drive.

    You can specify additional options that control whether BitLocker software-based encryption is used instead of hardware-based encryption on computers that do not support hardware-based encryption and whether you want to restrict the encryption algorithms and cipher suites used with hardware-based encryption.

    **Note:** The \"Choose drive encryption method and cipher strength\" policy setting does not apply to hardware-based encryption. The encryption algorithm used by hardware-based encryption is set when the drive is partitioned. By default, BitLocker uses the algorithm configured on the drive to encrypt the drive. The \"Restrict encryption algorithms and cipher suites allowed for hardware-based encryption\" option enables you to restrict the encryption algorithms that BitLocker can use with hardware encryption. If the algorithm set for the drive is not available, BitLocker will disable the use of hardware-based encryption.

    Encryption algorithms are specified by object identifiers (OID). For example:

    * AES 128 in CBC mode OID: 2.16.840.1.101.3.4.1.2
    * AES 256 in CBC mode OID: 2.16.840.1.101.3.4.1.42
    The recommended state for this setting is: Disabled .

    Rationale: From a strict security perspective the hardware-based encryption may offer the same, greater, or less protection than what is provided by BitLocker's software-based encryption depending on how the algorithms and key lengths compare.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSHardwareEncryption' }
    its('OSHardwareEncryption') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.12_BL_Ensure_Configure_use_of_hardware-based_encryption_for_operating_system_drives_Use_BitLocker_software-based_encryption_when_hardware_encryption_is_not_available_is_set_to_Disable_False' do
  title "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives: Use BitLocker software-based encryption when hardware encryption is not available' is set to 'Disable: False'"
  desc  "
    This policy setting allows you to manage BitLocker's use of hardware-based encryption on operating system drives and specify which encryption algorithms it can use with hardware-based encryption. Using hardware-based encryption can improve performance of drive operations that involve frequent reading or writing of data to the drive.

    If hardware-based encryption is not available BitLocker software-based encryption will be used instead.

    The recommended state for this setting is: Disable: False (unchecked).

    Rationale: From a strict security perspective the hardware-based encryption may offer the same, greater, or less protection than what is provided by BitLocker's software-based encryption depending on how the algorithms and key lengths compare.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'OSAllowSoftwareEncryptionFailover' }
    its('OSAllowSoftwareEncryptionFailover') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.13_BL_Ensure_Require_additional_authentication_at_startup_is_set_to_Enabled' do
  title "(BL) Ensure 'Require additional authentication at startup' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure whether BitLocker requires additional authentication each time the computer starts and whether you are using BitLocker with or without a Trusted Platform Module (TPM). This policy setting is applied when you turn on BitLocker.

    **Note:** Only one of the additional authentication options can be required at startup, otherwise a policy error occurs.

    If you want to use BitLocker on a computer without a TPM, select the \"Allow BitLocker without a compatible TPM\" check box. In this mode a USB drive is required for start-up and the key information used to encrypt the drive is stored on the USB drive, creating a USB key. When the USB key is inserted the access to the drive is authenticated and the drive is accessible. If the USB key is lost or unavailable you will need to use one of the BitLocker recovery options to access the drive.

    On a computer with a compatible TPM, four types of authentication methods can be used at startup to provide added protection for encrypted data. When the computer starts, it can use only the TPM for authentication, or it can also require insertion of a USB flash drive containing a startup key, the entry of a 4-digit to 20-digit personal identification number (PIN), or both.

    Users can configure advanced startup options in the BitLocker setup wizard.

    **Note #2:** If you want to require the use of a startup PIN and a USB flash drive, you must configure BitLocker settings using the command-line tool manage-bde instead of the BitLocker Drive Encryption setup wizard.

    The recommended state for this setting is: Enabled .

    Rationale: TPM without use of a PIN will only validate early boot components and does not require a user to enter any additional authentication information. If a computer is lost or stolen in this configuration, BitLocker will not provide any additional measure of protection beyond what is provided by native Windows authentication unless the early boot components are tampered with or the encrypted drive is removed from the machine.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'UseAdvancedStartup' }
    its('UseAdvancedStartup') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.2.14_BL_Ensure_Require_additional_authentication_at_startup_Allow_BitLocker_without_a_compatible_TPM_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False'"
  desc  "
    This policy setting allows you to configure whether you can use BitLocker without a Trusted Platform Module (TPM), instead using a password or startup key on a USB flash drive. This policy setting is applied when you turn on BitLocker.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: TPM without use of a PIN will only validate early boot components and does not require a user to enter any additional authentication information. If a computer is lost or stolen in this configuration, BitLocker will not provide any additional measure of protection beyond what is provided by native Windows authentication unless the early boot components are tampered with or the encrypted drive is removed from the machine.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'EnableBDEWithNoTPM' }
    its('EnableBDEWithNoTPM') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.1_BL_Ensure_Allow_access_to_BitLocker-protected_removable_data_drives_from_earlier_versions_of_Windows_is_set_to_Disabled' do
  title "(BL) Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled'"
  desc  "
    This policy setting configures whether or not removable data drives formatted with the FAT file system can be unlocked and viewed on computers running Windows Server 2008 (non-R2), Windows Vista, Windows XP with Service Pack 3 (SP3), or Windows XP with Service Pack 2 (SP2) operating systems.

    **Note:** This policy setting does not apply to drives that are formatted with the NTFS file system.

    The recommended state for this setting is: Disabled .

    Rationale: By default BitLocker virtualizes FAT formatted drives to permit access via the BitLocker To Go Reader on previous versions of Windows. Additionally the BitLocker To Go Reader application is applied to the unencrypted portion of the drive.

    The BitLocker To Go Reader application, like any other application, is subject to spoofing and could be a mechanism to propagate malware.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVDiscoveryVolumeType' }
    its('RDVDiscoveryVolumeType') { should eq '<none>' }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.2_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_is_set_to_Enabled' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    The \"Allow data recovery agent\" check box is used to specify whether a Data Recovery Agent can be used with BitLocker-protected removable data drives. Before a Data Recovery Agent can be used it must be added from the Public Key Policies item in either the Group Policy Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption Deployment Guide on Microsoft TechNet for more information about adding Data Recovery Agents.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    Select \"Omit recovery options from the BitLocker setup wizard\" to prevent users from specifying recovery options when they enable BitLocker on a drive. This means that you will not be able to specify which recovery option to use when you enable BitLocker, instead BitLocker recovery options for the drive are determined by the policy setting.

    In \"Save BitLocker recovery information to Active Directory Domain Services\" choose which BitLocker recovery information to store in AD DS for removable data drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    Select the \"Do not enable BitLocker until recovery information is stored in AD DS for removable data drives\" check box if you want to prevent users from enabling BitLocker unless the computer is connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

    **Note:** If the \"Do not enable BitLocker until recovery information is stored in AD DS for removable data drives\" check box is selected, a recovery password is automatically generated.

    The recommended state for this setting is: Enabled .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVRecovery' }
    its('RDVRecovery') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.3_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Allow_data_recovery_agent_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    The \"Allow data recovery agent\" check box is used to specify whether a Data Recovery Agent can be used with BitLocker-protected removable data drives. Before a Data Recovery Agent can be used it must be added from the Public Key Policies item in either the Group Policy Management Console or the Local Group Policy Editor. Consult the BitLocker Drive Encryption Deployment Guide on Microsoft TechNet for more information about adding Data Recovery Agents.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVManageDRA' }
    its('RDVManageDRA') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.4_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Recovery_Password_is_set_to_Enabled_Do_not_allow_48-digit_recovery_password' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    The recommended state for this setting is: Enabled: Do not allow 48-digit recovery password .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVRecoveryPassword' }
    its('RDVRecoveryPassword') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.5_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Recovery_Key_is_set_to_Enabled_Do_not_allow_256-bit_recovery_key' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Configure user storage of BitLocker recovery information\" select whether users are allowed, required, or not allowed to generate a 48-digit recovery password or a 256-bit recovery key.

    The recommended state for this setting is: Enabled: Do not allow 256-bit recovery key .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVRecoveryKey' }
    its('RDVRecoveryKey') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.6_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Omit_recovery_options_from_the_BitLocker_setup_wizard_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    Select \"Omit recovery options from the BitLocker setup wizard\" to prevent users from specifying recovery options when they enable BitLocker on a drive. This means that you will not be able to specify which recovery option to use when you enable BitLocker, instead BitLocker recovery options for the drive are determined by the policy setting.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVHideRecoveryPage' }
    its('RDVHideRecoveryPage') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.7_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Save_BitLocker_recovery_information_to_AD_DS_for_removable_data_drives_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Save BitLocker recovery information to Active Directory Domain Services\" choose which BitLocker recovery information to store in AD DS for removable data drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVActiveDirectoryBackup' }
    its('RDVActiveDirectoryBackup') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.8_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Configure_storage_of_BitLocker_recovery_information_to_AD_DS_is_set_to_Enabled_Backup_recovery_passwords_and_key_packages' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    In \"Save BitLocker recovery information to Active Directory Domain Services\" choose which BitLocker recovery information to store in AD DS for removable data drives. If you select \"Backup recovery password and key package\", both the BitLocker recovery password and key package are stored in AD DS. If you select \"Backup recovery password only\", only the recovery password is stored in AD DS.

    The recommended state for this setting is: Enabled: Backup recovery passwords and key packages .

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVActiveDirectoryInfoToStore' }
    its('RDVActiveDirectoryInfoToStore') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.9_BL_Ensure_Choose_how_BitLocker-protected_removable_drives_can_be_recovered_Do_not_enable_BitLocker_until_recovery_information_is_stored_to_AD_DS_for_removable_data_drives_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False'"
  desc  "
    This policy setting allows you to control how BitLocker-protected removable data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker.

    Select the \"Do not enable BitLocker until recovery information is stored in AD DS for removable data drives\" check box if you want to prevent users from enabling BitLocker unless the computer is connected to the domain and the backup of BitLocker recovery information to AD DS succeeds.

    **Note:** If the \"Do not enable BitLocker until recovery information is stored in AD DS for removable data drives\" check box is selected, a recovery password is automatically generated.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: Administrators should always have a safe, secure way to access encrypted data in the event users cannot access their data.

    Additionally, as with any authentication method, a drive can be compromised by guessing or finding the authentication information used to access the drive.

    To use BitLocker a Data Recovery Agent will need to be configured for removable drives. To recover a drive will require highly-controlled access to the Data Recovery Agent private key.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVRequireActiveDirectoryBackup' }
    its('RDVRequireActiveDirectoryBackup') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.10_BL_Ensure_Configure_use_of_hardware-based_encryption_for_removable_data_drives_is_set_to_Disabled' do
  title "(BL) Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage BitLocker's use of hardware-based encryption on removable data drives and specify which encryption algorithms it can use with hardware-based encryption. Using hardware-based encryption can improve performance of drive operations that involve frequent reading or writing of data to the drive.

    You can specify additional options that control whether BitLocker software-based encryption is used instead of hardware-based encryption on computers that do not support hardware-based encryption and whether you want to restrict the encryption algorithms and cipher suites used with hardware-based encryption.

    **Note:** The \"Choose drive encryption method and cipher strength\" policy setting does not apply to hardware-based encryption. The encryption algorithm used by hardware-based encryption is set when the drive is partitioned. By default, BitLocker uses the algorithm configured on the drive to encrypt the drive. The \"Restrict encryption algorithms and cipher suites allowed for hardware-based encryption\" option enables you to restrict the encryption algorithms that BitLocker can use with hardware encryption. If the algorithm set for the drive is not available, BitLocker will disable the use of hardware-based encryption.

    Encryption algorithms are specified by object identifiers (OID). For example:

    * AES 128 in CBC mode OID: 2.16.840.1.101.3.4.1.2
    * AES 256 in CBC mode OID: 2.16.840.1.101.3.4.1.42
    The recommended state for this setting is: Disabled .

    Rationale: From a strict security perspective the hardware-based encryption may offer the same, greater, or less protection than what is provided by BitLocker's software-based encryption depending on how the algorithms and key lengths compare.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVHardwareEncryption' }
    its('RDVHardwareEncryption') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.11_BL_Ensure_Configure_use_of_passwords_for_removable_data_drives_is_set_to_Disabled' do
  title "(BL) Ensure 'Configure use of passwords for removable data drives' is set to 'Disabled'"
  desc  "
    This policy setting allows you to specify whether a password is required to unlock BitLocker-protected removable data drives.

    **Note:** This setting is enforced when turning on BitLocker, not when unlocking a drive. BitLocker will allow unlocking a drive with any of the protectors available on the drive.

    The recommended state for this setting is: Disabled .

    Rationale: Using a dictionary-style attack, passwords can be guessed or discovered by repeatedly attempting to unlock a drive. Since this type of BitLocker password does not include anti-dictionary attack protections provided by a TPM, for example, there is no mechanism to slow down use of rapid brute-force attacks against them.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVPassphrase' }
    its('RDVPassphrase') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.12_BL_Ensure_Configure_use_of_smart_cards_on_removable_data_drives_is_set_to_Enabled' do
  title "(BL) Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether smart cards can be used to authenticate user access to BitLocker-protected removable data drives on a computer.

    Smart cards can be used to authenticate user access to the drive. You can require smart card authentication by selecting the \"Require use of smart cards on removable data drives\" check box.

    **Note:** This setting is enforced when turning on BitLocker, not when unlocking a volume. BitLocker will allow unlocking a drive with any of the protectors available on the drive.

    The recommended state for this setting is: Enabled .

    Rationale: A drive can be compromised by guessing or finding the authentication information used to access the drive. For example, a password could be guessed, or a drive set to automatically unlock could be lost or stolen with the computer it automatically unlocks with.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVAllowUserCert' }
    its('RDVAllowUserCert') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.13_BL_Ensure_Configure_use_of_smart_cards_on_removable_data_drives_Require_use_of_smart_cards_on_removable_data_drives_is_set_to_Enabled_True' do
  title "(BL) Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True'"
  desc  "
    This policy setting specifies whether smart cards **must** be used to authenticate user access to BitLocker-protected removable data drives on a computer.

    Smart cards can be used to authenticate user access to the drive. You can require smart card authentication by selecting the \"Require use of smart cards on removable data drives\" check box.

    **Note:** This setting is enforced when turning on BitLocker, not when unlocking a volume. BitLocker will allow unlocking a drive with any of the protectors available on the drive.

    The recommended state for this setting is: Enabled: True (checked).

    Rationale: A drive can be compromised by guessing or finding the authentication information used to access the drive. For example, a password could be guessed, or a drive set to automatically unlock could be lost or stolen with the computer it automatically unlocks with.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVEnforceUserCert' }
    its('RDVEnforceUserCert') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.14_BL_Ensure_Deny_write_access_to_removable_drives_not_protected_by_BitLocker_is_set_to_Enabled' do
  title "(BL) Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'"
  desc  "
    This policy setting configures whether BitLocker protection is required for a computer to be able to write data to a removable data drive.

    All removable data drives that are not BitLocker-protected will be mounted as read-only. If the drive is protected by BitLocker, it will be mounted with read and write access.

    The recommended state for this setting is: Enabled .

    Rationale: Users may not voluntarily encrypt removable drives prior to saving important data to the drive.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVDenyWriteAccess' }
    its('RDVDenyWriteAccess') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.3.15_BL_Ensure_Deny_write_access_to_removable_drives_not_protected_by_BitLocker_Do_not_allow_write_access_to_devices_configured_in_another_organization_is_set_to_Enabled_False' do
  title "(BL) Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'"
  desc  "
    This policy setting configures whether the computer will be able to write data to BitLocker-protected removable drives that were configured in another organization.

    The recommended state for this setting is: Enabled: False (unchecked).

    Rationale: Restricting write access to BitLocker-protected removable drives that were configured in another organization can hinder legitimate business operations where encrypted data sharing is necessary.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\FVE') do
    it { should have_property 'RDVDenyCrossOrg' }
    its('RDVDenyCrossOrg') { should cmp == 0 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.11.4_BL_Ensure_Disable_new_DMA_devices_when_this_computer_is_locked_is_set_to_Enabled' do
  title "(BL) Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled'"
  desc  "
    This policy setting allows you to block direct memory access (DMA) for all hot pluggable PCI downstream ports until a user logs into Windows.

    The recommended state for this setting is: Enabled .

    **Note:** Microsoft changed the implementation of this setting in Windows 10 R1709 to strengthen its enforcement. As a result, some hardware configurations may experience unexpected problems with this setting in that release (or newer), until updated firmware and/or drivers from the vendor are installed to correct the problem. See the Impact Statement for more information.

    Rationale: A BitLocker-protected computer may be vulnerable to Direct Memory Access (DMA) attacks when the computer is turned on or is in the Standby power state - this includes when the workstation is locked. Enabling this setting will help prevent such an attack while the computer is left unattended.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE') do
    it { should have_property 'DisableExternalDMAUnderLock' }
    its('DisableExternalDMAUnderLock') { should cmp == 1 }
  end
  only_if { bitlocker == 'on' }
end

control '18.9.12.1_L2_Ensure_Allow_Use_of_Camera_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow Use of Camera' is set to 'Disabled'"
  desc  "
    This policy setting controls whether the use of Camera devices on the machine are permitted.

    The recommended state for this setting is: Disabled .

    Rationale: Cameras in a high security environment can pose serious privacy and data exfiltration risks - they should be disabled to help mitigate that risk.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Camera') do
    it { should have_property 'AllowCamera' }
    its('AllowCamera') { should cmp == 0 }
  end
end

control '18.9.13.1_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc  "
    This policy setting turns off experiences that help consumers make the most of their devices and Microsoft account.

    The recommended state for this setting is: Enabled .

    **Note:**[Per Microsoft TechNet](https://technet.microsoft.com/en-us/itpro/windows/manage/group-policies-for-enterprise-and-education-editions) , this policy setting only applies to Windows 10 Enterprise and Windows 10 Education editions.

    Rationale: Having apps silently install in an enterprise managed environment is not good security practice - especially if the apps send data back to a 3rd party.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    it { should have_property 'DisableWindowsConsumerFeatures' }
    its('DisableWindowsConsumerFeatures') { should cmp == 1 }
  end
end

control '18.9.13.2_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc  "
    This policy setting turns off experiences that help consumers make the most of their devices and Microsoft account.

    The recommended state for this setting is: Enabled .

    **Note:**[Per Microsoft TechNet](https://technet.microsoft.com/en-us/itpro/windows/manage/group-policies-for-enterprise-and-education-editions) , this policy setting only applies to Windows 10 Enterprise and Windows 10 Education editions.

    Rationale: Having apps silently install in an enterprise managed environment is not good security practice - especially if the apps send data back to a 3rd party.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    it { should have_property 'DisableWindowsConsumerFeatures' }
    its('DisableWindowsConsumerFeatures') { should cmp == 1 }
  end
end

control '18.9.14.1_L1_Ensure_Require_pin_for_pairing_is_set_to_Enabled_First_Time_OR_Enabled_Always' do
  title "(L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
  desc  "
    This policy setting controls whether or not a PIN is required for pairing to a wireless display device.

    The recommended state for this setting is: Enabled: First Time OR Enabled: Always .

    Rationale: If this setting is not configured or disabled then a PIN would not be required when pairing wireless display devices to the system, increasing the risk of unauthorized use.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect') do
      it { should have_property 'RequirePinForPairing' }
      its('RequirePinForPairing') { should cmp == 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect') do
      it { should have_property 'RequirePinForPairing' }
      its('RequirePinForPairing') { should cmp == 2 }
    end
  end
end

control '18.9.15.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure the display of the password reveal button in password entry user experiences.

    The recommended state for this setting is: Enabled .

    Rationale: This is a useful feature when entering a long and complex password, especially when using a touchscreen. The potential risk is that someone else may see your password while surreptitiously observing your screen.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI') do
    it { should have_property 'DisablePasswordReveal' }
    its('DisablePasswordReveal') { should cmp == 1 }
  end
end

control '18.9.15.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled' do
  title "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc  "
    This policy setting controls whether administrator accounts are displayed when a user attempts to elevate a running application.

    The recommended state for this setting is: Disabled .

    Rationale: Users could see the list of administrator accounts, making it slightly easier for a malicious user who has logged onto a console session to try to crack the passwords of those accounts.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should cmp == 0 }
  end
end

control '18.9.15.3_L1_Ensure_Prevent_the_use_of_security_questions_for_local_accounts_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled'"
  desc  "
    This policy setting controls whether security questions can be used to reset local account passwords. The security question feature does not apply to domain accounts, only local accounts on the workstation.

    The recommended state for this setting is: Enabled .

    Rationale: Users could establish security questions that are easily guessed or sleuthed by observing the user&#x2019;s social media accounts, making it easier for a malicious actor to change the local user account password and gain access to the computer as that user account.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'NoLocalPasswordResetQuestions' }
    its('NoLocalPasswordResetQuestions') { should cmp == 1 }
  end
end

control '18.9.16.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only_or_Enabled_1_-_Basic' do
  title "(L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
  desc  "
    This policy setting determines the amount of diagnostic and usage data reported to Microsoft:

    *  A value of 0 - Security [Enterprise Only] will send minimal data to Microsoft. This data includes Malicious Software Removal Tool (MSRT)  Microsoft Defender Antivirus data, if enabled, and telemetry client settings. Setting a value of 0 applies to enterprise, EDU, IoT and server devices only. Setting a value of 0 for other devices is equivalent to choosing a value of 1.
    *  A value of 1 - Basic sends only a basic amount of diagnostic and usage data. Note that setting values of 0 or 1 will degrade certain experiences on the device.
    *  A value of 2 - Enhanced sends enhanced diagnostic and usage data.
    *  A value of 3 - Full sends the same data as a value of 2, plus additional diagnostics data, including the files and content that may have caused the problem.
    Windows 10 telemetry settings apply to the Windows operating system and some first party apps. This setting does not apply to third party apps running on Windows 10.

    The recommended state for this setting is: Enabled: 0 - Security [Enterprise Only] or Enabled: 1 - Basic .

    **Note:** If the **Allow Telemetry** setting is configured to 0 - Security [Enterprise Only] , then the options in Windows Update to defer upgrades and updates will have no effect.

    **Note #2:** In the Microsoft Windows 10 RTM (Release 1507) Administrative Templates, the zero value was initially named 0 - Off [Enterprise Only] , but it was renamed to 0 - Security [Enterprise Only] starting with the Windows 10 Release 1511 Administrative Templates.

    Rationale: Sending any data to a 3rd party vendor is a security concern and should only be done on an as needed basis.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp == 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp == 1 }
    end
  end
end

control '18.9.16.2_L2_Ensure_Configure_Authenticated_Proxy_usage_for_the_Connected_User_Experience_and_Telemetry_service_is_set_to_Enabled_Disable_Authenticated_Proxy_usage' do
  title "(L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
  desc  "
    This policy setting controls whether the Connected User Experience and Telemetry service can automatically use an authenticated proxy to send data back to Microsoft.

    The recommended state for this setting is: Enabled: Disable Authenticated Proxy usage .

    Rationale: Sending any data to a 3rd party vendor is a security concern and should only be done on an as needed basis.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should have_property 'DisableEnterpriseAuthProxy' }
    its('DisableEnterpriseAuthProxy') { should cmp == 1 }
  end
end

control '18.9.16.3_L1_Ensure_Do_not_show_feedback_notifications_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
  desc  "
    This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.

    The recommended state for this setting is: Enabled .

    Rationale: Users should not be sending any feedback to 3rd party vendors in an enterprise managed environment.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    it { should have_property 'DoNotShowFeedbackNotifications' }
    its('DoNotShowFeedbackNotifications') { should cmp == 1 }
  end
end

control '18.9.16.4_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled' do
  title "(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users can access the Insider build controls in the Advanced Options for Windows Update. These controls are located under \"Get Insider builds,\" and enable users to make their devices available for downloading and installing Windows preview software.

    The recommended state for this setting is: Disabled .

    **Note:** This policy setting applies only to devices running Windows 10 Pro or Windows 10 Enterprise, up until Release 1703. For Release 1709 or newer, Microsoft encourages using the Manage preview builds setting (Rule 18.9.102.1.1). We have kept this setting in the benchmark to ensure that any older builds of Windows 10 in the environment are still enforced.

    Rationale: It can be risky for experimental features to be allowed in an enterprise managed environment because this can introduce bugs and security holes into systems, making it easier for an attacker to gain access. It is generally preferred to only use production-ready builds.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds') do
    it { should have_property 'AllowBuildPreview' }
    its('AllowBuildPreview') { should cmp == 0 }
  end
end

control '18.9.17.1_L1_Ensure_Download_Mode_is_NOT_set_to_Enabled_Internet' do
  title "(L1) Ensure 'Download Mode' is NOT set to 'Enabled: Internet'"
  desc  "
    This policy setting specifies the download method that Delivery Optimization can use in downloads of Windows Updates, Apps and App updates. The following methods are supported:

    * 0 = HTTP only, no peering.
    * 1 = HTTP blended with peering behind the same NAT.
    * 2 = HTTP blended with peering across a private group. Peering occurs on devices in the same Active Directory Site (if exist) or the same domain by default. When this option is selected, peering will cross NATs. To create a custom group use Group ID in combination with Mode 2.
    * 3 = HTTP blended with Internet Peering.
    * 99 = Simple download mode with no peering. Delivery Optimization downloads using HTTP only and does not attempt to contact the Delivery Optimization cloud services.
    * 100 = Bypass mode. Do not use Delivery Optimization and use BITS instead.
    The recommended state for this setting is any value EXCEPT: Enabled: Internet (3) .

    **Note:** The default on all SKUs other than Enterprise, Enterprise LTSB or Education is Enabled: Internet (3) , so on other SKUs, be sure to set this to a different value.

    Rationale: Due to privacy concerns and security risks, updates should only be downloaded directly from Microsoft, or from a trusted machine on the internal network that received **its** updates from a trusted source and approved by the network administrator.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization') do
    it { should have_property 'DODownloadMode' }
    its('DODownloadMode') { should cmp != 3 }
  end
end

control '18.9.26.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  title "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.

    The recommended state for this setting is: Disabled .

    **Note:** Old events may or may not be retained according to the **Backup log automatically when full** policy setting.

    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control '18.9.26.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater' do
  title "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes (4,194,240 kilobytes) in kilobyte increments.

    The recommended state for this setting is: Enabled: 32,768 or greater .

    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end

control '18.9.26.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  title "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.

    The recommended state for this setting is: Disabled .

    **Note:** Old events may or may not be retained according to the **Backup log automatically when full** policy setting.

    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control '18.9.26.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater' do
  title "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes (4,194,240 kilobytes) in kilobyte increments.

    The recommended state for this setting is: Enabled: 196,608 or greater .

    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 196608 }
  end
end

control '18.9.26.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  title "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.

    The recommended state for this setting is: Disabled .

    **Note:** Old events may or may not be retained according to the **Backup log automatically when full** policy setting.

    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control '18.9.26.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater' do
  title "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes (4,194,240 kilobytes) in kilobyte increments.

    The recommended state for this setting is: Enabled: 32,768 or greater .

    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end

control '18.9.26.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled' do
  title "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.

    The recommended state for this setting is: Disabled .

    **Note:** Old events may or may not be retained according to the **Backup log automatically when full** policy setting.

    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should have_property 'Retention' }
    its('Retention') { should cmp == 0 }
  end
end

control '18.9.26.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater' do
  title "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes (4,194,240 kilobytes) in kilobyte increments.

    The recommended state for this setting is: Enabled: 32,768 or greater .

    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end

control '18.9.30.2_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc  "
    Disabling Data Execution Prevention can allow certain legacy plug-in applications to function without terminating Explorer.

    The recommended state for this setting is: Disabled .

    **Note:** Some legacy plug-in applications and other software may not function with Data Execution Prevention and will require an exception to be defined for that specific plug-in/software.

    Rationale: Data Execution Prevention is an important security feature supported by Explorer that helps to limit the impact of certain types of malware.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoDataExecutionPrevention' }
    its('NoDataExecutionPrevention') { should cmp == 0 }
  end
end

control '18.9.30.3_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc  "
    Without heap termination on corruption, legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Ensuring that heap termination on corruption is active will prevent this.

    The recommended state for this setting is: Disabled .

    Rationale: Allowing an application to function after its session has become corrupt increases the risk posture to the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoHeapTerminationOnCorruption' }
    its('NoHeapTerminationOnCorruption') { should cmp == 0 }
  end
end

control '18.9.30.4_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc  "
    This policy setting allows you to configure the amount of functionality that the shell protocol can have. When using the full functionality of this protocol, applications can open folders and launch files. The protected mode reduces the functionality of this protocol allowing applications to only open a limited set of folders. Applications are not able to open files with this protocol when it is in the protected mode. It is recommended to leave this protocol in the protected mode to increase the security of Windows.

    The recommended state for this setting is: Disabled .

    Rationale: Limiting the opening of files and folders to a limited set reduces the attack surface of the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'PreXPSP2ShellProtocolBehavior' }
    its('PreXPSP2ShellProtocolBehavior') { should cmp == 0 }
  end
end

control '18.9.35.1_L1_Ensure_Prevent_the_computer_from_joining_a_homegroup_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'"
  desc  "
    By default, users can add their computer to a HomeGroup on a home network.

    The recommended state for this setting is: Enabled .

    **Note:** The HomeGroup feature is available in all workstation releases of Windows from Windows 7 through Windows 10 Release 1709. Microsoft removed the feature completely starting with Windows 10 Release 1803. However, if your environment still contains **any** Windows 10 Release 1709 (or older) workstations, then this setting remains important to disable HomeGroup on those systems.

    Rationale: While resources on a domain-joined computer cannot be shared with a HomeGroup, information from the domain-joined computer can be leaked to other computers in the HomeGroup.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup') do
    it { should have_property 'DisableHomeGroup' }
    its('DisableHomeGroup') { should cmp == 1 }
  end
end

control '18.9.39.1_L2_Ensure_Turn_off_location_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off location' is set to 'Enabled'"
  desc  "
    This policy setting turns off the location feature for the computer.

    The recommended state for this setting is: Enabled .

    Rationale: This setting affects the location feature (e.g. GPS or other location tracking). From a security perspective, it&#x2019;s not a good idea to reveal your location to software in most cases, but there are legitimate uses, such as mapping software. However, they should not be used in high security environments.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should have_property 'DisableLocation' }
    its('DisableLocation') { should cmp == 1 }
  end
end

control '18.9.43.1_L2_Ensure_Allow_Message_Service_Cloud_Sync_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
  desc  "
    This policy setting allows backup and restore of cellular text messages to Microsoft's cloud services.

    The recommended state for this setting is: Disabled .

    Rationale: In a high security environment, data should never be sent to any 3rd party since this data could contain sensitive information.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging') do
    it { should have_property 'AllowMessageSync' }
    its('AllowMessageSync') { should cmp == 0 }
  end
end

control '18.9.44.1_L1_Ensure_Block_all_consumer_Microsoft_account_user_authentication_is_set_to_Enabled' do
  title "(L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
  desc  "
    This setting determines whether applications and services on the device can utilize new consumer Microsoft account authentication via the Windows OnlineID and WebAccountManager APIs.

    The recommended state for this setting is: Enabled .

    Rationale: Organizations that want to effectively implement identity management policies and maintain firm control of what accounts are used on their computers will probably want to block Microsoft accounts. Organizations may also need to block Microsoft accounts in order to meet the requirements of compliance standards that apply to their information systems.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount') do
    it { should have_property 'DisableUserAuth' }
    its('DisableUserAuth') { should cmp == 1 }
  end
end

control '18.9.45.3.1_L1_Ensure_Configure_local_setting_override_for_reporting_to_Microsoft_MAPS_is_set_to_Disabled' do
  title "(L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
  desc  "
    This policy setting configures a local override for the configuration to join Microsoft Active Protection Service (MAPS), which Microsoft renamed to **Windows Defender Antivirus Cloud Protection Service** and then **Microsoft Defender Antivirus Cloud Protection Service** . This setting can only be set by Group Policy.

    The recommended state for this setting is: Disabled .

    Rationale: The decision on whether or not to participate in Microsoft MAPS / Microsoft Defender Antivirus Cloud Protection Service for malicious software reporting should be made centrally in an enterprise managed environment, so that all computers within it behave consistently in that regard. Configuring this setting to Disabled ensures that the decision remains centrally managed.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet') do
    it { should have_property 'LocalSettingOverrideSpynetReporting' }
    its('LocalSettingOverrideSpynetReporting') { should cmp == 0 }
  end
end

control '18.9.45.3.2_L2_Ensure_Join_Microsoft_MAPS_is_set_to_Disabled' do
  title "(L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'"
  desc  "
    This policy setting allows you to join Microsoft Active Protection Service (MAPS), which Microsoft renamed to **Windows Defender Antivirus Cloud Protection Service** and then **Microsoft Defender Antivirus Cloud Protection Service** . Microsoft MAPS / Microsoft Defender Antivirus Cloud Protection Service is the online community that helps you choose how to respond to potential threats. The community also helps stop the spread of new malicious software infections. You can choose to send basic or additional information about detected software. Additional information helps Microsoft create new definitions and help it to protect your computer.

    Possible options are:

    * (0x0) Disabled (default)
    * (0x1) Basic membership
    * (0x2) Advanced membership
    **Basic membership** will send basic information to Microsoft about software that has been detected including where the software came from the actions that you apply or that are applied automatically and whether the actions were successful.

    **Advanced membership** in addition to basic information will send more information to Microsoft about malicious software spyware and potentially unwanted software including the location of the software file names how the software operates and how it has impacted your computer.

    The recommended state for this setting is: Disabled .

    Rationale: The information that would be sent can include things like location of detected items on your computer if harmful software was removed. The information would be automatically collected and sent. In some instances personal information might unintentionally be sent to Microsoft. However, Microsoft states that it will not use this information to identify you or contact you.

    For privacy reasons in high security environments, it is best to prevent these data submissions altogether.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet') do
      it { should have_property 'SpynetReporting' }
      its('SpynetReporting') { should cmp == 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet') do
      it { should_not have_property 'SpynetReporting' }
    end
  end
end

control '18.9.45.4.1.1_L1_Ensure_Configure_Attack_Surface_Reduction_rules_is_set_to_Enabled' do
  title "(L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
  desc  "
    This policy setting controls the state for the Attack Surface Reduction (ASR) rules.

    The recommended state for this setting is: Enabled .

    Rationale: Attack surface reduction helps prevent actions and apps that are typically used by exploit-seeking malware to infect machines.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR') do
    it { should have_property 'ExploitGuard_ASR_Rules' }
    its('ExploitGuard_ASR_Rules') { should cmp == 1 }
  end
end

control '18.9.45.4.1.2_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured' do
  title "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
  desc  "
    This policy setting sets the Attack Surface Reduction rules.

    The recommended state for this setting is:

    26190899-1602-49e8-8b27-eb1d0a1ce869 - 1 (Block Office communication application from creating child processes)

    3b576869-a4ec-4529-8536-b80a7769e899 - 1 (Block Office applications from creating executable content)

    5beb7efe-fd9a-4556-801d-275e5ffc04cc - 1 (Block execution of potentially obfuscated scripts)

    75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 - 1 (Block Office applications from injecting code into other processes)

    7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c - 1 (Block Adobe Reader from creating child processes)

    92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b - 1 (Block Win32 API calls from Office macro)

    9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 - 1 (Block credential stealing from the Windows local security authority subsystem (lsass.exe))

    b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 - 1 (Block untrusted and unsigned processes that run from USB)

    be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 - 1 (Block executable content from email client and webmail)

    d3e037e1-3eb8-44c8-a917-57927947596d - 1 (Block JavaScript or VBScript from launching downloaded executable content)

    d4f940ab-401b-4efc-aadc-ad5f3c50688a - 1 (Block Office applications from creating child processes)

    **Note:** More information on ASR rules can be found at the following link: [Use Attack surface reduction rules to prevent malware infection | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard)

    Rationale: Attack surface reduction helps prevent actions and apps that are typically used by exploit-seeking malware to infect machines.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '26190899-1602-49e8-8b27-eb1d0a1ce869' }
    its('26190899-1602-49e8-8b27-eb1d0a1ce869') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '3b576869-a4ec-4529-8536-b80a7769e899' }
    its('3b576869-a4ec-4529-8536-b80a7769e899') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '5beb7efe-fd9a-4556-801d-275e5ffc04cc' }
    its('5beb7efe-fd9a-4556-801d-275e5ffc04cc') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' }
    its('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' }
    its('7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' }
    its('92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }
    its('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' }
    its('b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' }
    its('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'd3e037e1-3eb8-44c8-a917-57927947596d' }
    its('d3e037e1-3eb8-44c8-a917-57927947596d') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules') do
    it { should have_property 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' }
    its('d4f940ab-401b-4efc-aadc-ad5f3c50688a') { should cmp == 1 }
  end
end

control '18.9.45.4.3.1_L1_Ensure_Prevent_users_and_apps_from_accessing_dangerous_websites_is_set_to_Enabled_Block' do
  title "(L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
  desc  "
    This policy setting controls Microsoft Defender Exploit Guard network protection.

    The recommended state for this setting is: Enabled: Block .

    Rationale: This setting can help prevent employees from using any application to access dangerous domains that may host phishing scams, exploit-hosting sites, and other malicious content on the Internet.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection') do
    it { should have_property 'EnableNetworkProtection' }
    its('EnableNetworkProtection') { should cmp == 1 }
  end
end

control '18.9.45.5.1_L2_Ensure_Enable_file_hash_computation_feature_is_set_to_Enabled' do
  title "(L2) Ensure 'Enable file hash computation feature' is set to 'Enabled'"
  desc  "
    This setting determines whether hash values are computed for files scanned by Microsoft Defender.

    The recommended state for this setting is: Enabled .

    Rationale: When running an antivirus solution such as Microsoft Defender Antivirus, it is important to ensure that it is configured to monitor for suspicious and known malicious activity. File hashes are a reliable way of detecting changes to files, and can speed up the scan process by skipping files that have not changed since they were last scanned and determined to be safe. A changed file hash can also be cause for additional scrutiny scanning.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine') do
    it { should have_property 'EnableFileHashComputation' }
    its('EnableFileHashComputation') { should cmp == 1 }
  end
end

control '18.9.45.8.1_L1_Ensure_Turn_on_behavior_monitoring_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure behavior monitoring for Microsoft Defender Antivirus.

    The recommended state for this setting is: Enabled .

    Rationale: When running an antivirus solution such as Microsoft Defender Antivirus, it is important to ensure that it is configured to heuristically monitor in real-time for suspicious and known malicious activity.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection') do
    it { should have_property 'DisableBehaviorMonitoring' }
    its('DisableBehaviorMonitoring') { should cmp == 0 }
  end
end

control '18.9.45.10.1_L2_Ensure_Configure_Watson_events_is_set_to_Disabled' do
  title "(L2) Ensure 'Configure Watson events' is set to 'Disabled'"
  desc  "
    This policy setting allows you to configure whether or not Watson events are sent.

    The recommended state for this setting is: Disabled .

    Rationale: Watson events are the reports that get sent to Microsoft when a program or service crashes or fails, including the possibility of automatic submission. Preventing this information from being sent can help reduce privacy concerns.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting') do
    it { should have_property 'DisableGenericReports' }
    its('DisableGenericReports') { should cmp == 1 }
  end
end

control '18.9.45.11.1_L1_Ensure_Scan_removable_drives_is_set_to_Enabled' do
  title "(L1) Ensure 'Scan removable drives' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether or not to scan for malicious software and unwanted software in the contents of removable drives, such as USB flash drives, when running a full scan.

    The recommended state for this setting is: Enabled .

    Rationale: It is important to ensure that any present removable drives are always included in any type of scan, as removable drives are more likely to contain malicious software brought in to the enterprise managed environment from an external, unmanaged computer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should have_property 'DisableRemovableDriveScanning' }
    its('DisableRemovableDriveScanning') { should cmp == 0 }
  end
end

control '18.9.45.11.2_L1_Ensure_Turn_on_e-mail_scanning_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure e-mail scanning. When e-mail scanning is enabled, the engine will parse the mailbox and mail files, according to their specific format, in order to analyze the mail bodies and attachments. Several e-mail formats are currently supported, for example: pst (Outlook), dbx, mbx, mime (Outlook Express), binhex (Mac).

    The recommended state for this setting is: Enabled .

    Rationale: Incoming e-mails should be scanned by an antivirus solution such as Microsoft Defender Antivirus, as email attachments are a commonly used attack vector to infiltrate computers with malicious software.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan') do
    it { should have_property 'DisableEmailScanning' }
    its('DisableEmailScanning') { should cmp == 0 }
  end
end

control '18.9.45.14_L1_Ensure_Configure_detection_for_potentially_unwanted_applications_is_set_to_Enabled_Block' do
  title "(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
  desc  "
    This policy setting controls detection and action for Potentially Unwanted Applications (PUA), which are sneaky unwanted application bundlers or their bundled applications, that can deliver adware or malware.

    The recommended state for this setting is: Enabled: Block .

    For more information, see this link: [Block potentially unwanted applications with Microsoft Defender Antivirus | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/detect-block-potentially-unwanted-apps-windows-defender-antivirus)

    Rationale: Potentially unwanted applications can increase the risk of your network being infected with malware, cause malware infections to be harder to identify, and can waste IT resources in cleaning up the applications. They should be blocked from installation.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should have_property 'PUAProtection' }
    its('PUAProtection') { should cmp == 1 }
  end
end

control '18.9.45.15_L1_Ensure_Turn_off_Microsoft_Defender_AntiVirus_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'"
  desc  "
    This policy setting turns off Microsoft Defender Antivirus. If the setting is configured to Disabled, Microsoft Defender Antivirus runs and computers are scanned for malware and other potentially unwanted software.

    The recommended state for this setting is: Disabled .

    Rationale: It is important to ensure a current, updated antivirus product is scanning each computer for malicious file activity. Microsoft provides a competent solution out of the box in Microsoft Defender Antivirus.

    Organizations that choose to purchase a reputable 3rd-party antivirus solution may choose to exempt themselves from this recommendation in lieu of the commercial alternative.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender') do
    it { should have_property 'DisableAntiSpyware' }
    its('DisableAntiSpyware') { should cmp == 0 }
  end
end

control '18.9.46.1_NG_Ensure_Allow_auditing_events_in_Microsoft_Defender_Application_Guard_is_set_to_Enabled' do
  title "(NG) Ensure 'Allow auditing events in Microsoft Defender Application Guard' is set to 'Enabled'"
  desc  "
    This policy setting allows you to decide whether auditing events can be collected from Microsoft Defender Application Guard.

    The recommended state for this setting is: Enabled .

    **Note:** Microsoft Defender Application Guard requires a 64-bit version of Windows and a CPU supporting hardware-assisted CPU virtualization (Intel VT-x or AMD-V). This feature is not officially supported on virtual hardware, although it can work on VMs (especially for testing) provided that the hardware-assisted CPU virtualization feature is exposed by the host to the guest VM.

    More information on system requirements for this feature can be found at [System requirements for Microsoft Defender Application Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)

    **Note #2:** Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

    Rationale: Auditing of Microsoft Defender Application Guard events may be useful when investigating a security incident.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppHVSI') do
    it { should have_property 'AuditApplicationGuard' }
    its('AuditApplicationGuard') { should cmp == 1 }
  end
end

control '18.9.46.2_NG_Ensure_Allow_camera_and_microphone_access_in_Microsoft_Defender_Application_Guard_is_set_to_Disabled' do
  title "(NG) Ensure 'Allow camera and microphone access in Microsoft Defender Application Guard' is set to 'Disabled'"
  desc  "
    The policy allows you to determine whether applications inside Microsoft Defender Application Guard can access the device&#x2019;s camera and microphone.

    The recommended state for this setting is: Disabled .

    **Note:** Microsoft Defender Application Guard requires a 64-bit version of Windows and a CPU supporting hardware-assisted CPU virtualization (Intel VT-x or AMD-V). This feature is not officially supported on virtual hardware, although it can work on VMs (especially for testing) provided that the hardware-assisted CPU virtualization feature is exposed by the host to the guest VM.

    More information on system requirements for this feature can be found at [System requirements for Microsoft Defender Application Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)

    **Note #2:** Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

    Rationale: In effort to stop sensitive information from being obtained for malicious use, untrusted sites within the Microsoft Defender Application Guard container should not be accessing the computers microphone or camera.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppHVSI') do
    it { should have_property 'AllowCameraMicrophoneRedirection' }
    its('AllowCameraMicrophoneRedirection') { should cmp == 0 }
  end
end

control '18.9.46.3_NG_Ensure_Allow_data_persistence_for_Microsoft_Defender_Application_Guard_is_set_to_Disabled' do
  title "(NG) Ensure 'Allow data persistence for Microsoft Defender Application Guard' is set to 'Disabled'"
  desc  "
    This policy setting allows you to decide whether data should persist across different sessions in Microsoft Defender Application Guard.

    The recommended state for this setting is: Disabled .

    **Note:** Microsoft Defender Application Guard requires a 64-bit version of Windows and a CPU supporting hardware-assisted CPU virtualization (Intel VT-x or AMD-V). This feature is not officially supported on virtual hardware, although it can work on VMs (especially for testing) provided that the hardware-assisted CPU virtualization feature is exposed by the host to the guest VM.

    More information on system requirements for this feature can be found at [System requirements for Microsoft Defender Application Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)

    **Note #2:** Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

    Rationale: The primary purpose of Microsoft Defender Application Guard is to present a \"sandboxed container\" for visiting untrusted websites. If data persistence is allowed, then it reduces the effectiveness of the sandboxing, and malicious content will be able to remain active in the Microsoft Defender Application Guard container between sessions.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppHVSI') do
    it { should have_property 'AllowPersistence' }
    its('AllowPersistence') { should cmp == 0 }
  end
end

control '18.9.46.4_NG_Ensure_Allow_files_to_download_and_save_to_the_host_operating_system_from_Microsoft_Defender_Application_Guard_is_set_to_Disabled' do
  title "(NG) Ensure 'Allow files to download and save to the host operating system from Microsoft Defender Application Guard' is set to 'Disabled'"
  desc  "
    This policy setting determines whether to save downloaded files to the host operating system from the Microsoft Defender Application Guard container.

    The recommended state for this setting is: Disabled .

    **Note:** Microsoft Defender Application Guard requires a 64-bit version of Windows and a CPU supporting hardware-assisted CPU virtualization (Intel VT-x or AMD-V). This feature is not officially supported on virtual hardware, although it can work on VMs (especially for testing) provided that the hardware-assisted CPU virtualization feature is exposed by the host to the guest VM.

    More information on system requirements for this feature can be found at [System requirements for Microsoft Defender Application Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)

    **Note #2:** Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

    Rationale: The primary purpose of Microsoft Defender Application Guard is to present a \"sandboxed container\". Potentially malicious files should not be copied to the host OS from the sandboxed environment, which could put the host at risk.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppHVSI') do
    it { should have_property 'SaveFilesToHost' }
    its('SaveFilesToHost') { should cmp == 0 }
  end
end

control '18.9.46.5_NG_Ensure_Configure_Microsoft_Defender_Application_Guard_clipboard_settings_Clipboard_behavior_setting_is_set_to_Enabled_Enable_clipboard_operation_from_an_isolated_session_to_the_host' do
  title "(NG) Ensure 'Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host'"
  desc  "
    This policy setting allows you to decide how the clipboard behaves while in Microsoft Defender Application Guard.

    The recommended state for this setting is: Enabled: Enable clipboard operation from an isolated session to the host .

    **Note:** Microsoft Defender Application Guard requires a 64-bit version of Windows and a CPU supporting hardware-assisted CPU virtualization (Intel VT-x or AMD-V). This feature is not officially supported on virtual hardware, although it can work on VMs (especially for testing) provided that the hardware-assisted CPU virtualization feature is exposed by the host to the guest VM.

    More information on system requirements for this feature can be found at [System requirements for Microsoft Defender Application Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)

    **Note #2:** Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

    Rationale: The primary purpose of Microsoft Defender Application Guard is to present a \"sandboxed container\" for visiting untrusted websites. If the host clipboard is made available to Microsoft Defender Application Guard, a compromised Microsoft Defender Application Guard session will have access to its content, potentially exposing sensitive information to a malicious website or application. However, the risk is reduced if the Microsoft Defender Application Guard clipboard is made accessible to the host, and indeed that functionality may often be necessary from an operational standpoint.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppHVSI') do
    it { should have_property 'AppHVSIClipboardSettings' }
    its('AppHVSIClipboardSettings') { should cmp == 1 }
  end
end

control '18.9.46.6_NG_Ensure_Turn_on_Microsoft_Defender_Application_Guard_in_Managed_Mode_is_set_to_Enabled_1' do
  title "(NG) Ensure 'Turn on Microsoft Defender Application Guard in Managed Mode' is set to 'Enabled: 1'"
  desc  "
    This policy setting enables application isolation through Microsoft Defender Application Guard (Application Guard).

    There are 4 options available:

    * * Disable Microsoft Defender Application Guard

    * * Enable Microsoft Defender Application Guard for Microsoft Edge ONLY

    * * Enable Microsoft Defender Application Guard for Microsoft Office ONLY

    * * Enable Microsoft Defender Application Guard for Microsoft Edge AND Microsoft Office

    The recommended state for this setting is: Enabled: 1 (Enable Microsoft Defender Application Guard for Microsoft Edge ONLY).

    **Note:** Microsoft Defender Application Guard requires a 64-bit version of Windows and a CPU supporting hardware-assisted CPU virtualization (Intel VT-x or AMD-V). This feature is not officially supported on virtual hardware, although it can work on VMs (especially for testing) provided that the hardware-assisted CPU virtualization feature is exposed by the host to the guest VM.

    More information on system requirements for this feature can be found at [System requirements for Microsoft Defender Application Guard (Windows 10) | Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard)

    **Note #2:** At time of publication, Microsoft Defender Application Guard in all currently released versions of Windows 10 does not yet support protection for Microsoft Office, only for Microsoft Edge. Therefore the additional available options of 2 and 3 in this setting are not yet valid.

    **Note #3:** Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

    Rationale: Microsoft Defender Application Guard uses Windows Hypervisor to create a virtualized environment for apps that are configured to use virtualization-based security isolation. While in isolation, improper user interactions and app vulnerabilities can&#x2019;t compromise the kernel or any other apps running outside of the virtualized environment.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\AppHVSI') do
    it { should have_property 'AllowAppHVSI_ProviderSet' }
    its('AllowAppHVSI_ProviderSet') { should cmp == 1 }
  end
end

control '18.9.55.1_L2_Ensure_Enable_news_and_interests_on_the_taskbar_is_set_to_Disabled' do
  title "(L2) Ensure 'Enable news and interests on the taskbar' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether the news and interests feature is allowed on the device.

    The recommended state for this setting is: Disabled .

    Rationale: Due to privacy concerns, apps and features such as news and interests on the Windows taskbar should be treated as a possible security risk due to the potential of data being sent back to 3rd parties, such as Microsoft.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Windows Feeds') do
    it { should have_property 'EnableFeeds' }
    its('EnableFeeds') { should cmp == 0 }
  end
end

control '18.9.56.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc  "
    This policy setting lets you prevent apps and features from working with files on OneDrive using the Next Generation Sync Client.

    The recommended state for this setting is: Enabled .

    Rationale: Enabling this setting prevents users from accidentally (or intentionally) uploading confidential or sensitive corporate information to the OneDrive cloud service using the Next Generation Sync Client.

    **Note:** This security concern applies to **any** cloud-based file storage application installed on a workstation, not just the one supplied with Windows.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive') do
    it { should have_property 'DisableFileSyncNGSC' }
    its('DisableFileSyncNGSC') { should cmp == 1 }
  end
end

control '18.9.62.1_L2_Ensure_Turn_off_Push_To_Install_service_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off Push To Install service' is set to 'Enabled'"
  desc  "
    This policy setting controls whether users can push Apps to the device from the Microsoft Store App running on other devices or the web.

    The recommended state for this setting is: Enabled .

    Rationale: In a high security managed environment, application installations should be managed centrally by IT staff, not by end users.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\PushToInstall') do
    it { should have_property 'DisablePushToInstall' }
    its('DisablePushToInstall') { should cmp == 1 }
  end
end

control '18.9.63.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc  "
    This policy setting helps prevent Remote Desktop clients from saving passwords on a computer.

    The recommended state for this setting is: Enabled .

    **Note:** If this policy setting was previously configured as Disabled or Not configured, any previously saved passwords will be deleted the first time a Remote Desktop client disconnects from any server.

    Rationale: An attacker with physical access to the computer may be able to break the protection guarding saved passwords. An attacker who compromises a user's account and connects to their computer could use saved passwords to gain access to additional hosts.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'DisablePasswordSaving' }
    its('DisablePasswordSaving') { should cmp == 1 }
  end
end

control '18.9.63.3.2.1_L2_Ensure_Allow_users_to_connect_remotely_by_using_Remote_Desktop_Services_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'"
  desc  "
    This policy setting allows you to configure remote access to computers by using Remote Desktop Services.

    The recommended state for this setting is: Disabled .

    Rationale: Any account with the **Allow log on through Remote Desktop Services** user right can log on to the remote console of the computer. If you do not restrict access to legitimate users who need to log on to the console of the computer, unauthorized users could download and execute malicious code to elevate their privileges.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDenyTSConnections' }
    its('fDenyTSConnections') { should cmp == 1 }
  end
end

control '18.9.63.3.3.1_L2_Ensure_Do_not_allow_COM_port_redirection_is_set_to_Enabled' do
  title "(L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether to prevent the redirection of data to client COM ports from the remote computer in a Remote Desktop Services session.

    The recommended state for this setting is: Enabled .

    Rationale: In a more security-sensitive environment, it is desirable to reduce the possible attack surface. The need for COM port redirection within a Remote Desktop session is very rare, so makes sense to reduce the number of unexpected avenues for data exfiltration and/or malicious code transfer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCcm' }
    its('fDisableCcm') { should cmp == 1 }
  end
end

control '18.9.63.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled' do
  title "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc  "
    This policy setting prevents users from sharing the local drives on their client computers to Remote Desktop Servers that they access. Mapped drives appear in the session folder tree in Windows Explorer in the following format:

    \\\\TSClient\\
    <driveletter>$

    If local drives are shared they are left vulnerable to intruders who want to exploit the data that is stored on them.

    The recommended state for this setting is: Enabled .</driveletter>

    Rationale: Data could be forwarded from the user's Remote Desktop Services session to the user's local computer without any direct user interaction. Malicious software already present on a compromised server would have direct and stealthy disk access to the user's local computer during the Remote Desktop session.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should cmp == 1 }
  end
end

control '18.9.62.3.3.3_L2_Ensure_Do_not_allow_LPT_port_redirection_is_set_to_Enabled' do
  title "(L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether to prevent the redirection of data to client LPT ports during a Remote Desktop Services session.

    The recommended state for this setting is: Enabled .

    Rationale: In a more security-sensitive environment, it is desirable to reduce the possible attack surface. The need for LPT port redirection within a Remote Desktop session is very rare, so makes sense to reduce the number of unexpected avenues for data exfiltration and/or malicious code transfer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableLPT' }
    its('fDisableLPT') { should cmp == 1 }
  end
end

control '18.9.62.3.3.4_L2_Ensure_Do_not_allow_supported_Plug_and_Play_device_redirection_is_set_to_Enabled' do
  title "(L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control the redirection of supported Plug and Play devices, such as Windows Portable Devices, to the remote computer in a Remote Desktop Services session.

    The recommended state for this setting is: Enabled .

    Rationale: In a more security-sensitive environment, it is desirable to reduce the possible attack surface. The need for Plug and Play device redirection within a Remote Desktop session is very rare, so makes sense to reduce the number of unexpected avenues for data exfiltration and/or malicious code transfer.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisablePNPRedir' }
    its('fDisablePNPRedir') { should cmp == 1 }
  end
end

control '18.9.63.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled' do
  title "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether Remote Desktop Services always prompts the client computer for a password upon connection. You can use this policy setting to enforce a password prompt for users who log on to Remote Desktop Services, even if they already provided the password in the Remote Desktop Connection client.

    The recommended state for this setting is: Enabled .

    Rationale: Users have the option to store both their username and password when they create a new Remote Desktop Connection shortcut. If the server that runs Remote Desktop Services allows users who have used this feature to log on to the server but not enter their password, then it is possible that an attacker who has gained physical access to the user's computer could connect to a Remote Desktop Server through the Remote Desktop Connection shortcut, even though they may not know the user's password.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should cmp == 1 }
  end
end

control '18.9.63.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled' do
  title "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to specify whether Remote Desktop Services requires secure Remote Procedure Call (RPC) communication with all clients or allows unsecured communication.

    You can use this policy setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.

    The recommended state for this setting is: Enabled .

    Rationale: Allowing unsecure RPC communication can exposes the server to man in the middle attacks and data disclosure attacks.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should cmp == 1 }
  end
end

control '18.9.63.3.9.3_L1_Ensure_Require_use_of_specific_security_layer_for_remote_RDP_connections_is_set_to_Enabled_SSL' do
  title "(L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
  desc  "
    This policy setting specifies whether to require the use of a specific security layer to secure communications between clients and RD Session Host servers during Remote Desktop Protocol (RDP) connections.

    The recommended state for this setting is: Enabled: SSL .

    **Note:** In spite of this setting being labeled **SSL** , it is actually enforcing Transport Layer Security (TLS) version 1.0, not the older (and less secure) SSL protocol.

    Rationale: The native Remote Desktop Protocol (RDP) encryption is now considered a weak protocol, so enforcing the use of stronger Transport Layer Security (TLS) encryption for all RDP communications between clients and RD Session Host servers is preferred.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'SecurityLayer' }
    its('SecurityLayer') { should cmp == 2 }
  end
end

control '18.9.63.3.9.4_L1_Ensure_Require_user_authentication_for_remote_connections_by_using_Network_Level_Authentication_is_set_to_Enabled' do
  title "(L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to specify whether to require user authentication for remote connections to the RD Session Host server by using Network Level Authentication.

    The recommended state for this setting is: Enabled .

    Rationale: Requiring that user authentication occur earlier in the remote connection process enhances security.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'UserAuthentication' }
    its('UserAuthentication') { should cmp == 1 }
  end
end

control '18.9.62.3.9.5_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level' do
  title "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc  "
    This policy setting specifies whether to require the use of a specific encryption level to secure communications between client computers and RD Session Host servers during Remote Desktop Protocol (RDP) connections. This policy only applies when you are using native RDP encryption. However, native RDP encryption (as opposed to SSL encryption) is not recommended. This policy does not apply to SSL encryption.

    The recommended state for this setting is: Enabled: High Level .

    Rationale: If Remote Desktop client connections that use low level encryption are allowed, it is more likely that an attacker will be able to decrypt any captured Remote Desktop Services network traffic.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should cmp == 3 }
  end
end

control '18.9.63.3.10.1_L2_Ensure_Set_time_limit_for_active_but_idle_Remote_Desktop_Services_sessions_is_set_to_Enabled_15_minutes_or_less' do
  title "(L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
  desc  "
    This policy setting allows you to specify the maximum amount of time that an active Remote Desktop Services session can be idle (without user input) before it is automatically disconnected.

    The recommended state for this setting is: Enabled: 15 minutes or less .

    Rationale: This setting helps to prevent active Remote Desktop sessions from tying up the computer for long periods of time while not in use, preventing computing resources from being consumed by large numbers of inactive sessions. In addition, old, forgotten Remote Desktop sessions that are still active can cause password lockouts if the user's password has changed but the old session is still running. For systems that limit the number of connected users (e.g. servers in the default Administrative mode - 2 sessions only), other users' old but still active sessions can prevent another user from connecting, resulting in an effective denial of service.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should cmp <= 900000 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MaxIdleTime' }
    its('MaxIdleTime') { should cmp != 0 }
  end
end

control '18.9.63.3.10.2_L2_Ensure_Set_time_limit_for_disconnected_sessions_is_set_to_Enabled_1_minute' do
  title "(L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
  desc  "
    This policy setting allows you to configure a time limit for disconnected Remote Desktop Services sessions.

    The recommended state for this setting is: Enabled: 1 minute .

    Rationale: This setting helps to prevent active Remote Desktop sessions from tying up the computer for long periods of time while not in use, preventing computing resources from being consumed by large numbers of disconnected but still active sessions. In addition, old, forgotten Remote Desktop sessions that are still active can cause password lockouts if the user's password has changed but the old session is still running. For systems that limit the number of connected users (e.g. servers in the default Administrative mode - 2 sessions only), other users' old but still active sessions can prevent another user from connecting, resulting in an effective denial of service. This setting is important to ensure a disconnected session is properly terminated.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'MaxDisconnectionTime' }
    its('MaxDisconnectionTime') { should cmp == 60000 }
  end
end

control '18.9.63.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled' do
  title "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Remote Desktop Services retains a user's per-session temporary folders at logoff.

    The recommended state for this setting is: Disabled .

    Rationale: Sensitive information could be contained inside the temporary folders and visible to other administrators that log into the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'DeleteTempDirsOnExit' }
    its('DeleteTempDirsOnExit') { should cmp == 1 }
  end
end

control '18.9.64.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc  "
    This policy setting prevents the user from having enclosures (file attachments) downloaded from an RSS feed to the user's computer.

    The recommended state for this setting is: Enabled .

    Rationale: Allowing attachments to be downloaded through the RSS feed can introduce files that could have malicious intent.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should cmp == 1 }
  end
end

control '18.9.65.2_L2_Ensure_Allow_Cloud_Search_is_set_to_Enabled_Disable_Cloud_Search' do
  title "(L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
  desc  "
    This policy setting allows search and Cortana to search cloud sources like OneDrive and SharePoint.

    The recommended state for this setting is: Enabled: Disable Cloud Search .

    Rationale: Due to privacy concerns, data should never be sent to any 3rd party since this data could contain sensitive information.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
      it { should have_property 'AllowCloudSearch' }
      its('AllowCloudSearch') { should cmp == 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
      it { should_not have_property 'AllowCloudSearch' }
    end
  end
end

control '18.9.65.3_L1_Ensure_Allow_Cortana_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow Cortana' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Cortana is allowed on the device.

    The recommended state for this setting is: Disabled .

    Rationale: If Cortana is enabled, sensitive information could be contained in search history and sent out to Microsoft.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowCortana' }
    its('AllowCortana') { should cmp == 0 }
  end
end

control '18.9.65.4_L1_Ensure_Allow_Cortana_above_lock_screen_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled'"
  desc  "
    This policy setting determines whether or not the user can interact with Cortana using speech while the system is locked.

    The recommended state for this setting is: Disabled .

    Rationale: Access to any computer resource should not be allowed when the device is locked.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowCortanaAboveLock' }
    its('AllowCortanaAboveLock') { should cmp == 0 }
  end
end

control '18.9.65.5_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc  "
    This policy setting controls whether encrypted items are allowed to be indexed. When this setting is changed, the index is rebuilt completely. Full volume encryption (such as BitLocker Drive Encryption or a non-Microsoft solution) must be used for the location of the index to maintain security for encrypted files.

    The recommended state for this setting is: Disabled .

    Rationale: Indexing and allowing users to search encrypted files could potentially reveal confidential data stored within the encrypted files.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
    its('AllowIndexingEncryptedStoresOrItems') { should cmp == 0 }
  end
end

control '18.9.65.6_L1_Ensure_Allow_search_and_Cortana_to_use_location_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether search and Cortana can provide location aware search and Cortana results.

    The recommended state for this setting is: Disabled .

    Rationale: In an enterprise managed environment, allowing Cortana and Search to have access to location data is unnecessary. Organizations likely do not want this information shared out.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search') do
    it { should have_property 'AllowSearchToUseLocation' }
    its('AllowSearchToUseLocation') { should cmp == 0 }
  end
end

control '18.9.70.1_L2_Ensure_Turn_off_KMS_Client_Online_AVS_Validation_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
  desc  "
    The Key Management Service (KMS) is a Microsoft license activation method that entails setting up a local server to store the software licenses. The KMS server itself needs to connect to Microsoft to activate the KMS service, but subsequent on-network clients can activate Microsoft Windows OS and/or their Microsoft Office via the KMS server instead of connecting directly to Microsoft. This policy setting lets you opt-out of sending KMS client activation data to Microsoft automatically.

    The recommended state for this setting is: Enabled .

    Rationale: Even though the KMS licensing method does not **require** KMS clients to connect to Microsoft, they still send KMS client activation state data to Microsoft automatically. Preventing this information from being sent can help reduce privacy concerns in high security environments.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform') do
    it { should have_property 'NoGenTicket' }
    its('NoGenTicket') { should cmp == 1 }
  end
end

control '18.9.73.1_L2_Ensure_Disable_all_apps_from_Microsoft_Store_is_set_to_Disabled' do
  title "(L2) Ensure 'Disable all apps from Microsoft Store' is set to 'Disabled'"
  desc  "
    This setting configures the launch of all apps from the Microsoft Store that came pre-installed or were downloaded.

    The recommended state for this setting is: Disabled .

    **Note:** This policy setting only applies to Windows 10 Enterprise and Windows 10 Education editions.

    **Note #2:** The name of this setting and the Enabled/Disabled values are incorrectly worded &#x2013; logically, the title implies that configuring it to Enabled will disable all apps from the Microsoft Store, and configuring it to Disabled will enable all apps from the Microsoft Store. The opposite is true (and is consistent with the GPME help text). This is a logical wording mistake by Microsoft in the Administrative Template.

    Rationale: The Store service is a retail outlet built into Windows, primarily for consumer use. In an enterprise managed environment the IT department should be managing the installation of all applications to reduce the risk of the installation of vulnerable software.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'DisableStoreApps' }
    its('DisableStoreApps') { should cmp == 1 }
  end
end

control '18.9.73.2_L1_Ensure_Only_display_the_private_store_within_the_Microsoft_Store_is_set_to_Enabled' do
  title "(L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'"
  desc  "
    This policy setting denies access to the retail catalog in the Microsoft Store, but displays the private store.

    The recommended state for this setting is: Enabled .

    Rationale: Allowing the private store will allow an organization to control the apps that users have access to add to a system.  This will help ensure that unapproved malicious apps are not running on a system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'RequirePrivateStoreOnly' }
    its('RequirePrivateStoreOnly') { should cmp == 1 }
  end
end

control '18.9.73.3_L1_Ensure_Turn_off_Automatic_Download_and_Install_of_updates_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
  desc  "
    This setting enables or disables the automatic download and installation of Microsoft Store app updates.

    The recommended state for this setting is: Disabled .

    Rationale: Keeping your system properly patched can help protect against 0 day vulnerabilities.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'AutoDownload' }
    its('AutoDownload') { should cmp == 4 }
  end
end

control '18.9.73.4_L1_Ensure_Turn_off_the_offer_to_update_to_the_latest_version_of_Windows_is_set_to_Enabled' do
  title "(L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
  desc  "
    Enables or disables the Microsoft Store offer to update to the latest version of Windows.

    The recommended state for this setting is: Enabled .

    Rationale: Unplanned OS upgrades can lead to more preventable support calls. The IT department should be managing and approving all upgrades and updates.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'DisableOSUpgrade' }
    its('DisableOSUpgrade') { should cmp == 1 }
  end
end

control '18.9.73.5_L2_Ensure_Turn_off_the_Store_application_is_set_to_Enabled' do
  title "(L2) Ensure 'Turn off the Store application' is set to 'Enabled'"
  desc  "
    This setting denies or allows access to the Store application.

    The recommended state for this setting is: Enabled .

    **Note:**[Per Microsoft TechNet](https://technet.microsoft.com/en-us/itpro/windows/manage/group-policies-for-enterprise-and-education-editions) and [MSKB 3135657](https://support.microsoft.com/en-us/help/3135657/can-t-disable-windows-store-in-windows-10-pro-through-group-policy) , this policy setting does not apply to any Windows 10 editions other than Enterprise and Education.

    Rationale: Only applications approved by an IT department should be installed. Allowing users to install 3rd party applications can lead to missed patches and potential zero day vulnerabilities.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'RemoveWindowsStore' }
    its('RemoveWindowsStore') { should cmp == 1 }
  end
end

control '18.9.81.1.1_L1_Ensure_Configure_Windows_Defender_SmartScreen_is_set_to_Enabled_Warn_and_prevent_bypass' do
  title "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
  desc  "
    This policy setting allows you to manage the behavior of Windows Defender SmartScreen. Windows Defender SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.

    The recommended state for this setting is: Enabled: Warn and prevent bypass .

    Rationale: Windows Defender SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. However, due to the fact that some information is sent to Microsoft about files and programs run on PCs some organizations may prefer to disable it.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'ShellSmartScreenLevel' }
    its('ShellSmartScreenLevel') { should eq 'Block' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableSmartScreen' }
    its('EnableSmartScreen') { should cmp == 1 }
  end
end

control '18.9.81.2.1_L1_Ensure_Configure_Windows_Defender_SmartScreen_is_set_to_Enabled' do
  title "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'"
  desc  "
    This setting lets you decide whether to turn on SmartScreen Filter. SmartScreen Filter provides warning messages to help protect your employees from potential phishing scams and malicious software.

    The recommended state for this setting is: Enabled .

    Rationale: SmartScreen serves an important purpose as it helps to warn users of possible malicious sites and files. Allowing users to turn off this setting can make the browser become more vulnerable to compromise.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter') do
    it { should have_property 'EnabledV9' }
    its('EnabledV9') { should cmp == 1 }
  end
end

control '18.9.81.2.2_L1_Ensure_Prevent_bypassing_Windows_Defender_SmartScreen_prompts_for_sites_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled'"
  desc  "
    This setting lets you decide whether employees can override the SmartScreen Filter warnings about potentially malicious websites.

    The recommended state for this setting is: Enabled .

    Rationale: SmartScreen will warn an employee if a website is potentially malicious. Enabling this setting prevents these warnings from being bypassed.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter') do
    it { should have_property 'PreventOverride' }
    its('PreventOverride') { should cmp == 1 }
  end
end

control '18.9.83.1_L1_Ensure_Enables_or_disables_Windows_Game_Recording_and_Broadcasting_is_set_to_Disabled' do
  title "(L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
  desc  "
    This setting enables or disables the Windows Game Recording and Broadcasting features.

    The recommended state for this setting is: Disabled .

    Rationale: If this setting is allowed users could record and broadcast session info to external sites which is a privacy concern.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR') do
    it { should have_property 'AllowGameDVR' }
    its('AllowGameDVR') { should cmp == 0 }
  end
end

control '18.9.85.1_L2_Ensure_Allow_suggested_apps_in_Windows_Ink_Workspace_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
  desc  "
    This policy setting determines whether suggested apps in Windows Ink Workspace are allowed.

    The recommended state for this setting is: Disabled .

    Rationale: This Microsoft feature is designed to collect data and suggest apps based on that data collected. Disabling this setting will help ensure your data is not shared with any third party.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
    it { should have_property 'AllowSuggestedAppsInWindowsInkWorkspace' }
    its('AllowSuggestedAppsInWindowsInkWorkspace') { should cmp == 0 }
  end
end

control '18.9.84.2_L1_Ensure_Allow_Windows_Ink_Workspace_is_set_to_Enabled_On_but_disallow_access_above_lock_OR_Disabled_but_not_Enabled_On' do
  title "(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
  desc  "
    This policy setting determines whether Windows Ink items are allowed above the lock screen.

    The recommended state for this setting is: Enabled: On, but disallow access above lock OR Disabled .

    Rationale: Allowing any apps to be accessed while system is locked is not recommended. If this feature is permitted, it should only be accessible once a user authenticates with the proper credentials.
  "
  impact 1.0
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp == 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp == 0 }
    end
  end
end

control '18.9.86.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc  "
    This setting controls whether users are permitted to change installation options that typically are available only to system administrators. The security features of Windows Installer normally prevent users from changing installation options that are typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.

    The recommended state for this setting is: Disabled .

    Rationale: In an enterprise managed environment, only IT staff with administrative rights should be installing or changing software on a system. Allowing users the ability to have any control over installs can risk unapproved software from being installed or removed from a system, which could cause the system to become vulnerable to compromise.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should cmp == 0 }
  end
end

control '18.9.86.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled' do
  title "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  "
    This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.

    **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.

    **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.

    The recommended state for this setting is: Disabled .

    Rationale: Users with limited privileges can exploit this feature by creating a Windows Installer installation package that creates a new local account that belongs to the local built-in Administrators group, adds their current account to the local built-in Administrators group, installs malicious software, or performs other unauthorized activities.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should cmp == 0 }
  end
end

control '18.9.86.3_L2_Ensure_Prevent_Internet_Explorer_security_prompt_for_Windows_Installer_scripts_is_set_to_Disabled' do
  title "(L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
  desc  "
    This policy setting controls whether Web-based programs are allowed to install software on the computer without notifying the user.

    The recommended state for this setting is: Disabled .

    Rationale: Suppressing the system warning can pose a security risk and increase the attack surface on the system.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'SafeForScripting' }
    its('SafeForScripting') { should cmp == 0 }
  end
end

control '18.9.87.1_L1_Ensure_Sign-in_and_lock_last_interactive_user_automatically_after_a_restart_is_set_to_Disabled' do
  title "(L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
  desc  "
    This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system.

    The recommended state for this setting is: Disabled .

    Rationale: Disabling this feature will prevent the caching of user's credentials and unauthorized use of the device, and also ensure the user is aware of the restart.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'DisableAutomaticRestartSignOn' }
    its('DisableAutomaticRestartSignOn') { should cmp == 1 }
  end
end

control '18.9.96.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
  desc  "
    This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log.

    The recommended state for this setting is: Disabled .

    **Note:** In Microsoft's own hardening guidance, they recommend the opposite value, Enabled , because having this data logged improves investigations of PowerShell attack incidents. However, the default ACL on the PowerShell Operational log allows Interactive User (i.e. **any** logged on user) to read it, and therefore possibly expose passwords or other sensitive information to unauthorized users. If Microsoft locks down the default ACL on that log in the future (e.g. to restrict it only to Administrators), then we will revisit this recommendation in a future release.

    Rationale: There are potential risks of capturing passwords in the PowerShell logs. This setting should only be needed for debugging purposes, and not in normal operation, it is important to ensure this is set to Disabled .
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    it { should have_property 'EnableScriptBlockLogging' }
    its('EnableScriptBlockLogging') { should cmp == 0 }
  end
end

control '18.9.96.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled' do
  title "(L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
  desc  "
    This Policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts.

    The recommended state for this setting is: Disabled .

    Rationale: If this setting is enabled there is a risk that passwords could get stored in plain text in the PowerShell_transcript output file.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription') do
    it { should have_property 'EnableTranscripting' }
    its('EnableTranscripting') { should cmp == 0 }
  end
end

control '18.9.98.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Basic authentication.

    The recommended state for this setting is: Disabled .

    **Note:** Clients that use Microsoft's Exchange Online service (Office 365) will require an exception to this recommendation, to instead have this setting set to Enabled. Exchange Online uses Basic authentication over HTTPS, and so the Exchange Online authentication traffic will still be safely encrypted.

    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp == 0 }
  end
end

control '18.9.98.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client sends and receives unencrypted messages over the network.

    The recommended state for this setting is: Disabled .

    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end

control '18.9.98.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled' do
  title "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client will not use Digest authentication.

    The recommended state for this setting is: Enabled .

    Rationale: Digest authentication is less robust than other authentication methods available in WinRM, an attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should cmp == 0 }
  end
end

control '18.9.98.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.

    The recommended state for this setting is: Disabled .

    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp == 0 }
  end
end

control '18.9.98.2.2_L2_Ensure_Allow_remote_server_management_through_WinRM_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service automatically listens on the network for requests on the HTTP transport over the default HTTP port.

    The recommended state for this setting is: Disabled .

    Rationale: Any feature is a potential avenue of attack, those that enable inbound network connections are particularly risky. Only enable the use of the Windows Remote Management (WinRM) service on trusted networks and when feasible employ additional controls such as IPsec.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowAutoConfig' }
    its('AllowAutoConfig') { should cmp == 0 }
  end
end

control '18.9.98.2.3_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled' do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.

    The recommended state for this setting is: Disabled .

    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end

control '18.9.98.2.4_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled' do
  title "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will allow RunAs credentials to be stored for any plug-ins.

    The recommended state for this setting is: Enabled .

    **Note:** If you enable and then disable this policy setting, any values that were previously configured for RunAsPassword will need to be reset.

    Rationale: Although the ability to store RunAs credentials is a convenient feature it increases the risk of account compromise slightly. For example, if you forget to lock your desktop before leaving it unattended for a few minutes another person could access not only the desktop of your computer but also any hosts you manage via WinRM with cached RunAs credentials.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should cmp == 1 }
  end
end

control '18.9.99.1_L2_Ensure_Allow_Remote_Shell_Access_is_set_to_Disabled' do
  title "(L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage configuration of remote access to all supported shells to execute scripts and commands.

    The recommended state for this setting is: Disabled .

    **Note:** The GPME help text for this setting is incorrectly worded, implying that configuring it to Enabled will reject new Remote Shell connections, and setting it to Disabled will allow Remote Shell connections. The opposite is true (and is consistent with the title of the setting). This is a wording mistake by Microsoft in the Administrative Template.

    Rationale: Any feature is a potential avenue of attack, those that enable inbound network connections are particularly risky. Only enable the use of the Windows Remote Shell on trusted networks and when feasible employ additional controls such as IPsec.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS') do
    it { should have_property 'AllowRemoteShellAccess' }
    its('AllowRemoteShellAccess') { should cmp == 0 }
  end
end

control '18.9.100.2.1_L1_Ensure_Prevent_users_from_modifying_settings_is_set_to_Enabled' do
  title "(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
  desc  "
    This policy setting prevent users from making changes to the Exploit protection settings area in the Windows Security settings.

    The recommended state for this setting is: Enabled .

    Rationale: Only authorized IT staff should be able to make changes to the exploit protection settings in order to ensure the organizations specific configuration is not modified.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection') do
    it { should have_property 'DisallowExploitProtectionOverride' }
    its('DisallowExploitProtectionOverride') { should cmp == 1 }
  end
end

control '18.9.103.1.1_L1_Ensure_Manage_preview_builds_is_set_to_Enabled_Disable_preview_builds' do
  title "(L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
  desc  "
    This policy setting determines whether users can access the Windows Insider Program controls in Settings -&gt; Update and Security. These controls enable users to make their devices available for downloading and installing preview (beta) builds of Windows software.

    The recommended state for this setting is: Enabled: Disable preview builds .

    Rationale: It can be risky for experimental features to be allowed in an enterprise managed environment because this can introduce bugs and security holes into systems, making it easier for an attacker to gain access. It is generally preferred to only use production-ready builds.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'ManagePreviewBuilds' }
    its('ManagePreviewBuilds') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'ManagePreviewBuildsPolicyValue' }
    its('ManagePreviewBuildsPolicyValue') { should cmp == 0 }
  end
end

control '18.9.103.1.2_L1_Ensure_Select_when_Preview_Builds_and_Feature_Updates_are_received_is_set_to_Enabled_Semi-Annual_Channel_180_or_more_days' do
  title "(L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
  desc  "
    This policy setting determines the level of Preview Build or Feature Updates to receive, and when.

    The Windows readiness level for each new Windows 10 Feature Update is classified in one of 5 categories, depending on your organizations level of comfort with receiving them:

    * **Preview Build - Fast:** Devices set to this level will be the first to receive new builds of Windows with features not yet available to the general public. Select Fast to participate in identifying and reporting issues to Microsoft, and provide suggestions on new functionality.

    * **Preview Build - Slow:** Devices set to this level receive new builds of Windows before they are available to the general public, but at a slower cadence than those set to Fast, and with changes and fixes identified in earlier builds.

    * **Release Preview:** Receive builds of Windows just before Microsoft releases them to the general public.

    * **Semi-Annual Channel (Targeted):** Receive feature updates when they are released to the general public.

    * **Semi-Annual Channel:** Feature updates will arrive when they are declared Semi-Annual Channel. This usually occurs about 4 months after Semi-Annual Channel (Targeted), indicating that Microsoft, Independent Software Vendors (ISVs), partners and customer believe that the release is ready for broad deployment.

    The recommended state for this setting is: Enabled: Semi-Annual Channel, 180 or more days .

    **Note:** If the \"Allow Telemetry\" policy is set to 0, this policy will have no effect.

    **Note #2:** Starting with Windows 10 R1607, Microsoft introduced a new Windows Update (WU) client behavior called **Dual Scan** , with an eye to cloud-based update management. In some cases, this Dual Scan feature can interfere with Windows Updates from Windows Server Update Services (WSUS) and/or manual WU updates. If you are using WSUS in your environment, you may need to set the above setting to Not Configured**or** configure the setting **Do not allow update deferral policies to cause scans against Windows Update** (added in the Windows 10 Release 1709 Administrative Templates) in order to prevent the Dual Scan feature from interfering. More information on Dual Scan is available at these links:

    * [Demystifying &#x201C;Dual Scan&#x201D; &#x2013; WSUS Product Team Blog](https://blogs.technet.microsoft.com/wsus/2017/05/05/demystifying-dual-scan/)
    * [Improving Dual Scan on 1607 &#x2013; WSUS Product Team Blog](https://blogs.technet.microsoft.com/wsus/2017/08/04/improving-dual-scan-on-1607/)
    **Note #3:** Prior to Windows 10 R1703, values above 180 days are not recognized by the OS. Starting with Windows 10 R1703, the maximum number of days you can defer is 365 days.

    Rationale: Forcing new features without prior testing in your environment could cause software incompatibilities as well as introducing new bugs into the operating system. In an enterprise managed environment, it is generally preferred to delay Feature Updates until thorough testing and a deployment plan is in place. This recommendation delays the **automatic** installation of new features as long as possible.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'DeferFeatureUpdates' }
    its('DeferFeatureUpdates') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'BranchReadinessLevel' }
    its('BranchReadinessLevel') { should cmp == 16 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'DeferFeatureUpdatesPeriodInDays' }
    its('DeferFeatureUpdatesPeriodInDays') { should cmp >= 180 }
  end
end

control '18.9.103.1.3_L1_Ensure_Select_when_Quality_Updates_are_received_is_set_to_Enabled_0_days' do
  title "(L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
  desc  "
    This settings controls when Quality Updates are received.

    The recommended state for this setting is: Enabled: 0 days .

    **Note:** If the \"Allow Telemetry\" policy is set to 0, this policy will have no effect.

    **Note #2:** Starting with Windows 10 R1607, Microsoft introduced a new Windows Update (WU) client behavior called **Dual Scan** , with an eye to cloud-based update management. In some cases, this Dual Scan feature can interfere with Windows Updates from Windows Server Update Services (WSUS) and/or manual WU updates. If you are using WSUS in your environment, you may need to set the above setting to Not Configured**or** configure the setting **Do not allow update deferral policies to cause scans against Windows Update** (added in the Windows 10 Release 1709 Administrative Templates) in order to prevent the Dual Scan feature from interfering. More information on Dual Scan is available at these links:

    * [Demystifying &#x201C;Dual Scan&#x201D; &#x2013; WSUS Product Team Blog](https://blogs.technet.microsoft.com/wsus/2017/05/05/demystifying-dual-scan/)
    * [Improving Dual Scan on 1607 &#x2013; WSUS Product Team Blog](https://blogs.technet.microsoft.com/wsus/2017/08/04/improving-dual-scan-on-1607/)

    Rationale: Quality Updates can contain important bug fixes and/or security patches, and should be installed as soon as possible.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'DeferQualityUpdates' }
    its('DeferQualityUpdates') { should cmp == 1 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'DeferQualityUpdatesPeriodInDays' }
    its('DeferQualityUpdatesPeriodInDays') { should cmp == 0 }
  end
end

control '18.9.103.2_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled' do
  title "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.

    After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:

    *  2 - Notify for download and auto install **(Notify before downloading any updates)**
    *  3 - Auto download and notify for install **(Download the updates automatically and notify when they are ready to be installed.) (Default setting)**
    *  4 - Auto download and schedule the install **(Automatically download updates and install them on the schedule specified below.))**
    *  5 - Allow local admin to choose setting **(Leave decision on above choices up to the local Administrators (Not Recommended))**
    The recommended state for this setting is: Enabled .

    **Note:** The sub-setting \" **Configure automatic updating:** \" has 4 possible values &#x2013; all of them are valid depending on specific organizational needs, however if feasible we suggest using a value of 4 - Auto download and schedule the install . This suggestion is not a scored requirement.

    **Note #2:** Organizations that utilize a 3rd-party solution for patching may choose to exempt themselves from this recommendation, and instead configure it to Disabled so that the native Windows Update mechanism does not interfere with the 3rd-party patching process.

    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should have_property 'NoAutoUpdate' }
    its('NoAutoUpdate') { should cmp == 0 }
  end
end

control '18.9.103.3_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day' do
  title "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc  "
    This policy setting specifies when computers in your environment will receive security updates from Windows Update or WSUS.

    The recommended state for this setting is: 0 - Every day .

    **Note:** This setting is only applicable if 4 - Auto download and schedule the install is selected in Rule 18.9.102.2. It will have no impact if any other option is selected.

    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should have_property 'ScheduledInstallDay' }
    its('ScheduledInstallDay') { should cmp == 0 }
  end
end

control '18.9.103.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled' do
  title "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
  desc  "
    This policy setting specifies that Automatic Updates will wait for computers to be restarted by the users who are logged on to them to complete a scheduled installation.

    The recommended state for this setting is: Disabled .

    **Note:** This setting applies only when you configure Automatic Updates to perform scheduled update installations. If you configure the Configure Automatic Updates setting to Disabled, this setting has no effect.

    Rationale: Some security updates require that the computer be restarted to complete an installation. If the computer cannot restart automatically, then the most recent update will not completely install and no new updates will download to the computer until it is restarted. Without the auto-restart functionality, users who are not security-conscious may choose to indefinitely delay the restart, therefore keeping the computer in a less secure state.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    it { should have_property 'NoAutoRebootWithLoggedOnUsers' }
    its('NoAutoRebootWithLoggedOnUsers') { should cmp == 0 }
  end
end

control '18.9.103.5_L1_Ensure_Remove_access_to_Pause_updates_feature_is_set_to_Enabled' do
  title "(L1) Ensure 'Remove access to &#x201C;Pause updates&#x201D; feature' is set to 'Enabled'"
  desc  "
    This policy removes access to \"Pause updates\" feature.

    The recommended state for this setting is: Enabled .

    Rationale: In order to ensure security and system updates are applied, system administrators should control when updates are applied to systems.
  "
  impact 1.0
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    it { should have_property 'SetDisablePauseUXAccess' }
    its('SetDisablePauseUXAccess') { should cmp == 1 }
  end
end
