# encoding: UTF-8

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords" do
  title "(L1) Ensure 'Enforce password history' is set to '24 or more password(s)'"
  desc  "
    This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password. The value for this policy setting must be between 0 and 24 passwords. The default value for Windows Vista is 0 passwords, but the default setting in a domain is 24 passwords. To maintain the effectiveness of this policy setting, use the Minimum password age setting to prevent users from repeatedly changing their password.
    
    The recommended state for this setting is: 24 or more password(s).
    
    Rationale: The longer a user uses the same password, the greater the chance that an attacker can determine the password through brute force attacks. Also, any accounts that may have been compromised will remain exploitable for as long as the password is left unchanged. If password changes are required but password reuse is not prevented, or if users continually reuse a small number of passwords, the effectiveness of a good password policy is greatly reduced.
    
    If you specify a low number for this policy setting, users will be able to use the same small number of passwords repeatedly. If you do not also configure the Minimum password age setting, users might repeatedly change their passwords until they can reuse their original password.
  "
  impact 1.0
  tag cce: "CCE-35219-5"
  describe security_policy do
    its("PasswordHistorySize") { should be >= 24 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2_L1_Ensure_Maximum_password_age_is_set_to_60_or_fewer_days_but_not_0" do
  title "(L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'"
  desc  "
    This policy setting defines how long a user can use their password before it expires.
    
    Values for this policy setting range from 0 to 999 days. If you set the value to 0, the password will never expire.
    
    Because attackers can crack passwords, the more frequently you change the password the less opportunity an attacker has to use a cracked password. However, the lower this value is set, the higher the potential for an increase in calls to help desk support due to users having to change their password or forgetting which password is current.
    
    The recommended state for this setting is 60 or fewer days, but not 0.
    
    Rationale: The longer a password exists the higher the likelihood that it will be compromised by a brute force attack, by an attacker gaining general knowledge about the user, or by the user sharing the password. Configuring the Maximum password age setting to 0 so that users are never required to change their passwords is a major security risk because that allows a compromised password to be used by the malicious user for as long as the valid user is authorized access.
  "
  impact 1.0
  tag cce: "CCE-34907-6"
  describe security_policy do
    its("MaximumPasswordAge") { should be <= 60 }
  end
  describe security_policy do
    its("MaximumPasswordAge") { should be > 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3_L1_Ensure_Minimum_password_age_is_set_to_1_or_more_days" do
  title "(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'"
  desc  "
    This policy setting determines the number of days that you must use a password before you can change it. The range of values for this policy setting is between 1 and 999 days. (You may also set the value to 0 to allow immediate password changes.) The default value for this setting is 0 days.
    
    The recommended state for this setting is: 1 or more day(s)).
    
    Rationale: Users may have favorite passwords that they like to use because they are easy to remember and they believe that their password choice is secure from compromise. Unfortunately, passwords are compromised and if an attacker is targeting a specific individual user account, with foreknowledge of data about that user, reuse of old passwords can cause a security breach. To address password reuse a combination of security settings is required. Using this policy setting with the Enforce password history setting prevents the easy reuse of old passwords. For example, if you configure the Enforce password history setting to ensure that users cannot reuse any of their last 12 passwords, they could change their password 13 times in a few minutes and reuse the password they started with, unless you also configure the Minimum password age setting to a number that is greater than 0. You must configure this policy setting to a number that is greater
     than 0 for the Enforce password history setting to be effective.
  "
  impact 1.0
  tag cce: "CCE-35366-4"
  describe security_policy do
    its("MinimumPasswordAge") { should be >= 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4_L1_Ensure_Minimum_password_length_is_set_to_14_or_more_characters" do
  title "(L1) Ensure 'Minimum password length' is set to '14 or more character(s)'"
  desc  "
    This policy setting determines the least number of characters that make up a password for a user account. There are many different theories about how to determine the best password length for an organization, but perhaps \"pass phrase\" is a better term than \"password.\" In Microsoft Windows 2000 or later, pass phrases can be quite long and can include spaces. Therefore, a phrase such as \"I want to drink a $5 milkshake\" is a valid pass phrase; it is a considerably stronger password than an 8 or 10 character string of random numbers and letters, and yet is easier to remember. Users must be educated about the proper selection and maintenance of passwords, especially with regard to password length.
    
    The recommended state for this setting is: 14 or more character(s).
    
    Rationale: Types of password attacks include dictionary attacks (which attempt to use common words and phrases) and brute force attacks (which try every possible combination of characters). Also, attackers sometimes try to obtain the account database so they can use tools to discover the accounts and passwords.
  "
  impact 1.0
  tag cce: "CCE-33789-9"
  describe security_policy do
    its("MinimumPasswordLength") { should be >= 14 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5_L1_Ensure_Password_must_meet_complexity_requirements_is_set_to_Enabled" do
  title "(L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
  desc  "
    This policy setting checks all new passwords to ensure that they meet basic requirements for strong passwords.
    
    When this policy is enabled, passwords must meet the following minimum requirements:
    - Not contain the user's account name or parts of the user's full name that exceed two consecutive characters
    - Be at least six characters in length
    - Contain characters from three of the following four categories:
    - English uppercase characters (A through Z)
    - English lowercase characters (a through z)
    - Base 10 digits (0 through 9)
    - Non-alphabetic characters (for example, !, $, #, %)
    - A catch-all category of any Unicode character that does not fall under the previous four categories. This fifth category can be regionally specific.
    
    Each additional character in a password increases its complexity exponentially. For instance, a seven-character, all lower-case alphabetic password would have 267 (approximately 8 x 109 or 8 billion) possible combinations. At 1,000,000 attempts per second (a capability of many password-cracking utilities), it would only take 133 minutes to crack. A seven-character alphabetic password with case sensitivity has 527 combinations. A seven-character case-sensitive alphanumeric password without punctuation has 627 combinations. An eight-character password has 268 (or 2 x 1011) possible combinations. Although this might seem to be a large number, at 1,000,000 attempts per second it would take only 59 hours to try all possible passwords. Remember, these times will significantly increase for passwords that use ALT characters and other special keyboard characters such as \"!\" or \"@\". Proper use of the password settings can help make it
     difficult to mount a brute force attack.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Passwords that contain only alphanumeric characters are extremely easy to discover with several publicly available tools.
  "
  impact 1.0
  tag cce: "CCE-33777-4"
  describe security_policy do
    its("PasswordComplexity") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6_L1_Ensure_Store_passwords_using_reversible_encryption_is_set_to_Disabled" do
  title "(L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
  desc  "
    This policy setting determines whether the operating system stores passwords in a way that uses reversible encryption, which provides support for application protocols that require knowledge of the user's password for authentication purposes. Passwords that are stored with reversible encryption are essentially the same as plaintext versions of the passwords.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Enabling this policy setting allows the operating system to store passwords in a weaker format that is much more susceptible to compromise and weakens your system security.
  "
  impact 1.0
  tag cce: "CCE-35370-6"
  describe security_policy do
    its("ClearTextPassword") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.1_L1_Ensure_Account_lockout_duration_is_set_to_15_or_more_minutes" do
  title "(L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
  desc  "
    This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again. The setting does this by specifying the number of minutes a locked out account will remain unavailable. If the value for this policy setting is configured to 0, locked out accounts will remain locked out until an administrator manually unlocks them.
    
    Although it might seem like a good idea to configure the value for this policy setting to a high value, such a configuration will likely increase the number of calls that the help desk receives to unlock accounts locked by mistake. Users should be aware of the length of time a lock remains in place, so that they realize they only need to call the help desk if they have an extremely urgent need to regain access to their computer.
    
    The recommended state for this setting is: 15 or more minute(s).
    
    Rationale: A denial of service (DoS) condition can be created if an attacker abuses the Account lockout threshold and repeatedly attempts to log on with a specific account. Once you configure the Account lockout threshold setting, the account will be locked out after the specified number of failed attempts. If you configure the Account lockout duration setting to 0, then the account will remain locked out until an administrator unlocks it manually.
  "
  impact 1.0
  tag cce: "CCE-35409-2"
  describe security_policy do
    its("LockoutDuration") { should be >= 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.2_L1_Ensure_Account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0" do
  title "(L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'"
  desc  "
    This policy setting determines the number of failed logon attempts before the account is locked. Setting this policy to 0 does not conform with the benchmark as doing so disables the account lockout threshold.
    
    The recommended state for this setting is: 10 or fewer invalid logon attempt(s), but not 0.
    
    Rationale: Setting an account lockout threshold reduces the likelihood that an online password brute force attack will be successful. Setting the account lockout threshold too low introduces risk of increased accidental lockouts and/or a malicious actor intentionally locking out accounts.
  "
  impact 1.0
  tag cce: "CCE-33728-7"
  describe security_policy do
    its("LockoutBadCount") { should be <= 10 }
  end
  describe security_policy do
    its("LockoutBadCount") { should be > 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.3_L1_Ensure_Reset_account_lockout_counter_after_is_set_to_15_or_more_minutes" do
  title "(L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
  desc  "
    This policy setting determines the length of time before the Account lockout threshold resets to zero. The default value for this policy setting is Not Defined. If the Account lockout threshold is defined, this reset time must be less than or equal to the value for the Account lockout duration setting.
    
    If you leave this policy setting at its default value or configure the value to an interval that is too long, your environment could be vulnerable to a DoS attack. An attacker could maliciously perform a number of failed logon attempts on all users in the organization, which will lock out their accounts. If no policy were determined to reset the account lockout, it would be a manual task for administrators. Conversely, if a reasonable time value is configured for this policy setting, users would be locked out for a set period until all of the accounts are unlocked automatically.
    
    The recommended state for this setting is: 15 or more minute(s).
    
    Rationale: Users can accidentally lock themselves out of their accounts if they mistype their password multiple times. To reduce the chance of such accidental lockouts, the Reset account lockout counter after setting determines the number of minutes that must elapse before the counter that tracks failed logon attempts and triggers lockouts is reset to 0.
  "
  impact 1.0
  tag cce: "CCE-35408-4"
  describe security_policy do
    its("ResetLockoutCount") { should be >= 15 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.1_L1_Ensure_Access_Credential_Manager_as_a_trusted_caller_is_set_to_No_One" do
  title "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc  "
    This security setting is used by Credential Manager during Backup and Restore. No accounts should have this user right, as it is only assigned to Winlogon. Users' saved credentials might be compromised if this user right is assigned to other entities.
    
    The recommended state for this setting is: No One.
    
    Rationale: If an account is given this right the user of the account may create an application that calls into Credential Manager and is returned the credentials for another user.
  "
  impact 1.0
  tag cce: "CCE-35457-1"
  describe security_policy.SeTrustedCredManAccessPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.2_L1_Ensure_Access_this_computer_from_the_network_is_set_to_Administrators" do
  title "(L1) Ensure 'Access this computer from the network' is set to 'Administrators'"
  desc  "
    This policy setting allows other users on the network to connect to the computer and is required by various network protocols that include Server Message Block (SMB)-based protocols, NetBIOS, Common Internet File System (CIFS), and Component Object Model Plus (COM+).
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Users who can connect from their computer to the network can access resources on target computers for which they have permission. For example, the Access this computer from the network user right is required for users to connect to shared printers and folders. If this user right is assigned to the Everyone group, then anyone in the group will be able to read the files in those shared folders. However, this situation is unlikely for new installations of Windows Server 2003 with Service Pack 1 (SP1), because the default share and NTFS permissions in Windows Server 2003 do not include the Everyone group. This vulnerability may have a higher level of risk for computers that you upgrade from Windows NT 4.0 or Windows 2000, because the default permissions for these operating systems are not as restrictive as the default permissions in Windows Server 2003.
  "
  impact 1.0
  tag cce: "CCE-32928-4"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeNetworkLogonRight - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.3_L1_Ensure_Act_as_part_of_the_operating_system_is_set_to_No_One" do
  title "(L1) Ensure 'Act as part of the operating system' is set to 'No One'"
  desc  "
    This policy setting allows a process to assume the identity of any user and thus gain access to the resources that the user is authorized to access.
    
    The recommended state for this setting is: No One.
    
    Rationale: The Act as part of the operating system user right is extremely powerful. Anyone with this user right can take complete control of the computer and erase evidence of their activities.
  "
  impact 1.0
  tag cce: "CCE-35403-5"
  describe security_policy.SeTcbPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.4_L1_Ensure_Adjust_memory_quotas_for_a_process_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE" do
  title "(L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
  desc  "
    This policy setting allows a user to adjust the maximum amount of memory that is available to a process. The ability to adjust memory quotas is useful for system tuning, but it can be abused. In the wrong hands, it could be used to launch a denial of service (DoS) attack.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE.
    
    Rationale: A user with the Adjust memory quotas for a process privilege can reduce the amount of memory that is available to any process, which could cause business-critical network applications to become slow or to fail. In the wrong hands, this privilege could be used to start a denial of service (DoS) attack.
  "
  impact 1.0
  tag cce: "CCE-35490-2"
  allowed_principals = ((['S-1-5-32-544'] + ['S-1-5-19']) + ['S-1-5-20'])
  describe security_policy.SeIncreaseQuotaPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.5_L1_Ensure_Allow_log_on_locally_is_set_to_Administrators_Users" do
  title "(L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'"
  desc  "
    This policy setting determines which users can interactively log on to computers in your environment. Logons that are initiated by pressing the CTRL+ALT+DEL key sequence on the client computer keyboard require this user right. Users who attempt to log on through Terminal Services or IIS also require this user right.
    
    The Guest account is assigned this user right by default. Although this account is disabled by default, it's recommended that you enable this setting through Group Policy. However, this user right should generally be restricted to the Administrators and Users groups. Assign this user right to the Backup Operators group if your organization requires that they have this capability.
    
    The recommended state for this setting is: Administrators, Users.
    
    Rationale: Any account with the Allow log on locally user right can log on at the console of the computer. If you do not restrict this user right to legitimate users who need to be able to log on to the console of the computer, unauthorized users could download and run malicious software to elevate their privileges.
  "
  impact 1.0
  tag cce: "CCE-35640-2"
  allowed_principals = ((users.where { username.casecmp('Users') == 0}.uids.entries + groups.where { name.casecmp('Users') == 0}.gids.entries) + ['S-1-5-32-544'])
  describe security_policy.SeInteractiveLogonRight - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.6_L1_Ensure_Allow_log_on_through_Remote_Desktop_Services_is_set_to_Administrators_Remote_Desktop_Users" do
  title "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
  desc  "
    This policy setting determines which users or groups have the right to log on as a Terminal Services client. Remote desktop users require this user right. If your organization uses Remote Assistance as part of its help desk strategy, create a group and assign it this user right through Group Policy. If the help desk in your organization does not use Remote Assistance, assign this user right only to the Administrators group or use the restricted groups feature to ensure that no user accounts are part of the Remote Desktop Users group.
    
    Restrict this user right to the Administrators group, and possibly the Remote Desktop Users group, to prevent unwanted users from gaining access to computers on your network by means of the Remote Assistance feature.
    
    The recommended state for this setting is: Administrators, Remote Desktop Users
    
    Rationale: Any account with the Allow log on through Terminal Services user right can log on to the remote console of the computer. If you do not restrict this user right to legitimate users who need to log on to the console of the computer, unauthorized users could download and run malicious software to elevate their privileges.
  "
  impact 1.0
  tag cce: "CCE-33035-7"
  allowed_principals = (['S-1-5-32-544'] + ['S-1-5-32-555'])
  describe security_policy.SeRemoteInteractiveLogonRight - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Ensure_Back_up_files_and_directories_is_set_to_Administrators" do
  title "(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
  desc  "
    This policy setting allows users to circumvent file and directory permissions to back up the system. This user right is enabled only when an application (such as NTBACKUP) attempts to access a file or directory through the NTFS file system backup application programming interface (API). Otherwise, the assigned file and directory permissions apply.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Users who are able to back up data from a computer could take the backup media to a non-domain computer on which they have administrative privileges and restore the data. They could take ownership of the files and view any unencrypted data that is contained within the backup set.
  "
  impact 1.0
  tag cce: "CCE-35699-8"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeBackupPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.8_L1_Ensure_Change_the_system_time_is_set_to_Administrators_LOCAL_SERVICE" do
  title "(L1) Ensure 'Change the system time' is set to 'Administrators, 'LOCAL SERVICE'"
  desc  "
    This policy setting determines which users and groups can change the time and date on the internal clock of the computers in your environment. Users who are assigned this user right can affect the appearance of event logs. When a computer's time setting is changed, logged events reflect the new time, not the actual time that the events occurred.
    
    When configuring a user right in the SCM enter a comma delimited list of accounts. Accounts can be either local or located in Active Directory, they can be groups, users, or computers.
    
    **Note:** Discrepancies between the time on the local computer and on the domain controllers in your environment may cause problems for the Kerberos authentication protocol, which could make it impossible for users to log on to the domain or obtain authorization to access domain resources after they are logged on. Also, problems will occur when Group Policy is applied to client computers if the system time is not synchronized with the domain controllers.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE.
    
    Rationale: Users who can change the time on a computer could cause several problems. For example, time stamps on event log entries could be made inaccurate, time stamps on files and folders that are created or modified could be incorrect, and computers that belong to a domain may not be able to authenticate themselves or users who try to log on to the domain from them. Also, because the Kerberos authentication protocol requires that the requestor and authenticator have their clocks synchronized within an administrator-defined skew period, an attacker who changes a computer's time may cause that computer to be unable to obtain or grant Kerberos tickets.
    
    The risk from these types of events is mitigated on most domain controllers, member servers, and end-user computers because the Windows Time service automatically synchronizes time with domain controllers in the following ways:
    
    * All client desktop computers and member servers use the authenticating domain controller as their inbound time partner.
    * All domain controllers in a domain nominate the primary domain controller (PDC) emulator operations master as their inbound time partner.
    * All PDC emulator operations masters follow the hierarchy of domains in the selection of their inbound time partner.
    * The PDC emulator operations master at the root of the domain is authoritative for the organization. Therefore it is recommended that you configure this computer to synchronize with a reliable external time server.
    This vulnerability becomes much more serious if an attacker is able to change the system time and then stop the Windows Time service or reconfigure it to synchronize with a time server that is not accurate.
  "
  impact 1.0
  tag cce: "CCE-33094-4"
  allowed_principals = (['S-1-5-32-544'] + ['S-1-5-19'])
  describe security_policy.SeSystemtimePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.9_L1_Ensure_Change_the_time_zone_is_set_to_Administrators_LOCAL_SERVICE_Users" do
  title "(L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'"
  desc  "
    This setting determines which users can change the time zone of the computer. This ability holds no great danger for the computer and may be useful for mobile workers.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE, Users.
    
    Rationale: Changing the time zone represents little vulnerability because the system time is not affected. This setting merely enables users to display their preferred time zone while being synchronized with domain controllers in different time zones.
  "
  impact 1.0
  tag cce: "CCE-33431-8"
  allowed_principals = ((['S-1-5-32-544'] + ['S-1-5-19']) + (users.where { username.casecmp('Users') == 0}.uids.entries + groups.where { name.casecmp('Users') == 0}.gids.entries))
  describe security_policy.SeTimeZonePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.10_L1_Ensure_Create_a_pagefile_is_set_to_Administrators" do
  title "(L1) Ensure 'Create a pagefile' is set to 'Administrators'"
  desc  "
    This policy setting allows users to change the size of the pagefile. By making the pagefile extremely large or extremely small, an attacker could easily affect the performance of a compromised computer.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Users who can change the page file size could make it extremely small or move the file to a highly fragmented storage volume, which could cause reduced computer performance.
  "
  impact 1.0
  tag cce: "CCE-33051-4"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeCreatePagefilePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.11_L1_Ensure_Create_a_token_object_is_set_to_No_One" do
  title "(L1) Ensure 'Create a token object' is set to 'No One'"
  desc  "
    This policy setting allows a process to create an access token, which may provide elevated rights to access sensitive data.
    
    The recommended state for this setting is: No One.
    
    Rationale: A user account that is given this user right has complete control over the system and can lead to the system being compromised. It is highly recommended that you do not assign any user accounts this right.
    
    The operating system examines a user's access token to determine the level of the user's privileges. Access tokens are built when users log on to the local computer or connect to a remote computer over a network. When you revoke a privilege, the change is immediately recorded, but the change is not reflected in the user's access token until the next time the user logs on or connects. Users with the ability to create or modify tokens can change the level of access for any currently logged on account. They could escalate their own privileges or create a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-33779-0"
  describe security_policy.SeCreateTokenPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.12_L1_Ensure_Create_global_objects_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE" do
  title "(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc  "
    This policy setting determines whether users can create global objects that are available to all sessions. Users can still create objects that are specific to their own session if they do not have this user right.
    
    Users who can create global objects could affect processes that run under other users' sessions. This capability could lead to a variety of problems, such as application failure or data corruption.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
    
    Rationale: Users who can create global objects could affect Windows services and processes that run under other user or system accounts. This capability could lead to a variety of problems, such as application failure, data corruption and elevation of privilege.
  "
  impact 1.0
  tag cce: "CCE-33095-1"
  allowed_principals = ((['S-1-5-32-544'] + ['S-1-5-19']) + (['S-1-5-20'] + ['S-1-5-6']))
  describe security_policy.SeCreateGlobalPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.13_L1_Ensure_Create_permanent_shared_objects_is_set_to_No_One" do
  title "(L1) Ensure 'Create permanent shared objects' is set to 'No One'"
  desc  "
    This user right is useful to kernel-mode components that extend the object namespace. However, components that run in kernel mode have this user right inherently. Therefore, it is typically not necessary to specifically assign this user right.
    
    The recommended state for this setting is: No One.
    
    Rationale: Users who have the Create permanent shared objects user right could create new shared objects and expose sensitive data to the network.
  "
  impact 1.0
  tag cce: "CCE-33780-8"
  describe security_policy.SeCreatePermanentPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.14_L1_Ensure_Create_symbolic_links_is_set_to_Administrators" do
  title "(L1) Ensure 'Create symbolic links' is set to 'Administrators'"
  desc  "
    This policy setting determines which users can create symbolic links. In Windows Vista, existing NTFS file system objects, such as files and folders, can be accessed by referring to a new kind of file system object called a symbolic link. A symbolic link is a pointer (much like a shortcut or .lnk file) to another file system object, which can be a file, folder, shortcut or another symbolic link. The difference between a shortcut and a symbolic link is that a shortcut only works from within the Windows shell. To other programs and applications, shortcuts are just another file, whereas with symbolic links, the concept of a shortcut is implemented as a feature of the NTFS file system.
    
    Symbolic links can potentially expose security vulnerabilities in applications that are not designed to use them. For this reason, the privilege for creating symbolic links should only be assigned to trusted users. By default, only Administrators can create symbolic links.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Users who have the Create Symbolic Links user right could inadvertently or maliciously expose your system to symbolic link attacks. Symbolic link attacks can be used to change the permissions on a file, to corrupt data, to destroy data, or as a Denial of Service attack.
  "
  impact 1.0
  tag cce: "CCE-33053-0"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeCreateSymbolicLinkPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.15_L1_Ensure_Debug_programs_is_set_to_Administrators" do
  title "(L1) Ensure 'Debug programs' is set to 'Administrators'"
  desc  "
    This policy setting determines which user accounts will have the right to attach a debugger to any process or to the kernel, which provides complete access to sensitive and critical operating system components. Developers who are debugging their own applications do not need to be assigned this user right; however, developers who are debugging new system components will need it.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: The Debug programs user right can be exploited to capture sensitive computer information from system memory, or to access and modify kernel or application structures. Some attack tools exploit this user right to extract hashed passwords and other private security information, or to insert rootkit code. By default, the Debug programs user right is assigned only to administrators, which helps to mitigate the risk from this vulnerability.
  "
  impact 1.0
  tag cce: "CCE-33157-9"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeDebugPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.16_L1_Ensure_Deny_access_to_this_computer_from_the_network_to_include_Guests_Local_account" do
  title "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
  desc  "
    This policy setting prohibits users from connecting to a computer from across the network, which would allow users to access and potentially modify data remotely. In high security environments, there should be no need for remote users to access data on a computer. Instead, file sharing should be accomplished through the use of network servers.
    
    The recommended state for this setting is to include: Guests, Local account.
    
    **Caution:** Configuring a standalone (non-domain-joined) workstation as described above may result in an inability to remotely administer the workstation.
    
    Rationale: Users who can log on to the computer over the network can enumerate lists of account names, group names, and shared resources. Users with permission to access shared folders and files can connect over the network and possibly view or modify data.
  "
  impact 1.0
  tag cce: "CCE-34173-5"
  security_principals = (['S-1-5-32-546'] + ['S-1-5-113']).uniq
  describe security_policy.SeDenyNetworkLogonRight & security_principals do
    it { should eq security_principals }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.17_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests" do
  title "(L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
  desc  "
    This policy setting determines which accounts will not be able to log on to the computer as a batch job. A batch job is not a batch (.bat) file, but rather a batch-queue facility. Accounts that use the Task Scheduler to schedule jobs need this user right.
    
    The **Deny log on as a batch job** user right overrides the **Log on as a batch job** user right, which could be used to allow accounts to schedule jobs that consume excessive system resources. Such an occurrence could cause a DoS condition. Failure to assign this user right to the recommended accounts can be a security risk.
    
    The recommended state for this setting is to include: Guests.
    
    Rationale: Accounts that have the Deny log on as a batch job user right could be used to schedule jobs that could consume excessive computer resources and cause a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-35461-3"
  security_principals = (['S-1-5-32-546']).uniq
  describe security_policy.SeDenyBatchLogonRight & security_principals do
    it { should eq security_principals }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.18_L1_Ensure_Deny_log_on_as_a_service_to_include_Guests" do
  title "(L1) Ensure 'Deny log on as a service' to include 'Guests'"
  desc  "
    This security setting determines which service accounts are prevented from registering a process as a service. This policy setting supersedes the **Log on as a service** policy setting if an account is subject to both policies.
    
    The recommended state for this setting is to include: Guests.
    
    **Note:** This security setting does not apply to the System, Local Service, or Network Service accounts.
    
    Rationale: Accounts that can log on as a service could be used to configure and start new unauthorized services, such as a keylogger or other malicious software. The benefit of the specified countermeasure is somewhat reduced by the fact that only users with administrative privileges can install and configure services, and an attacker who has already attained that level of access could configure the service to run with the System account.
  "
  impact 1.0
  tag cce: "CCE-35404-3"
  security_principals = (['S-1-5-32-546']).uniq
  describe security_policy.SeDenyServiceLogonRight & security_principals do
    it { should eq security_principals }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.19_L1_Ensure_Deny_log_on_locally_to_include_Guests" do
  title "(L1) Ensure 'Deny log on locally' to include 'Guests'"
  desc  "
    This security setting determines which users are prevented from logging on at the computer. This policy setting supersedes the **Allow log on locally** policy setting if an account is subject to both policies.
    
    **Important:** If you apply this security policy to the Everyone group, no one will be able to log on locally.
    
    The recommended state for this setting is to include: Guests.
    
    Rationale: Any account with the ability to log on locally could be used to log on at the console of the computer. If this user right is not restricted to legitimate users who need to log on to the console of the computer, unauthorized users might download and run malicious software that elevates their privileges.
  "
  impact 1.0
  tag cce: "CCE-35293-0"
  security_principals = (['S-1-5-32-546']).uniq
  describe security_policy.SeDenyInteractiveLogonRight & security_principals do
    it { should eq security_principals }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.20_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_to_include_Guests_Local_account" do
  title "(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
  desc  "
    This policy setting determines whether users can log on as Terminal Services clients. After the baseline workstation is joined to a domain environment, there is no need to use local accounts to access the workstation from the network. Domain accounts can access the server for administration and end-user processing.
    
    The recommended state for this setting is to include: Guests, Local account.
    
    **Caution:** Configuring a standalone (non-domain-joined) workstation as described above may result in an inability to remotely administer the workstation.
    
    Rationale: Any account with the right to log on through Terminal Services could be used to log on to the remote console of the computer. If this user right is not restricted to legitimate users who need to log on to the console of the computer, unauthorized users might download and run malicious software that elevates their privileges.
  "
  impact 1.0
  tag cce: "CCE-33787-3"
  security_principals = (['S-1-5-32-546'] + ['S-1-5-113']).uniq
  describe security_policy.SeDenyRemoteInteractiveLogonRight & security_principals do
    it { should eq security_principals }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Enable_computer_and_user_accounts_to_be_trusted_for_delegation_is_set_to_No_One" do
  title "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
  desc  "
    This policy setting allows users to change the Trusted for Delegation setting on a computer object in Active Directory. Abuse of this privilege could allow unauthorized users to impersonate other users on the network.
    
    The recommended state for this setting is: No One.
    
    Rationale: Misuse of the Enable computer and user accounts to be trusted for delegation user right could allow unauthorized users to impersonate other users on the network. An attacker could exploit this privilege to gain access to network resources and make it difficult to determine what has happened after a security incident.
  "
  impact 1.0
  tag cce: "CCE-33778-2"
  describe security_policy.SeEnableDelegationPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Ensure_Force_shutdown_from_a_remote_system_is_set_to_Administrators" do
  title "(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
  desc  "
    This policy setting allows users to shut down Windows Vista-based computers from remote locations on the network. Anyone who has been assigned this user right can cause a denial of service (DoS) condition, which would make the computer unavailable to service user requests. Therefore, it is recommended that only highly trusted administrators be assigned this user right.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Any user who can shut down a computer could cause a DoS condition to occur. Therefore, this user right should be tightly restricted.
  "
  impact 1.0
  tag cce: "CCE-33715-4"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeRemoteShutdownPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.23_L1_Ensure_Generate_security_audits_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE" do
  title "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc  "
    This policy setting determines which users or processes can generate audit records in the Security log.
    
    The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.
    
    Rationale: An attacker could use this capability to create a large number of audited events, which would make it more difficult for a system administrator to locate any illicit activity. Also, if the event log is configured to overwrite events as needed, any evidence of unauthorized activities could be overwritten by a large number of unrelated events.
  "
  impact 1.0
  tag cce: "CCE-35363-1"
  allowed_principals = (['S-1-5-19'] + ['S-1-5-20'])
  describe security_policy.SeAuditPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.24_L1_Ensure_Impersonate_a_client_after_authentication_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE" do
  title "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc  "
    The policy setting allows programs that run on behalf of a user to impersonate that user (or another specified account) so that they can act on behalf of the user. If this user right is required for this kind of impersonation, an unauthorized user will not be able to convince a client to connect#x2014;for example, by remote procedure call (RPC) or named pipes#x2014;to a service that they have created to impersonate that client, which could elevate the unauthorized user's permissions to administrative or system levels.
    
    Services that are started by the Service Control Manager have the built-in Service group added by default to their access tokens. COM servers that are started by the COM infrastructure and configured to run under a specific account also have the Service group added to their access tokens. As a result, these processes are assigned this user right when they are started.
    
    Also, a user can impersonate an access token if any of the following conditions exist:
    - The access token that is being impersonated is for this user.
    - The user, in this logon session, logged on to the network with explicit credentials to create the access token.
    - The requested level is less than Impersonate, such as Anonymous or Identify.
    
    An attacker with the Impersonate a client after authentication user right could create a service, trick a client to make them connect to the service, and then impersonate that client to elevate the attacker's level of access to that of the client.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
    
    Rationale: An attacker with the Impersonate a client after authentication user right could create a service, trick a client to make them connect to the service, and then impersonate that client to elevate the attacker's level of access to that of the client.
  "
  impact 1.0
  tag cce: "CCE-34021-6"
  allowed_principals = ((['S-1-5-32-544'] + ['S-1-5-19']) + (['S-1-5-20'] + ['S-1-5-6']))
  describe security_policy.SeImpersonatePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.25_L1_Ensure_Increase_scheduling_priority_is_set_to_Administrators" do
  title "(L1) Ensure 'Increase scheduling priority' is set to 'Administrators'"
  desc  "
    This policy setting determines whether users can increase the base priority class of a process. (It is not a privileged operation to increase relative priority within a priority class.) This user right is not required by administrative tools that are supplied with the operating system but might be required by software development tools.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: A user who is assigned this user right could increase the scheduling priority of a process to Real-Time, which would leave little processing time for all other processes and could lead to a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-35178-3"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeIncreaseBasePriorityPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Load_and_unload_device_drivers_is_set_to_Administrators" do
  title "(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
  desc  "
    This policy setting allows users to dynamically load a new device driver on a system. An attacker could potentially use this capability to install malicious code that appears to be a device driver. This user right is required for users to add local printers or printer drivers in Windows Vista.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Device drivers run as highly privileged code. A user who has the Load and unload device drivers user right could unintentionally install malicious code that masquerades as a device driver. Administrators should exercise greater care and install only drivers with verified digital signatures.
  "
  impact 1.0
  tag cce: "CCE-34903-5"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeLoadDriverPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.27_L1_Ensure_Lock_pages_in_memory_is_set_to_No_One" do
  title "(L1) Ensure 'Lock pages in memory' is set to 'No One'"
  desc  "
    This policy setting allows a process to keep data in physical memory, which prevents the system from paging the data to virtual memory on disk. If this user right is assigned, significant degradation of system performance can occur.
    
    The recommended state for this setting is: No One.
    
    Rationale: Users with the Lock pages in memory user right could assign physical memory to several processes, which could leave little or no RAM for other processes and result in a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-33807-9"
  describe security_policy.SeLockMemoryPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.30_L1_Ensure_Manage_auditing_and_security_log_is_set_to_Administrators" do
  title "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
  desc  "
    This policy setting determines which users can change the auditing options for files and directories and clear the Security log.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: The ability to manage the Security event log is a powerful user right and it should be closely guarded. Anyone with this user right can clear the Security log to erase important evidence of unauthorized activity.
  "
  impact 1.0
  tag cce: "CCE-35275-7"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeSecurityPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.31_L1_Ensure_Modify_an_object_label_is_set_to_No_One" do
  title "(L1) Ensure 'Modify an object label' is set to 'No One'"
  desc  "
    This privilege determines which user accounts can modify the integrity label of objects, such as files, registry keys, or processes owned by other users. Processes running under a user account can modify the label of an object owned by that user to a lower level without this privilege.
    
    The recommended state for this setting is: No One.
    
    Rationale: By modifying the integrity label of an object owned by another user a malicious user may cause them to execute code at a higher level of privilege than intended.
  "
  impact 1.0
  tag cce: "CCE-34913-4"
  describe security_policy.SeRelabelPrivilege do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.32_L1_Ensure_Modify_firmware_environment_values_is_set_to_Administrators" do
  title "(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
  desc  "
    This policy setting allows users to configure the system-wide environment variables that affect hardware configuration. This information is typically stored in the Last Known Good Configuration. Modification of these values and could lead to a hardware failure that would result in a denial of service condition.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Anyone who is assigned the Modify firmware environment values user right could configure the settings of a hardware component to cause it to fail, which could lead to data corruption or a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-35183-3"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeSystemEnvironmentPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.33_L1_Ensure_Perform_volume_maintenance_tasks_is_set_to_Administrators" do
  title "(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
  desc  "
    This policy setting allows users to manage the system's volume or disk configuration, which could allow a user to delete a volume and cause data loss as well as a denial-of-service condition.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: A user who is assigned the Perform volume maintenance tasks user right could delete a volume, which could result in the loss of data or a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-35369-8"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeManageVolumePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.34_L1_Ensure_Profile_single_process_is_set_to_Administrators" do
  title "(L1) Ensure 'Profile single process' is set to 'Administrators'"
  desc  "
    This policy setting determines which users can use tools to monitor the performance of non-system processes. Typically, you do not need to configure this user right to use the Microsoft Management Console (MMC) Performance snap-in. However, you do need this user right if System Monitor is configured to collect data using Windows Management Instrumentation (WMI). Restricting the Profile single process user right prevents intruders from gaining additional information that could be used to mount an attack on the system.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: The Profile single process user right presents a moderate vulnerability. An attacker with this user right could monitor a computer's performance to help identify critical processes that they might wish to attack directly. The attacker may also be able to determine what processes run on the computer so that they could identify countermeasures that they may need to avoid, such as antivirus software, an intrusion-detection system, or which other users are logged on to a computer.
  "
  impact 1.0
  tag cce: "CCE-35000-9"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeProfileSingleProcessPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.35_L1_Ensure_Profile_system_performance_is_set_to_Administrators_NT_SERVICEWdiServiceHost" do
  title "(L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'"
  desc  "
    This policy setting allows users to use tools to view the performance of different system processes, which could be abused to allow attackers to determine a system's active processes and provide insight into the potential attack surface of the computer.
    
    The recommended state for this setting is: Administrators, NT SERVICE\\WdiServiceHost.
    
    Rationale: The Profile system performance user right poses a moderate vulnerability. Attackers with this user right could monitor a computer's performance to help identify critical processes that they might wish to attack directly. Attackers may also be able to determine what processes are active on the computer so that they could identify countermeasures that they may need to avoid, such as antivirus software or an intrusion detection system.
  "
  impact 1.0
  tag cce: "CCE-35001-7"
  allowed_principals = (['S-1-5-32-544'] + ['S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'])
  describe security_policy.SeSystemProfilePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.36_L1_Ensure_Replace_a_process_level_token_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE" do
  title "(L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc  "
    This policy setting allows one process or service to start another service or process with a different security access token, which can be used to modify the security access token of that sub-process and result in the escalation of privileges.
    
    The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.
    
    Rationale: User with the Replace a process level token privilege are able to start processes as other users whose credentials they know. They could use this method to hide their unauthorized actions on the computer. (On Windows 2000-based computers, use of the Replace a process level token user right also requires the user to have the Adjust memory quotas for a process user right that is discussed earlier in this section.)
  "
  impact 1.0
  tag cce: "CCE-35003-3"
  allowed_principals = (['S-1-5-19'] + ['S-1-5-20'])
  describe security_policy.SeAssignPrimaryTokenPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.37_L1_Ensure_Restore_files_and_directories_is_set_to_Administrators" do
  title "(L1) Ensure 'Restore files and directories' is set to 'Administrators'"
  desc  "
    This policy setting determines which users can bypass file, directory, registry, and other persistent object permissions when restoring backed up files and directories on computers that run Windows Vista in your environment. This user right also determines which users can set valid security principals as object owners; it is similar to the Back up files and directories user right.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: An attacker with the Restore files and directories user right could restore sensitive data to a computer and overwrite data that is more recent, which could lead to loss of important data, data corruption, or a denial of service. Attackers could overwrite executable files that are used by legitimate administrators or system services with versions that include malicious software to grant themselves elevated privileges, compromise data, or install backdoors for continued access to the computer.
    
    **Note:** Even if the following countermeasure is configured, an attacker could still restore data to a computer in a domain that is controlled by the attacker. Therefore, it is critical that organizations carefully protect the media that are used to back up data.
  "
  impact 1.0
  tag cce: "CCE-35067-8"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeRestorePrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.38_L1_Ensure_Shut_down_the_system_is_set_to_Administrators_Users" do
  title "(L1) Ensure 'Shut down the system' is set to 'Administrators, Users'"
  desc  "
    This policy setting determines which users who are logged on locally to the computers in your environment can shut down the operating system with the Shut Down command. Misuse of this user right can result in a denial of service condition.
    
    The recommended state for this setting is: Administrators, Users.
    
    Rationale: The ability to shut down a workstation should be available generally to Administrators and authorized Users of that workstation, but not permitted for guests or unauthorized users - in order to prevent a Denial of Service attack.
  "
  impact 1.0
  tag cce: "CCE-35004-1"
  allowed_principals = ((users.where { username.casecmp('Users') == 0}.uids.entries + groups.where { name.casecmp('Users') == 0}.gids.entries) + ['S-1-5-32-544'])
  describe security_policy.SeShutdownPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.39_L1_Ensure_Take_ownership_of_files_or_other_objects_is_set_to_Administrators" do
  title "(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
  desc  "
    This policy setting allows users to take ownership of files, folders, registry keys, processes, or threads. This user right bypasses any permissions that are in place to protect objects to give ownership to the specified user.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Any users with the Take ownership of files or other objects user right can take control of any object, regardless of the permissions on that object, and then make any changes they wish to that object. Such changes could result in exposure of data, corruption of data, or a DoS condition.
  "
  impact 1.0
  tag cce: "CCE-35009-0"
  allowed_principals = ['S-1-5-32-544']
  describe security_policy.SeTakeOwnershipPrivilege - allowed_principals do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_L1_Ensure_Accounts_Administrator_account_status_is_set_to_Disabled" do
  title "(L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
  desc  "
    This policy setting enables or disables the Administrator account during normal operation. When a computer is booted into safe mode, the Administrator account is always enabled, regardless of how this setting is configured. Note that this setting will have no impact when applied to the domain controller organizational unit via group policy because domain controllers have no local account database. It can be configured at the domain level via group policy, similar to account lockout and password policy settings.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: In some organizations, it can be a daunting management challenge to maintain a regular schedule for periodic password changes for local accounts. Therefore, you may want to disable the built-in Administrator account instead of relying on regular password changes to protect it from attack. Another reason to disable this built-in account is that it cannot be locked out no matter how many failed logons it accrues, which makes it a prime target for brute force attacks that attempt to guess passwords. Also, this account has a well-known security identifier (SID) and there are third-party tools that allow authentication by using the SID rather than the account name. This capability means that even if you rename the Administrator account, an attacker could launch a brute force attack by using the SID to log on.
  "
  impact 1.0
  tag cce: "CCE-33511-7"
  machine_sid = powershell('"{0}-500" -f ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()').stdout.strip.gsub(/^S-[0-9]*-[0-9]*-[0-9]*-/, '').gsub(/-[0-9]+$/, '')
  user_sid = "S-1-5-21-#{machine_sid}-500"
  describe powershell("Get-LocalUser -SID '#{user_sid}' | Format-Table Enabled -HideTableHeaders").stdout.strip.upcase do
    it { should eq "FALSE" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1.2_L1_Ensure_Accounts_Block_Microsoft_accounts_is_set_to_Users_cant_add_or_log_on_with_Microsoft_accounts" do
  title "(L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
  desc  "
    This policy setting prevents users from adding new Microsoft accounts on this computer.
    
    If you select the \"Users can't add Microsoft accounts\" option, users will not be able to create new Microsoft accounts on this computer, switch a local account to a Microsoft account, or connect a domain account to a Microsoft account. This is the preferred option if you need to limit the use of Microsoft accounts in your enterprise.
    
    If you select the \"Users can't add or log on with Microsoft accounts\" option, existing Microsoft account users will not be able to log on to Windows. Selecting this option might make it impossible for an existing administrator on this computer to log on and manage the system.
    
    If you disable or do not configure this policy (recommended), users will be able to use Microsoft accounts with Windows.
    
    The recommended state for this setting is: Users can't add or log on with Microsoft accounts.
    
    Rationale: Organizations that want to effectively implement identity management policies and maintain firm control of what accounts are used to log onto their computers will probably want to block Microsoft accounts. Organizations may also need to block Microsoft accounts in order to meet the requirements of compliance standards that apply to their information systems.
  "
  impact 1.0
  tag cce: "CCE-35487-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "NoConnectedUser" }
    its("NoConnectedUser") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled" do
  title "(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
  desc  "
    This policy setting determines whether the Guest account is enabled or disabled. The Guest account allows unauthenticated network users to gain access to the system. Note that this setting will have no impact when applied to the domain controller organizational unit via group policy because domain controllers have no local account database. It can be configured at the domain level via group policy, similar to account lockout and password policy settings.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: The default Guest account allows unauthenticated network users to log on as Guest with no password. These unauthorized users could access any resources that are accessible to the Guest account over the network. This capability means that any network shares with permissions that allow access to the Guest account, the Guests group, or the Everyone group will be accessible over the network, which could lead to the exposure or corruption of data.
  "
  impact 1.0
  tag cce: "CCE-33949-9"
  machine_sid = powershell('"{0}-500" -f ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()').stdout.strip.gsub(/^S-[0-9]*-[0-9]*-[0-9]*-/, '').gsub(/-[0-9]+$/, '')
  user_sid = "S-1-5-21-#{machine_sid}-501"
  describe powershell("Get-LocalUser -SID '#{user_sid}' | Format-Table Enabled -HideTableHeaders").stdout.strip.upcase do
    it { should eq "FALSE" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1.4_L1_Ensure_Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only_is_set_to_Enabled" do
  title "(L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
  desc  "
    This policy setting determines whether local accounts that are not password protected can be used to log on from locations other than the physical computer console. If you enable this policy setting, local accounts that have blank passwords will not be able to log on to the network from remote client computers. Such accounts will only be able to log on at the keyboard of the computer.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Blank passwords are a serious threat to computer security and should be forbidden through both organizational policy and suitable technical measures. In fact, the default settings for Active Directory domains require complex passwords of at least seven characters. However, if users with the ability to create new accounts bypass your domain-based password policies, they could create accounts with blank passwords. For example, a user could build a stand-alone computer, create one or more accounts with blank passwords, and then join the computer to the domain. The local accounts with blank passwords would still function. Anyone who knows the name of one of these unprotected accounts could then use it to log on.
  "
  impact 1.0
  tag cce: "CCE-32929-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "LimitBlankPasswordUse" }
    its("LimitBlankPasswordUse") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1.5_L1_Configure_Accounts_Rename_administrator_account" do
  title "(L1) Configure 'Accounts: Rename administrator account'"
  desc  "
    The built-in local administrator account is a well-known account name that attackers will target. It is recommended to choose another name for this account, and to avoid names that denote administrative or elevated access accounts. Be sure to also change the default description for the local administrator (through the Computer Management console).
    
    Rationale: The Administrator account exists on all computers that run the Windows 2000 or later operating systems. If you rename this account, it is slightly more difficult for unauthorized persons to guess this privileged user name and password combination.
    
    The built-in Administrator account cannot be locked out, regardless of how many times an attacker might use a bad password. This capability makes the Administrator account a popular target for brute force attacks that attempt to guess passwords. The value of this countermeasure is lessened because this account has a well-known SID, and there are third-party tools that allow authentication by using the SID rather than the account name. Therefore, even if you rename the Administrator account, an attacker could launch a brute force attack by using the SID to log on.
  "
  impact 1.0
  tag cce: "CCE-33034-0"
  describe powershell("Get-WmiObject -Class win32_useraccount -filter \"Domain='$($env:ComputerName)' and name='Administrator'\"") do
    its("stdout") { should eq "" }
    its("exit_status") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.1.6_L1_Configure_Accounts_Rename_guest_account" do
  title "(L1) Configure 'Accounts: Rename guest account'"
  desc  "
    The built-in local guest account is another well-known name to attackers. It is recommended to rename this account to something that does not indicate its purpose. Even if you disable this account, which is recommended, ensure that you rename it for added security.
    
    Rationale: The Guest account exists on all computers that run the Windows 2000 or later operating systems. If you rename this account. it is slightly more difficult for unauthorized persons to guess this privileged user name and password combination.
  "
  impact 1.0
  tag cce: "CCE-35488-6"
  describe powershell("Get-WmiObject -Class win32_useraccount -filter \"Domain='$($env:ComputerName)' and name='Guest'\"") do
    its("stdout") { should eq "" }
    its("exit_status") { should cmp 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.2.1_L1_Ensure_Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings_is_set_to_Enabled" do
  title "(L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
  desc  "
    This policy setting allows administrators to enable the more precise auditing capabilities present in Windows Vista.
    
    The Audit Policy settings available in Windows Server 2003 Active Directory do not yet contain settings for managing the new auditing subcategories. To properly apply the auditing policies prescribed in this baseline, the Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings setting needs to be configured to Enabled.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Prior to the introduction of auditing subcategories in Windows Vista, it was difficult to track events at a per-system or per-user level. The larger event categories created too many events and the key information that needed to be audited was difficult to find.
  "
  impact 1.0
  tag cce: "CCE-35533-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "scenoapplylegacyauditpolicy" }
    its("scenoapplylegacyauditpolicy") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.2.2_L1_Ensure_Audit_Shut_down_system_immediately_if_unable_to_log_security_audits_is_set_to_Disabled" do
  title "(L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
  desc  "
    This policy setting determines whether the system shuts down if it is unable to log Security events. It is a requirement for Trusted Computer System Evaluation Criteria (TCSEC)-C2 and Common Criteria certification to prevent auditable events from occurring if the audit system is unable to log them. Microsoft has chosen to meet this requirement by halting the system and displaying a stop message if the auditing system experiences a failure. When this policy setting is enabled, the system will be shut down if a security audit cannot be logged for any reason.
    
    If the Audit: Shut down system immediately if unable to log security audits setting is enabled, unplanned system failures can occur. Therefore, this policy setting is configured to Not Defined for both of the environments that are discussed in this chapter.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If the computer is unable to record events to the Security log, critical evidence or important troubleshooting information may not be available for review after a security incident. Also, an attacker could potentially generate a large volume of Security log events to purposely force a computer shutdown.
  "
  impact 1.0
  tag cce: "CCE-33046-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "crashonauditfail" }
    its("crashonauditfail") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.4.1_L1_Ensure_Devices_Allowed_to_format_and_eject_removable_media_is_set_to_Administrators_and_Interactive_Users" do
  title "(L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'"
  desc  "
    This policy setting determines who is allowed to format and eject removable NTFS media. You can use this policy setting to prevent unauthorized users from removing data on one computer to access it on another computer on which they have local administrator privileges.
    
    The recommended state for this setting is: Administrators and Interactive Users.
    
    Rationale: Users may be able to move data on removable disks to a different computer where they have administrative privileges. The user could then take ownership of any file, grant themselves full control, and view or modify any file. The fact that most removable storage devices will eject media by pressing a mechanical button diminishes the advantage of this policy setting.
  "
  impact 1.0
  tag cce: "CCE-34355-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "AllocateDASD" }
    its("AllocateDASD") { should eq "2" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.6.1_L1_Ensure_Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always_is_set_to_Enabled" do
  title "(L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
  desc  "
    This policy setting determines whether all secure channel traffic that is initiated by the domain member must be signed or encrypted. If a system is set to always encrypt or sign secure channel data, it cannot establish a secure channel with a domain controller that is not capable of signing or encrypting all secure channel traffic, because all secure channel data must be signed and encrypted.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: When a computer joins a domain, a computer account is created. After it joins the domain, the computer uses the password for that account to create a secure channel with the domain controller for its domain every time that it restarts. Requests that are sent on the secure channel are authenticated#x2014;and sensitive information such as passwords are encrypted#x2014;but the channel is not integrity-checked, and not all information is encrypted. If a computer is configured to always encrypt or sign secure channel data but the domain controller cannot sign or encrypt any portion of the secure channel data, the computer and domain controller cannot establish a secure channel. If the computer is configured to encrypt or sign secure channel data when possible, a secure channel can be established, but the level of encryption and signing is negotiated.
  "
  impact 1.0
  tag cce: "CCE-34892-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "requiresignorseal" }
    its("requiresignorseal") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.6.2_L1_Ensure_Domain_member_Digitally_encrypt_secure_channel_data_when_possible_is_set_to_Enabled" do
  title "(L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
  desc  "
    This policy setting determines whether a domain member should attempt to negotiate encryption for all secure channel traffic that it initiates. If you enable this policy setting, the domain member will request encryption of all secure channel traffic. If you disable this policy setting, the domain member will be prevented from negotiating secure channel encryption.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: When a Windows Server 2003, Windows XP, Windows 2000, or Windows NT computer joins a domain, a computer account is created. After it joins the domain, the computer uses the password for that account to create a secure channel with the domain controller for its domain every time that it restarts. Requests that are sent on the secure channel are authenticated#x2014;and sensitive information such as passwords are encrypted#x2014;but the channel is not integrity-checked, and not all information is encrypted. If a computer is configured to always encrypt or sign secure channel data but the domain controller cannot sign or encrypt any portion of the secure channel data, the computer and domain controller cannot establish a secure channel. If the computer is configured to encrypt or sign secure channel data when possible, a secure channel can be established, but the level of encryption and signing is negotiated.
  "
  impact 1.0
  tag cce: "CCE-35273-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "sealsecurechannel" }
    its("sealsecurechannel") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.6.3_L1_Ensure_Domain_member_Digitally_sign_secure_channel_data_when_possible_is_set_to_Enabled" do
  title "(L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
  desc  "
    This policy setting determines whether a domain member should attempt to negotiate whether all secure channel traffic that it initiates must be digitally signed. Digital signatures protect the traffic from being modified by anyone who captures the data as it traverses the network.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: When a computer joins a domain, a computer account is created. After it joins the domain, the computer uses the password for that account to create a secure channel with the domain controller for its domain every time that it restarts. Requests that are sent on the secure channel are authenticated#x2014;and sensitive information such as passwords are encrypted#x2014;but the channel is not integrity-checked, and not all information is encrypted. If a computer is configured to always encrypt or sign secure channel data but the domain controller cannot sign or encrypt any portion of the secure channel data, the computer and domain controller cannot establish a secure channel. If the computer is configured to encrypt or sign secure channel data when possible, a secure channel can be established, but the level of encryption and signing is negotiated.
  "
  impact 1.0
  tag cce: "CCE-34893-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "signsecurechannel" }
    its("signsecurechannel") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.6.4_L1_Ensure_Domain_member_Disable_machine_account_password_changes_is_set_to_Disabled" do
  title "(L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
  desc  "
    This policy setting determines whether a domain member can periodically change its computer account password. If you enable this policy setting, the domain member will be prevented from changing its computer account password. If you disable this policy setting, the domain member can change its computer account password as specified by the Domain Member: Maximum machine account password age setting, which by default is every 30 days. Computers that cannot automatically change their account passwords are potentially vulnerable, because an attacker might be able to determine the password for the system's domain account.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: The default configuration for Windows Server 2003-based computers that belong to a domain is that they are automatically required to change the passwords for their accounts every 30 days. If you disable this policy setting, computers that run Windows Server 2003 will retain the same passwords as their computer accounts. Computers that are no longer able to automatically change their account password are at risk from an attacker who could determine the password for the computer's domain account.
  "
  impact 1.0
  tag cce: "CCE-34986-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "disablepasswordchange" }
    its("disablepasswordchange") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.6.5_L1_Ensure_Domain_member_Maximum_machine_account_password_age_is_set_to_30_or_fewer_days_but_not_0" do
  title "(L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
  desc  "
    This policy setting determines the maximum allowable age for a computer account password. By default, domain members automatically change their domain passwords every 30 days. If you increase this interval significantly so that the computers no longer change their passwords, an attacker would have more time to undertake a brute force attack against one of the computer accounts.
    
    The recommended state for this setting is: 30 or fewer days, but not 0.
    
    **Note:** A value of 0 does not conform to the benchmark as it disables maximum password age.
    
    Rationale: In Active Directory-based domains, each computer has an account and password just like every user. By default, the domain members automatically change their domain password every 30 days. If you increase this interval significantly, or set it to 0 so that the computers no longer change their passwords, an attacker will have more time to undertake a brute force attack to guess the password of one or more computer accounts.
  "
  impact 1.0
  tag cce: "CCE-34894-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "maximumpasswordage" }
    its("maximumpasswordage") { should cmp > 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "maximumpasswordage" }
    its("maximumpasswordage") { should cmp <= 30 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.6.6_L1_Ensure_Domain_member_Require_strong_Windows_2000_or_later_session_key_is_set_to_Enabled" do
  title "(L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
  desc  "
    When this policy setting is enabled, a secure channel can only be established with domain controllers that are capable of encrypting secure channel data with a strong (128-bit) session key.
    
    To enable this policy setting, all domain controllers in the domain must be able to encrypt secure channel data with a strong key, which means all domain controllers must be running Microsoft Windows 2000 or later.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Session keys that are used to establish secure channel communications between domain controllers and member computers are much stronger in Windows 2000 than they were in previous Microsoft operating systems. Whenever possible, you should take advantage of these stronger session keys to help protect secure channel communications from attacks that attempt to hijack network sessions and eavesdropping. (Eavesdropping is a form of hacking in which network data is read or altered in transit. The data can be modified to hide or change the sender, or be redirected.)
  "
  impact 1.0
  tag cce: "CCE-35177-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "requirestrongkey" }
    its("requirestrongkey") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.1_L1_Ensure_Interactive_logon_Do_not_display_last_user_name_is_set_to_Enabled" do
  title "(L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"
  desc  "
    This policy setting determines whether the account name of the last user to log on to the client computers in your organization will be displayed in each computer's respective Windows logon screen. Enable this policy setting to prevent intruders from collecting account names visually from the screens of desktop or laptop computers in your organization.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An attacker with access to the console (for example, someone with physical access or someone who is able to connect to the server through Terminal Services) could view the name of the last user who logged on to the server. The attacker could then try to guess the password, use a dictionary, or use a brute-force attack to try and log on.
  "
  impact 1.0
  tag cce: "CCE-34898-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "DontDisplayLastUserName" }
    its("DontDisplayLastUserName") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.2_L1_Ensure_Interactive_logon_Do_not_require_CTRLALTDEL_is_set_to_Disabled" do
  title "(L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users must press CTRL+ALT+DEL before they log on. If you enable this policy setting, users can log on without this key combination. If you disable this policy setting, users must press CTRL+ALT+DEL before they log on to Windows unless they use a smart card for Windows logon. A smart card is a tamper-proof device that stores security information.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Microsoft developed this feature to make it easier for users with certain types of physical impairments to log on to computers that run Windows. If users are not required to press CTRL+ALT+DEL, they are susceptible to attacks that attempt to intercept their passwords. If CTRL+ALT+DEL is required before logon, user passwords are communicated by means of a trusted path.
    
    An attacker could install a Trojan horse program that looks like the standard Windows logon dialog box and capture the user's password. The attacker would then be able to log on to the compromised account with whatever level of privilege that user has.
  "
  impact 1.0
  tag cce: "CCE-35099-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "DisableCAD" }
    its("DisableCAD") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.4_L1_Ensure_Interactive_logon_Machine_inactivity_limit_is_set_to_900_or_fewer_seconds_but_not_0" do
  title "(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
  desc  "
    Windows notices inactivity of a logon session, and if the amount of inactive time exceeds the inactivity limit, then the screen saver will run, locking the session.
    
    The recommended state for this setting is: 900 or fewer second(s), but not 0.
    
    **Note:** A value of 0 does not conform to the benchmark as it disables the machine inactivity limit.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  tag cce: "CCE-34900-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "InactivityTimeoutSecs" }
    its("InactivityTimeoutSecs") { should cmp <= 900 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "InactivityTimeoutSecs" }
    its("InactivityTimeoutSecs") { should cmp != 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.5_L1_Configure_Interactive_logon_Message_text_for_users_attempting_to_log_on" do
  title "(L1) Configure 'Interactive logon: Message text for users attempting to log on'"
  desc  "
    This policy setting specifies a text message that displays to users when they log on. Set the following group policy to a value that is consistent with the security and operational requirements of your organization.
    
    Rationale: Displaying a warning message before logon may help prevent an attack by warning the attacker about the consequences of their misconduct before it happens. It may also help to reinforce corporate policy by notifying employees of the appropriate policy during the logon process. This text is often used for legal reasons#x2014;for example, to warn users about the ramifications of misusing company information or to warn them that their actions may be audited.
    
    **Note:** Any warning that you display should first be approved by your organization's legal and human resources representatives.
  "
  impact 1.0
  tag cce: "CCE-35064-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "LegalNoticeText" }
    its("LegalNoticeText") { should match(/[a-zA-Z]/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.6_L1_Configure_Interactive_logon_Message_title_for_users_attempting_to_log_on" do
  title "(L1) Configure 'Interactive logon: Message title for users attempting to log on'"
  desc  "
    This policy setting specifies the text displayed in the title bar of the window that users see when they log on to the system. Configure this setting in a manner that is consistent with the security and operational requirements of your organization.
    
    Rationale: Displaying a warning message before logon may help prevent an attack by warning the attacker about the consequences of their misconduct before it happens. It may also help to reinforce corporate policy by notifying employees of the appropriate policy during the logon process.
  "
  impact 1.0
  tag cce: "CCE-35179-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "LegalNoticeCaption" }
    its("LegalNoticeCaption") { should match(/[a-zA-Z]/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.8_L1_Ensure_Interactive_logon_Prompt_user_to_change_password_before_expiration_is_set_to_between_5_and_14_days" do
  title "(L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
  desc  "
    This policy setting determines how far in advance users are warned that their password will expire. It is recommended that you configure this policy setting to at least 5 days but no more than 14 days to sufficiently warn users when their passwords will expire.
    
    The recommended state for this setting is: between 5 and 14 days.
    
    Rationale: Users will need to be warned that their passwords are going to expire, or they may inadvertently be locked out of the computer when their passwords expire. This condition could lead to confusion for users who access the network locally, or make it impossible for users to access your organization's network through dial-up or virtual private network (VPN) connections.
  "
  impact 1.0
  tag cce: "CCE-35274-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "passwordexpirywarning" }
    its("passwordexpirywarning") { should cmp <= 14 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "passwordexpirywarning" }
    its("passwordexpirywarning") { should cmp >= 5 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.7.9_L1_Ensure_Interactive_logon_Smart_card_removal_behavior_is_set_to_Lock_Workstation_or_higher" do
  title "(L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
  desc  "
    This policy setting determines what happens when the smart card for a logged-on user is removed from the smart card reader.
    
    The recommended state for this setting is: Lock Workstation. Configuring this setting to Force Logoff or Disconnect if a Remote Desktop Services session also conforms with the benchmark.
    
    Rationale: Users sometimes forget to lock their workstations when they are away from them, allowing the possibility for malicious users to access their computers. If smart cards are used for authentication, the computer should automatically lock itself when the card is removed to ensure that only the user with the smart card is accessing resources using those credentials.
  "
  impact 1.0
  tag cce: "CCE-34988-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "scremoveoption" }
    its("scremoveoption") { should match(/^(1|2|3)$/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.8.1_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_always_is_set_to_Enabled" do
  title "(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
  desc  "
    This policy setting determines whether packet signing is required by the SMB client component. If you enable this policy setting, the Microsoft network client computer cannot communicate with a Microsoft network server unless that server agrees to sign SMB packets. In mixed environments with legacy client computers, set this option to Disabled because these computers will not be able to authenticate or gain access to domain controllers. However, you can use this policy setting in Windows 2000 or later environments.
    
    **Note:** When Windows Vista-based computers have this policy setting enabled and they connect to file or print shares on remote servers, it is important that the setting is synchronized with its companion setting, **Microsoft network server: Digitally sign communications (always)**, on those servers. For more information about these settings, see the \"Microsoft network client and server: Digitally sign communications (four related settings)\" section in Chapter 5 of the Threats and Countermeasures guide.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Session hijacking uses tools that allow attackers who have access to the same network as the client or server to interrupt, end, or steal a session in progress. Attackers can potentially intercept and modify unsigned SMB packets and then modify the traffic and forward it so that the server might perform undesirable actions. Alternatively, the attacker could pose as the server or client after legitimate authentication and gain unauthorized access to data.
    
    SMB is the resource sharing protocol that is supported by many Windows operating systems. It is the basis of NetBIOS and many other protocols. SMB signatures authenticate both users and the servers that host the data. If either side fails the authentication process, data transmission will not take place.
  "
  impact 1.0
  tag cce: "CCE-35222-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters") do
    it { should have_property "RequireSecuritySignature" }
    its("RequireSecuritySignature") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.8.2_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_if_server_agrees_is_set_to_Enabled" do
  title "(L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
  desc  "
    This policy setting determines whether the SMB client will attempt to negotiate SMB packet signing. The implementation of digital signing in Windows-based networks helps to prevent sessions from being hijacked. If you enable this policy setting, the Microsoft network client will use signing only if the server with which it communicates accepts digitally signed communication.
    
    **Note:** Enabling this policy setting on SMB clients on your network makes them fully effective for packet signing with all clients and servers in your environment.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Session hijacking uses tools that allow attackers who have access to the same network as the client or server to interrupt, end, or steal a session in progress. Attackers can potentially intercept and modify unsigned SMB packets and then modify the traffic and forward it so that the server might perform undesirable actions. Alternatively, the attacker could pose as the server or client after legitimate authentication and gain unauthorized access to data.
    
    SMB is the resource sharing protocol that is supported by many Windows operating systems. It is the basis of NetBIOS and many other protocols. SMB signatures authenticate both users and the servers that host the data. If either side fails the authentication process, data transmission will not take place.
  "
  impact 1.0
  tag cce: "CCE-34908-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters") do
    it { should have_property "EnableSecuritySignature" }
    its("EnableSecuritySignature") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.8.3_L1_Ensure_Microsoft_network_client_Send_unencrypted_password_to_third-party_SMB_servers_is_set_to_Disabled" do
  title "(L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
  desc  "
    Disable this policy setting to prevent the SMB redirector from sending plaintext passwords during authentication to third-party SMB servers that do not support password encryption. It is recommended that you disable this policy setting unless there is a strong business case to enable it. If this policy setting is enabled, unencrypted passwords will be allowed across the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If you enable this policy setting, the server can transmit passwords in plaintext across the network to other computers that offer SMB services. These other computers may not use any of the SMB security mechanisms that are included with Windows Server 2003.
  "
  impact 1.0
  tag cce: "CCE-33717-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters") do
    it { should have_property "EnablePlainTextPassword" }
    its("EnablePlainTextPassword") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.9.1_L1_Ensure_Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session_is_set_to_15_or_fewer_minutes_but_not_0" do
  title "(L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'"
  desc  "
    This policy setting allows you to specify the amount of continuous idle time that must pass in an SMB session before the session is suspended because of inactivity. Administrators can use this policy setting to control when a computer suspends an inactive SMB session. If client activity resumes, the session is automatically reestablished.
    
    A value of 0 appears to allow sessions to persist indefinitely. The maximum value is 99999, which is over 69 days; in effect, this value disables the setting.
    
    The recommended state for this setting is: 15 or fewer minute(s), but not 0.
    
    Rationale: Each SMB session consumes server resources, and numerous null sessions will slow the server or possibly cause it to fail. An attacker could repeatedly establish SMB sessions until the server's SMB services become slow or unresponsive.
  "
  impact 1.0
  tag cce: "CCE-34909-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "autodisconnect" }
    its("autodisconnect") { should cmp <= 15 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "autodisconnect" }
    its("autodisconnect") { should cmp != 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.9.2_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_always_is_set_to_Enabled" do
  title "(L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
  desc  "
    This policy setting determines if the server side SMB service is required to perform SMB packet signing. Enable this policy setting in a mixed environment to prevent downstream clients from using the workstation as a network server.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Session hijacking uses tools that allow attackers who have access to the same network as the client or server to interrupt, end, or steal a session in progress. Attackers can potentially intercept and modify unsigned SMB packets and then modify the traffic and forward it so that the server might perform undesirable actions. Alternatively, the attacker could pose as the server or client after legitimate authentication and gain unauthorized access to data.
    
    SMB is the resource sharing protocol that is supported by many Windows operating systems. It is the basis of NetBIOS and many other protocols. SMB signatures authenticate both users and the servers that host the data. If either side fails the authentication process, data transmission will not take place.
  "
  impact 1.0
  tag cce: "CCE-35065-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "requiresecuritysignature" }
    its("requiresecuritysignature") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.9.3_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_if_client_agrees_is_set_to_Enabled" do
  title "(L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
  desc  "
    This policy setting determines if the server side SMB service is able to sign SMB packets if it is requested to do so by a client that attempts to establish a connection. If no signing request comes from the client, a connection will be allowed without a signature if the **Microsoft network server: Digitally sign communications (always)** setting is not enabled.
    
    **Note:** Enable this policy setting on SMB clients on your network to make them fully effective for packet signing with all clients and servers in your environment.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Session hijacking uses tools that allow attackers who have access to the same network as the client or server to interrupt, end, or steal a session in progress. Attackers can potentially intercept and modify unsigned SMB packets and then modify the traffic and forward it so that the server might perform undesirable actions. Alternatively, the attacker could pose as the server or client after legitimate authentication and gain unauthorized access to data.
    
    SMB is the resource sharing protocol that is supported by many Windows operating systems. It is the basis of NetBIOS and many other protocols. SMB signatures authenticate both users and the servers that host the data. If either side fails the authentication process, data transmission will not take place.
  "
  impact 1.0
  tag cce: "CCE-35182-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "enablesecuritysignature" }
    its("enablesecuritysignature") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.9.4_L1_Ensure_Microsoft_network_server_Disconnect_clients_when_logon_hours_expire_is_set_to_Enabled" do
  title "(L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
  desc  "
    This policy setting determines whether to disconnect users who are connected to the local computer outside their user account's valid logon hours. It affects the SMB component. If you enable this policy setting, client sessions with the SMB service will be forcibly disconnected when the client's logon hours expire. If you disable this policy setting, established client sessions will be maintained after the client's logon hours expire. If you enable this policy setting you should also enable **Network security: Force logoff when logon hours expire**.
    
    If your organization configures logon hours for users, this policy setting is necessary to ensure they are effective.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If your organization configures logon hours for users, then it makes sense to enable this policy setting. Otherwise, users who should not have access to network resources outside of their logon hours may actually be able to continue to use those resources with sessions that were established during allowed hours.
  "
  impact 1.0
  tag cce: "CCE-34911-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "enableforcedlogoff" }
    its("enableforcedlogoff") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.9.5_L1_Ensure_Microsoft_network_server_Server_SPN_target_name_validation_level_is_set_to_Accept_if_provided_by_client_or_higher" do
  title "(L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
  desc  "
    This policy setting controls the level of validation a computer with shared folders or printers (the server) performs on the service principal name (SPN) that is provided by the client computer when it establishes a session using the server message block (SMB) protocol.
    
    The server message block (SMB) protocol provides the basis for file and print sharing and other networking operations, such as remote Windows administration. The SMB protocol supports validating the SMB server service principal name (SPN) within the authentication blob provided by a SMB client to prevent a class of attacks against SMB servers referred to as SMB relay attacks. This setting will affect both SMB1 and SMB2.
    
    This security setting determines the level of validation a SMB server performs on the service principal name (SPN) provided by the SMB client when trying to establish a session to an SMB server.
    
    The recommended state for this setting is: Accept if provided by client. Configuring this setting to Required from client also conforms with the benchmark.
    
    Rationale: The identity of a computer can be spoofed to gain unauthorized access to network resources.
  "
  impact 1.0
  tag cce: "CCE-35299-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "SMBServerNameHardeningLevel" }
    its("SMBServerNameHardeningLevel") { should cmp >= 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.1_L1_Ensure_Network_access_Allow_anonymous_SIDName_translation_is_set_to_Disabled" do
  title "(L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
  desc  "
    This policy setting determines whether an anonymous user can request security identifier (SID) attributes for another user, or use a SID to obtain its corresponding user name. Disable this policy setting to prevent unauthenticated users from obtaining user names that are associated with their respective SIDs.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If this policy setting is enabled, a user with local access could use the well-known Administrator's SID to learn the real name of the built-in Administrator account, even if it has been renamed. That person could then use the account name to initiate a password guessing attack.
  "
  impact 1.0
  tag cce: "CCE-34914-2"
  describe wmi({:namespace=>"root\\rsop\\computer", :query=>"SELECT Setting FROM RSOP_SecuritySettingBoolean WHERE KeyName='LSAAnonymousNameLookup' AND Precedence=1"}) do
    its("setting") { should cmp "False" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.2_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_is_set_to_Enabled" do
  title "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
  desc  "
    This policy setting controls the ability of anonymous users to enumerate the accounts in the Security Accounts Manager (SAM). If you enable this policy setting, users with anonymous connections cannot enumerate domain account user names on the workstations in your environment. This policy setting also allows additional restrictions on anonymous connections.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An unauthorized user could anonymously list account names and use the information to perform social engineering attacks or attempt to guess passwords. (Social engineering attacks try to deceive users in some way to obtain passwords or some form of security information.)
  "
  impact 1.0
  tag cce: "CCE-34631-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "RestrictAnonymousSAM" }
    its("RestrictAnonymousSAM") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.3_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares_is_set_to_Enabled" do
  title "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
  desc  "
    This policy setting controls the ability of anonymous users to enumerate SAM accounts as well as shares. If you enable this policy setting, anonymous users will not be able to enumerate domain account user names and network share names on the workstations in your environment.
    
    The Network access: Do not allow anonymous enumeration of SAM accounts and shares setting is configured to Enabled for the two environments that are discussed in this guide.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An unauthorized user could anonymously list account names and shared resources and use the information to attempt to guess passwords or perform social engineering attacks.
  "
  impact 1.0
  tag cce: "CCE-34723-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "RestrictAnonymous" }
    its("RestrictAnonymous") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.4_L1_Ensure_Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication_is_set_to_Enabled" do
  title "(L1) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
  desc  "
    This policy setting determines whether the Stored User Names and Passwords feature may save passwords or credentials for later use when it gains domain authentication. If you enable this policy setting, the Stored User Names and Passwords feature of Windows does not store passwords and credentials.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Passwords that are cached can be accessed by the user when logged on to the computer. Although this information may sound obvious, a problem can arise if the user unknowingly executes hostile code that reads the passwords and forwards them to another, unauthorized user.
  "
  impact 1.0
  tag cce: "CCE-33718-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "disabledomaincreds" }
    its("disabledomaincreds") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.5_L1_Ensure_Network_access_Let_Everyone_permissions_apply_to_anonymous_users_is_set_to_Disabled" do
  title "(L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
  desc  "
    This policy setting determines what additional permissions are assigned for anonymous connections to the computer. If you enable this policy setting, anonymous Windows users are allowed to perform certain activities, such as enumerate the names of domain accounts and network shares. An unauthorized user could anonymously list account names and shared resources and use the information to guess passwords or perform social engineering attacks.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: An unauthorized user could anonymously list account names and shared resources and use the information to attempt to guess passwords, perform social engineering attacks, or launch DoS attacks.
  "
  impact 1.0
  tag cce: "CCE-35367-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "EveryoneIncludesAnonymous" }
    its("EveryoneIncludesAnonymous") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.6_L1_Ensure_Network_access_Named_Pipes_that_can_be_accessed_anonymously_is_set_to_None" do
  title "(L1) Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'"
  desc  "
    This policy setting determines which communication sessions, or pipes, will have attributes and permissions that allow anonymous access.
    
    The recommended state for this setting is: 
    <blank> (i.e. None).</blank>
    
    Rationale: Limiting named pipes that can be accessed anonymously will reduce the attack surface of the system.
  "
  impact 1.0
  tag cce: "CCE-34965-4"
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters').NullSessionPipes&.reject { |value| value =~ /.+/ } || [] do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.7_L1_Ensure_Network_access_Remotely_accessible_registry_paths" do
  title "(L1) Ensure 'Network access: Remotely accessible registry paths'"
  desc  "
    This policy setting determines which registry paths will be accessible after referencing the WinReg key to determine access permissions to the paths.
    
    **Note:** This setting does not exist in Windows XP. There was a setting with that name in Windows XP, but it is called \"Network access: Remotely accessible registry paths and sub-paths\" in Windows Server 2003, Windows Vista, and Windows Server 2008.
    
    **Note:** When you configure this setting you specify a list of one or more objects. The delimiter used when entering the list is a line feed or carriage return, that is, type the first object on the list, press the Enter button, type the next object, press Enter again, etc. The setting value is stored as a comma-delimited list in group policy security templates. It is also rendered as a comma-delimited list in Group Policy Editor's display pane and the Resultant Set of Policy console. It is recorded in the registry as a line-feed delimited list in a REG_MULTI_SZ value.
    
    The recommended state for this setting is:
    
    System\\CurrentControlSet\\Control\\ProductOptions
    System\\CurrentControlSet\\Control\\Server Applications
    Software\\Microsoft\\Windows NT\\CurrentVersion
    
    Rationale: The registry is a database that contains computer configuration information, and much of the information is sensitive. An attacker could use this information to facilitate unauthorized activities. To reduce the risk of such an attack, suitable ACLs are assigned throughout the registry to help protect it from access by unauthorized users.
  "
  impact 1.0
  tag cce: "CCE-33976-2"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths').Machine&.reject { |value| value =~ /^((System\\CurrentControlSet\\Control\\ProductOptions)|(System\\CurrentControlSet\\Control\\Server Applications)|(Software\\Microsoft\\Windows NT\\CurrentVersion))$/ } || [] do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.8_L1_Ensure_Network_access_Remotely_accessible_registry_paths_and_sub-paths" do
  title "(L1) Ensure 'Network access: Remotely accessible registry paths and sub-paths'"
  desc  "
    This policy setting determines which registry paths and sub-paths will be accessible when an application or process references the WinReg key to determine access permissions.
    
    **Note:** In Windows XP this setting is called \"Network access: Remotely accessible registry paths,\" the setting with that same name in Windows Vista, Windows Server 2008, and Windows Server 2003 does not exist in Windows XP.
    
    **Note #2:** When you configure this setting you specify a list of one or more objects. The delimiter used when entering the list is a line feed or carriage return, that is, type the first object on the list, press the Enter button, type the next object, press Enter again, etc. The setting value is stored as a comma-delimited list in group policy security templates. It is also rendered as a comma-delimited list in Group Policy Editor's display pane and the Resultant Set of Policy console. It is recorded in the registry as a line-feed delimited list in a REG_MULTI_SZ value.
    
    The recommended state for this setting is:
    
    System\\CurrentControlSet\\Control\\Print\\Printers
    System\\CurrentControlSet\\Services\\Eventlog
    Software\\Microsoft\\OLAP Server
    Software\\Microsoft\\Windows NT\\CurrentVersion\\Print
    Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows
    System\\CurrentControlSet\\Control\\ContentIndex
    System\\CurrentControlSet\\Control\\Terminal Server
    System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig
    System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration
    Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib
    System\\CurrentControlSet\\Services\\SysmonLog
    
    Rationale: The registry contains sensitive computer configuration information that could be used by an attacker to facilitate unauthorized activities. The fact that the default ACLs assigned throughout the registry are fairly restrictive and help to protect the registry from access by unauthorized users reduces the risk of such an attack.
  "
  impact 1.0
  tag cce: "CCE-35300-3"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths').Machine&.reject { |value| value =~ /^((System\\CurrentControlSet\\Control\\Print\\Printers)|(System\\CurrentControlSet\\Services\\Eventlog)|(Software\\Microsoft\\OLAP Server)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Print)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows)|(System\\CurrentControlSet\\Control\\ContentIndex)|(System\\CurrentControlSet\\Control\\Terminal Server)|(System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig)|(System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration)|(Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib)|(System\\CurrentControlSet\\Services\\SysmonLog))$/ } || [] do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.9_L1_Ensure_Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares_is_set_to_Enabled" do
  title "(L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
  desc  "
    When enabled, this policy setting restricts anonymous access to only those shares and pipes that are named in the Network access: Named pipes that can be accessed anonymously and Network access: Shares that can be accessed anonymously settings. This policy setting controls null session access to shares on your computers by adding RestrictNullSessAccess with the value 1 in the
    
    HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters
    
    registry key. This registry value toggles null session shares on or off to control whether the server service restricts unauthenticated clients' access to named resources.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Null sessions are a weakness that can be exploited through shares (including the default shares) on computers in your environment.
  "
  impact 1.0
  tag cce: "CCE-33563-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "restrictnullsessaccess" }
    its("restrictnullsessaccess") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.10_L1_Ensure_Network_access_Shares_that_can_be_accessed_anonymously_is_set_to_None" do
  title "(L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
  desc  "
    This policy setting determines which network shares can be accessed by anonymous users. The default configuration for this policy setting has little effect because all users have to be authenticated before they can access shared resources on the server.
    
    The recommended state for this setting is: 
    <blank> (i.e. None).</blank>
    
    Rationale: It is very dangerous to enable this setting. Any shares that are listed can be accessed by any network user, which could lead to the exposure or corruption of sensitive data.
  "
  impact 1.0
  tag cce: "CCE-34651-0"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters').NullSessionShares&.reject { |value| value =~ /^$/ } || [] do
    it { should be_empty }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.10.11_L1_Ensure_Network_access_Sharing_and_security_model_for_local_accounts_is_set_to_Classic_-_local_users_authenticate_as_themselves" do
  title "(L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
  desc  "
    This policy setting determines how network logons that use local accounts are authenticated. The Classic option allows precise control over access to resources, including the ability to assign different types of access to different users for the same resource. The Guest only option allows you to treat all users equally. In this context, all users authenticate as Guest only to receive the same access level to a given resource.
    
    The recommended state for this setting is: Classic - local users authenticate as themselves.
    
    Rationale: With the Guest only model, any user who can authenticate to your computer over the network does so with guest privileges, which probably means that they will not have write access to shared resources on that computer. Although this restriction does increase security, it makes it more difficult for authorized users to access shared resources on those computers because ACLs on those resources must include access control entries (ACEs) for the Guest account. With the Classic model, local accounts should be password protected. Otherwise, if Guest access is enabled, anyone can use those user accounts to access shared system resources.
  "
  impact 1.0
  tag cce: "CCE-33719-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "ForceGuest" }
    its("ForceGuest") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.1_L1_Ensure_Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM_is_set_to_Enabled" do
  title "(L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
  desc  "
    When enabled, this policy setting causes Local System services that use Negotiate to use the computer identity when NTLM authentication is selected by the negotiation. This policy is supported on at least Windows 7 or Windows Server 2008 R2.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: When connecting to computers running versions of Windows earlier than Windows Vista or Windows Server 2008, services running as Local System and using SPNEGO (Negotiate) that revert to NTLM use the computer identity. In Windows 7, if you are connecting to a computer running Windows Server 2008 or Windows Vista, then a system service uses either the computer identity or a NULL session. When connecting with a NULL session, a system-generated session key is created, which provides no protection but allows applications to sign and encrypt data without errors. When connecting with the computer identity, both signing and encryption is supported in order to provide data protection.
  "
  impact 1.0
  tag cce: "CCE-33141-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "UseMachineId" }
    its("UseMachineId") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.2_L1_Ensure_Network_security_Allow_LocalSystem_NULL_session_fallback_is_set_to_Disabled" do
  title "(L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
  desc  "
    Allow NTLM to fall back to NULL session when used with LocalSystem. The default is TRUE up to Windows Vista / Server 2008 and FALSE from Windows 7 / Server 2008 R2 and beyond.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: NULL sessions are less secure because by definition they are unauthenticated.
  "
  impact 1.0
  tag cce: "CCE-35410-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "allownullsessionfallback" }
    its("allownullsessionfallback") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.3_L1_Ensure_Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities_is_set_to_Disabled" do
  title "(L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
  desc  "
    This setting determines if online identities are able to authenticate to this computer.
    
    Windows 7 and Windows Server 2008 R2 introduced an extension to the Negotiate authentication package, Spnego.dll. In previous versions of Windows, Negotiate decides whether to use Kerberos or NTLM for authentication. The extension SSP for Negotiate, Negoexts, which is treated as an authentication protocol by Windows, supports Microsoft SSPs including PKU2U.
    
    When computers are configured to accept authentication requests by using online IDs, Negoexts.dll calls the PKU2U SSP on the computer that is used to log on. The PKU2U SSP obtains a local certificate and exchanges the policy between the peer computers. When validated on the peer computer, the certificate within the metadata is sent to the logon peer for validation and associates the user's certificate to a security token and the logon process completes.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: The PKU2U protocol is a peer-to-peer authentication protocol, in most managed networks authentication should be managed centrally.
  "
  impact 1.0
  tag cce: "CCE-35411-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u") do
    it { should have_property "AllowOnlineID" }
    its("AllowOnlineID") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.4_L1_Ensure_Network_Security_Configure_encryption_types_allowed_for_Kerberos_is_set_to_RC4_HMAC_MD5_AES128_HMAC_SHA1_AES256_HMAC_SHA1_Future_encryption_types" do
  title "(L1) Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
  desc  "
    This policy setting allows you to set the encryption types that Kerberos is allowed to use. This policy is supported on at least Windows 7 or Windows Server 2008 R2.
    
    The recommended state for this setting is: RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types.
    
    Rationale: The strength of each encryption algorithm varies from one to the next, choosing stronger algorithms will reduce the risk of compromise however doing so may cause issues when the computer attempts to authenticate with systems that do not support them.
  "
  impact 1.0
  tag cce: "CCE-35786-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters") do
    it { should have_property "SupportedEncryptionTypes" }
    its("SupportedEncryptionTypes") { should cmp == 2147483644 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.5_L1_Ensure_Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change_is_set_to_Enabled" do
  title "(L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
  desc  "
    This policy setting determines whether the LAN Manager (LM) hash value for the new password is stored when the password is changed. The LM hash is relatively weak and prone to attack compared to the cryptographically stronger Microsoft Windows NT hash.
    
    **Note:** Older operating systems and some third-party applications may fail when this policy setting is enabled. Also, note that the password will need to be changed on all accounts after you enable this setting to gain the proper benefit.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The SAM file can be targeted by attackers who seek access to username and password hashes. Such attacks use special tools to crack passwords, which can then be used to impersonate users and gain access to resources on your network. These types of attacks will not be prevented if you enable this policy setting, but it will be much more difficult for these types of attacks to succeed.
  "
  impact 1.0
  tag cce: "CCE-35225-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "NoLMHash" }
    its("NoLMHash") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.6_L1_Ensure_Network_security_Force_logoff_when_logon_hours_expire_is_set_to_Enabled" do
  title "(L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
  desc  "
    This policy setting, which determines whether to disconnect users who are connected to the local computer outside their user account's valid logon hours, affects the SMB component. If you enable this policy setting, client sessions with the SMB server will be disconnected when the client's logon hours expire. If you disable this policy setting, established client sessions will be maintained after the client's logon hours expire.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If this setting is disabled, a user could remain connected to the computer outside of their allotted logon hours.
  "
  impact 1.0
  tag cce: "CCE-34993-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters") do
    it { should have_property "EnableForcedLogOff" }
    its("EnableForcedLogOff") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.7_L1_Ensure_Network_security_LAN_Manager_authentication_level_is_set_to_Send_NTLMv2_response_only._Refuse_LM__NTLM" do
  title "(L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM  NTLM'"
  desc  "
    LAN Manager (LM) is a family of early Microsoft client/server software that allows users to link personal computers together on a single network. Network capabilities include transparent file and print sharing, user security features, and network administration tools. In Active Directory domains, the Kerberos protocol is the default authentication protocol. However, if the Kerberos protocol is not negotiated for some reason, Active Directory will use LM, NTLM, or NTLMv2. LAN Manager authentication includes the LM, NTLM, and NTLM version 2 (NTLMv2) variants, and is the protocol that is used to authenticate all Windows clients when they perform the following operations:
    
    * Join a domain
    * Authenticate between Active Directory forests
    * Authenticate to down-level domains
    * Authenticate to computers that do not run Windows 2000, Windows Server 2003, or Windows XP)
    * Authenticate to computers that are not in the domain
    The possible values for the Network security: LAN Manager authentication level setting are:
    
    * Send LM  NTLM responses
    * Send LM  NTLM #x2014; use NTLMv2 session security if negotiated
    * Send NTLM responses only
    * Send NTLMv2 responses only
    * Send NTLMv2 responses only\\refuse LM
    * Send NTLMv2 responses only\\refuse LM  NTLM
    * Not Defined
    The Network security: LAN Manager authentication level setting determines which challenge/response authentication protocol is used for network logons. This choice affects the authentication protocol level that clients use, the session security level that the computers negotiate, and the authentication level that servers accept as follows:
    
    * Send LM  NTLM responses. Clients use LM and NTLM authentication and never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Send LM  NTLM - use NTLMv2 session security if negotiated. Clients use LM and NTLM authentication and use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Send NTLM response only. Clients use NTLM authentication only and use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Send NTLMv2 response only. Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Send NTLMv2 response only\\refuse LM. Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it. Domain controllers refuse LM (accept only NTLM and NTLMv2 authentication).
    * Send NTLMv2 response only\\refuse LM  NTLM. Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it. Domain controllers refuse LM and NTLM (accept only NTLMv2 authentication).
    * These settings correspond to the levels discussed in other Microsoft documents as follows:
    * Level 0 - Send LM and NTLM response; never use NTLMv2 session security. Clients use LM and NTLM authentication, and never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Level 1 - Use NTLMv2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Level 2 - Send NTLM response only. Clients use only NTLM authentication, and use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Level 3 - Send NTLMv2 response only. Clients use NTLMv2 authentication, and use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
    * Level 4 - Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLMv2 session security if the server supports it. Domain controllers refuse LM authentication, that is, they accept NTLM and NTLMv2.
    * Level 5 - Domain controllers refuse LM and NTLM responses (accept only NTLMv2). Clients use NTLMv2 authentication, use and NTLMv2 session security if the server supports it. Domain controllers refuse NTLM and LM authentication (they accept only NTLMv2).
    The recommended state for this setting is: Send NTLMv2 response only. Refuse LM  NTLM.
    
    Rationale: In Windows Vista, this setting is undefined. However, in Windows 2000, Windows Server 2003, and Windows XP clients are configured by default to send LM and NTLM authentication responses (Windows 95-based and Windows 98-based clients only send LM). The default setting on servers allows all clients to authenticate with servers and use their resources. However, this means that LM responses#x2014;the weakest form of authentication response#x2014;are sent over the network, and it is potentially possible for attackers to sniff that traffic to more easily reproduce the user's password.
    
    The Windows 95, Windows 98, and Windows NT operating systems cannot use the Kerberos version 5 protocol for authentication. For this reason, in a Windows Server 2003 domain, these computers authenticate by default with both the LM and NTLM protocols for network authentication. You can enforce a more secure authentication protocol for Windows 95, Windows 98, and Windows NT by using NTLMv2. For the logon process, NTLMv2 uses a secure channel to protect the authentication process. Even if you use NTLMv2 for earlier clients and servers, Windows-based clients and servers that are members of the domain will use the Kerberos authentication protocol to authenticate with Windows Server 2003 domain controllers.
  "
  impact 1.0
  tag cce: "CCE-35302-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "LmCompatibilityLevel" }
    its("LmCompatibilityLevel") { should cmp == 5 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.8_L1_Ensure_Network_security_LDAP_client_signing_requirements_is_set_to_Negotiate_signing_or_higher" do
  title "(L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
  desc  "
    This policy setting determines the level of data signing that is requested on behalf of clients that issue LDAP BIND requests, as follows:
    - None. The LDAP BIND request is issued with the caller-specified options.
    - Negotiate signing. If Transport Layer Security/Secure Sockets Layer (TLS/SSL) has not been started, the LDAP BIND request is initiated with the LDAP data signing option set in addition to the caller-specified options. If TLS/SSL has been started, the LDAP BIND request is initiated with the caller-specified options.
    - Require signature. This level is the same as Negotiate signing. However, if the LDAP server's intermediate saslBindInProgress response does not indicate that LDAP traffic signing is required, the caller is told that the LDAP BIND command request failed.
    
    **Note:** This policy setting does not have any impact on ldap_simple_bind or ldap_simple_bind_s. No Microsoft LDAP clients that are included with Windows XP Professional use ldap_simple_bind or ldap_simple_bind_s to communicate with a domain controller.
    
    The possible values for the Network security: LDAP client signing requirements setting are:
    - None
    - Negotiate signing
    - Require signature
    - Not Defined
    
    The recommended state for this setting is: Negotiate signing. Configuring this setting to Require signing also conforms with the benchmark.
    
    Rationale: Unsigned network traffic is susceptible to man-in-the-middle attacks in which an intruder captures the packets between the client and server, modifies them, and then forwards them to the server. For an LDAP server, this susceptibility means that an attacker could cause a server to make decisions that are based on false or altered data from the LDAP queries. To lower this risk in your network, you can implement strong physical security measures to protect the network infrastructure. Also, you can make all types of man-in-the-middle attacks extremely difficult if you require digital signatures on all network packets by means of IPsec authentication headers.
  "
  impact 1.0
  tag cce: "CCE-33802-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP") do
    it { should have_property "LDAPClientIntegrity" }
    its("LDAPClientIntegrity") { should cmp >= 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.9_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption" do
  title "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc  "
    This policy setting determines which behaviors are allowed for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.
    
    The possible values for the Network security: Minimum session security for NTLM SSP based (including secure RPC) clients setting are:
    - Require message confidentiality. This option is only available in Windows XP and Windows Server 2003, the connection will fail if encryption is not negotiated. Encryption converts data into a form that is not readable until decrypted.
    - Require message integrity. This option is only available in Windows XP and Windows Server 2003, the connection will fail if message integrity is not negotiated. The integrity of a message can be assessed through message signing. Message signing proves that the message has not been tampered with; it attaches a cryptographic signature that identifies the sender and is a numeric representation of the contents of the message.
    - Require 128-bit encryption. The connection will fail if strong encryption (128-bit) is not negotiated.
    - Require NTLMv2
     session security. The connection will fail if the NTLMv2 protocol is not negotiated.
    - Not Defined.
    
    The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption.
    
    Rationale: You can enable all of the options for this policy setting to help protect network traffic that uses the NTLM Security Support Provider (NTLM SSP) from being exposed or tampered with by an attacker who has gained access to the same network. In other words, these options help protect against man-in-the-middle attacks.
  "
  impact 1.0
  tag cce: "CCE-35447-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinClientSec" }
    its("NTLMMinClientSec") { should cmp == 537395200 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.11.10_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption" do
  title "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
  desc  "
    This policy setting determines which behaviors are allowed for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.
    
    The possible values for the Network security: Minimum session security for NTLM SSP based (including secure RPC) servers setting are:
    - Require message confidentiality. This option is only available in Windows XP and Windows Server 2003, the connection will fail if encryption is not negotiated. Encryption converts data into a form that is not readable until decrypted.
    - Require message integrity. This option is only available in Windows XP and Windows Server 2003, the connection will fail if message integrity is not negotiated. The integrity of a message can be assessed through message signing. Message signing proves that the message has not been tampered with; it attaches a cryptographic signature that identifies the sender and is a numeric representation of the contents of the message.
    - Require 128-bit encryption. The connection will fail if strong encryption (128-bit) is not negotiated.
    - Require NTLMv2
     session security. The connection will fail if the NTLMv2 protocol is not negotiated.
    - Not Defined.
    
    The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption.
    
    Rationale: You can enable all of the options for this policy setting to help protect network traffic that uses the NTLM Security Support Provider (NTLM SSP) from being exposed or tampered with by an attacker who has gained access to the same network. That is, these options help protect against man-in-the-middle attacks.
  "
  impact 1.0
  tag cce: "CCE-35108-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinServerSec" }
    its("NTLMMinServerSec") { should cmp == 537395200 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.15.1_L1_Ensure_System_objects_Require_case_insensitivity_for_non-Windows_subsystems_is_set_to_Enabled" do
  title "(L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
  desc  "
    This policy setting determines whether case insensitivity is enforced for all subsystems. The Microsoft Win32' subsystem is case insensitive. However, the kernel supports case sensitivity for other subsystems, such as the Portable Operating System Interface for UNIX (POSIX). Because Windows is case insensitive (but the POSIX subsystem will support case sensitivity), failure to enforce this policy setting makes it possible for a user of the POSIX subsystem to create a file with the same name as another file by using mixed case to label it. Such a situation can block access to these files by another user who uses typical Win32 tools, because only one of the files will be available.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Because Windows is case-insensitive but the POSIX subsystem will support case sensitivity, failure to enable this policy setting would make it possible for a user of that subsystem to create a file with the same name as another file but with a different mix of upper and lower case letters. Such a situation could potentially confuse users when they try to access such files from normal Win32 tools because only one of the files will be available.
  "
  impact 1.0
  tag cce: "CCE-35008-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel") do
    it { should have_property "ObCaseInsensitive" }
    its("ObCaseInsensitive") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.15.2_L1_Ensure_System_objects_Strengthen_default_permissions_of_internal_system_objects_e.g._Symbolic_Links_is_set_to_Enabled" do
  title "(L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
  desc  "
    This policy setting determines the strength of the default discretionary access control list (DACL) for objects. The setting helps secure objects that can be located and shared among processes and its default configuration strengthens the DACL, because it allows users who are not administrators to read shared objects but does not allow them to modify any that they did not create.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: This setting determines the strength of the default DACL for objects. Windows Server 2003 maintains a global list of shared computer resources so that objects can be located and shared among processes. Each type of object is created with a default DACL that specifies who can access the objects and with what permissions. If you enable this setting, the default DACL is strengthened because non-administrator users are allowed to read shared objects but not modify shared objects that they did not create.
  "
  impact 1.0
  tag cce: "CCE-35232-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager") do
    it { should have_property "ProtectionMode" }
    its("ProtectionMode") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.1_L1_Ensure_User_Account_Control_Admin_Approval_Mode_for_the_Built-in_Administrator_account_is_set_to_Enabled" do
  title "(L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
  desc  "
    This policy setting controls the behavior of Admin Approval Mode for the built-in Administrator account.
    
    The options are:
    - Enabled: The built-in Administrator account uses Admin Approval Mode. By default, any operation that requires elevation of privilege will prompt the user to approve the operation.
    - Disabled: (Default) The built-in Administrator account runs all applications with full administrative privilege.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: One of the risks that the User Account Control feature introduced with Windows Vista is trying to mitigate is that of malicious software running under elevated credentials without the user or administrator being aware of its activity. An attack vector for these programs was to discover the password of the account named \"Administrator\" because that user account was created for all installations of Windows. To address this risk, in Windows Vista the built-in Administrator account is disabled. In a default installation of a new computer, accounts with administrative control over the computer are initially set up in one of two ways:
    - If the computer is not joined to a domain, the first user account you create has the equivalent permissions as a local administrator.
    - If the computer is joined to a domain, no local administrator accounts are created. The Enterprise or Domain Administrator must log on to the computer and
     create one if a local administrator account is warranted.
    
    Once Windows Vista is installed, the built-in Administrator account may be enabled, but we strongly recommend that this account remain disabled.
  "
  impact 1.0
  tag cce: "CCE-35338-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "FilterAdministratorToken" }
    its("FilterAdministratorToken") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.2_L1_Ensure_User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop_is_set_to_Disabled" do
  title "(L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'"
  desc  "
    This policy setting controls whether User Interface Accessibility (UIAccess or UIA) programs can automatically disable the secure desktop for elevation prompts used by a standard user.
    - Enabled: UIA programs, including Windows Remote Assistance, automatically disable the secure desktop for elevation prompts. If you do not disable the \"User Account Control: Switch to the secure desktop when prompting for elevation\" policy setting, the prompts appear on the interactive user's desktop instead of the secure desktop.
    - Disabled: (Default) The secure desktop can be disabled only by the user of the interactive desktop or by disabling the \"User Account Control: Switch to the secure desktop when prompting for elevation\" policy setting.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: One of the risks that the UAC feature introduced with Windows Vista is trying to mitigate is that of malicious software running under elevated credentials without the user or administrator being aware of its activity. This setting allows the administrator to perform operations that require elevated privileges while connected via Remote Assistance. This increases security in that organizations can use UAC even when end user support is provided remotely. However, it also reduces security by adding the risk that an administrator might allow an unprivileged user to share elevated privileges for an application that the administrator needs to use during the Remote Desktop session.
  "
  impact 1.0
  tag cce: "CCE-35458-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableUIADesktopToggle" }
    its("EnableUIADesktopToggle") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.3_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode_is_set_to_Prompt_for_consent_on_the_secure_desktop" do
  title "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
  desc  "
    This policy setting controls the behavior of the elevation prompt for administrators.
    
    The options are:
    - Elevate without prompting: Allows privileged accounts to perform an operation that requires elevation without requiring consent or credentials. **Note:** Use this option only in the most constrained environments.
    - Prompt for credentials on the secure desktop: When an operation requires elevation of privilege, the user is prompted on the secure desktop to enter a privileged user name and password. If the user enters valid credentials, the operation continues with the user's highest available privilege.
    - Prompt for consent on the secure desktop: When an operation requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.
    - Prompt for credentials: When an operation requires elevation of privilege, the user is prompted to enter an
     administrative user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.
    - Prompt for consent: When an operation requires elevation of privilege, the user is prompted to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.
    - Prompt for consent for non-Windows binaries: (Default) When an operation for a non-Microsoft application requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.
    
    The recommended state for this setting is: Prompt for consent on the secure desktop.
    
    Rationale: One of the risks that the UAC feature introduced with Windows Vista is trying to mitigate is that of malicious software running under elevated credentials without the user or administrator being aware of its activity. This setting raises awareness to the administrator of elevated privilege operations and permits the administrator to prevent a malicious program from elevating its privilege when the program attempts to do so.
  "
  impact 1.0
  tag cce: "CCE-33784-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "ConsentPromptBehaviorAdmin" }
    its("ConsentPromptBehaviorAdmin") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.4_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users_is_set_to_Automatically_deny_elevation_requests" do
  title "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
  desc  "
    This policy setting controls the behavior of the elevation prompt for standard users. The options are:
    
    * Prompt for credentials: When an operation requires elevation of privilege, the user is prompted to enter an administrative user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.
    * Automatically deny elevation requests: When an operation requires elevation of privilege, a configurable access denied error message is displayed. An enterprise that is running desktops as standard user may choose this setting to reduce help desk calls.
    * Prompt for credentials on the secure desktop: (Default) When an operation requires elevation of privilege, the user is prompted on the secure desktop to enter a different user name and password. If the user enters valid credentials, the operation continues with the applicable privilege. Note that this option was introduced in Windows 7 and it is not applicable to computers running Windows Vista or Windows Server 2008.
    The recommended state for this setting is: Automatically deny elevation requests.
    
    Rationale: One of the risks that the User Account Control feature introduced with Windows Vista is trying to mitigate is that of malicious programs running under elevated credentials without the user or administrator being aware of their activity. This setting raises awareness to the user that a program requires the use of elevated privilege operations and requires that the user be able to supply administrative credentials in order for the program to run.
  "
  impact 1.0
  tag cce: "CCE-33785-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "ConsentPromptBehaviorUser" }
    its("ConsentPromptBehaviorUser") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.5_L1_Ensure_User_Account_Control_Detect_application_installations_and_prompt_for_elevation_is_set_to_Enabled" do
  title "(L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
  desc  "
    This policy setting controls the behavior of application installation detection for the computer.
    
    The options are:
    - Enabled: (Default for home) When an application installation package is detected that requires elevation of privilege, the user is prompted to enter an administrative user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.
    - Disabled: (Default for enterprise) Application installation packages are not detected and prompted for elevation. Enterprises that are running standard user desktops and use delegated installation technologies such as Group Policy Software Installation or Systems Management Server (SMS) should disable this policy setting. In this case, installer detection is unnecessary.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Some malicious software will attempt to install itself after being given permission to run. For example, malicious software with a trusted application shell. The user may have given permission for the program to run because the program is trusted, but if they are then prompted for installation of an unknown component this provides another way of trapping the software before it can do damage
  "
  impact 1.0
  tag cce: "CCE-35429-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableInstallerDetection" }
    its("EnableInstallerDetection") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.6_L1_Ensure_User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations_is_set_to_Enabled" do
  title "(L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
  desc  "
    This policy setting controls whether applications that request to run with a User Interface Accessibility (UIAccess) integrity level must reside in a secure location in the file system. Secure locations are limited to the following:
    - #x2026;\\Program Files\\, including subfolders
    - #x2026;\\Windows\\system32\\
    - #x2026;\\Program Files (x86)\\, including subfolders for 64-bit versions of Windows
    
    **Note:** Windows enforces a public key infrastructure (PKI) signature check on any interactive application that requests to run with a UIAccess integrity level regardless of the state of this security setting.
    
    The options are:
    - Enabled: (Default) If an application resides in a secure location in the file system, it runs only with UIAccess integrity.
    - Disabled: An application runs with UIAccess integrity even if it does not reside in a secure location in the file system.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: UIAccess Integrity allows an application to bypass User Interface Privilege Isolation (UIPI) restrictions when an application is elevated in privilege from a standard user to an administrator. This is required to support accessibility features such as screen readers that are transmitting user interfaces to alternative forms. A process that is started with UIAccess rights has the following abilities:
    - To set the foreground window.
    - To drive any application window using SendInput function.
    - To use read input for all integrity levels using low-level hooks, raw input, GetKeyState, GetAsyncKeyState, and GetKeyboardInput.
    - To set journal hooks.
    - To uses AttachThreadInput to attach a thread to a higher integrity input queue.
  "
  impact 1.0
  tag cce: "CCE-35401-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableSecureUIAPaths" }
    its("EnableSecureUIAPaths") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.7_L1_Ensure_User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode_is_set_to_Enabled" do
  title "(L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
  desc  "
    This policy setting controls the behavior of all User Account Control (UAC) policy settings for the computer. If you change this policy setting, you must restart your computer.
    
    The options are:
    - Enabled: (Default) Admin Approval Mode is enabled. This policy must be enabled and related UAC policy settings must also be set appropriately to allow the built-in Administrator account and all other users who are members of the Administrators group to run in Admin Approval Mode.
    - Disabled: Admin Approval Mode and all related UAC policy settings are disabled. **Note:** If this policy setting is disabled, the Security Center notifies you that the overall security of the operating system has been reduced.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: This is the setting that turns on or off UAC. If this setting is disabled, UAC will not be used and any security benefits and risk mitigations that are dependent on UAC will not be present on the system.
  "
  impact 1.0
  tag cce: "CCE-33788-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableLUA" }
    its("EnableLUA") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.8_L1_Ensure_User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation_is_set_to_Enabled" do
  title "(L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
  desc  "
    This policy setting controls whether the elevation request prompt is displayed on the interactive user's desktop or the secure desktop.
    
    The options are:
    - Enabled: (Default) All elevation requests go to the secure desktop regardless of prompt behavior policy settings for administrators and standard users.
    - Disabled: All elevation requests go to the interactive user's desktop. Prompt behavior policy settings for administrators and standard users are used.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Elevation prompt dialog boxes can be spoofed, causing users to disclose their passwords to malicious software.
  "
  impact 1.0
  tag cce: "CCE-33815-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "PromptOnSecureDesktop" }
    its("PromptOnSecureDesktop") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.3.17.9_L1_Ensure_User_Account_Control_Virtualize_file_and_registry_write_failures_to_per-user_locations_is_set_to_Enabled" do
  title "(L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
  desc  "
    This policy setting controls whether application write failures are redirected to defined registry and file system locations. This policy setting mitigates applications that run as administrator and write run-time application data to %ProgramFiles%, %Windir%, %Windir%\\system32, or HKEY_LOCAL_MACHINE\\Software.
    
    The options are:
    - Enabled: (Default) Application write failures are redirected at run time to defined user locations for both the file system and registry.
    - Disabled: Applications that write data to protected locations fail.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: This setting reduces vulnerabilities by ensuring that legacy applications only write data to permitted locations.
  "
  impact 1.0
  tag cce: "CCE-35459-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableVirtualization" }
    its("EnableVirtualization") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.1_L1_Ensure_Windows_Firewall_Domain_Firewall_state_is_set_to_On_recommended" do
  title "(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
  desc  "
    Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.
    
    The recommended state for this setting is: On (recommended).
    
    Rationale: If the firewall is turned off all traffic will be able to access the system and an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  tag cce: "CCE-33160-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.2_L1_Ensure_Windows_Firewall_Domain_Inbound_connections_is_set_to_Block_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
  desc  "
    This setting determines the behavior for inbound connections that do not match an inbound firewall rule. The default behavior is to block connections unless there are firewall rules to allow the connection.
    
    The recommended state for this setting is: Block (default).
    
    Rationale: If the firewall allows all traffic to access the system then an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  tag cce: "CCE-33063-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "DefaultInboundAction" }
    its("DefaultInboundAction") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.3_L1_Ensure_Windows_Firewall_Domain_Outbound_connections_is_set_to_Allow_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
  desc  "
    This setting determines the behavior for outbound connections that do not match an outbound firewall rule. In Windows Vista / Server 2008 and above, the default behavior is to allow connections unless there are firewall rules that block the connection.
    
    The recommended state for this setting is: Allow (default).
    
    Rationale: Some people believe that it is prudent to block all outbound connections except those specifically approved by the user or administrator. Microsoft disagrees with this opinion, blocking outbound connections by default will force users to deal with a large number of dialog boxes prompting them to authorize or block applications such as their web browser or instant messaging software. Additionally, blocking outbound traffic has little value because if an attacker has compromised the system they can reconfigure the firewall anyway.
  "
  impact 1.0
  tag cce: "CCE-33098-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "DefaultOutboundAction" }
    its("DefaultOutboundAction") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.4_L1_Ensure_Windows_Firewall_Domain_Settings_Display_a_notification_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
  desc  "
    Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.
    
    **Note:** When the Apply local firewall rules setting is configured to No, it's recommended to also configure the Display a notification setting to No. Otherwise, users will continue to receive messages that ask if they want to unblock a restricted inbound connection, but the user's response will be ignored.
    
    The recommended state for this setting is: No.
    
    Rationale: Firewall notifications can be complex and may confuse the end users, who would not be able to address the alert.
  "
  impact 1.0
  tag cce: "CCE-33062-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "DisableNotifications" }
    its("DisableNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.5_L1_Ensure_Windows_Firewall_Domain_Settings_Apply_local_firewall_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  tag cce: "CCE-33061-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "AllowLocalPolicyMerge" }
    its("AllowLocalPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.6_L1_Ensure_Windows_Firewall_Domain_Settings_Apply_local_connection_security_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  tag cce: "CCE-35701-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "AllowLocalIPsecPolicyMerge" }
    its("AllowLocalIPsecPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.7_L1_Ensure_Windows_Firewall_Domain_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewalldomainfw.log" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log'"
  desc  "
    Use this option to specify the path and name of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-34176-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogFilePath" }
    its("LogFilePath") { should cmp "%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.8_L1_Ensure_Windows_Firewall_Domain_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  "
    Use this option to specify the size limit of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: 16,384 KB or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35083-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogFileSize" }
    its("LogFileSize") { should cmp >= 16384 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.9_L1_Ensure_Windows_Firewall_Domain_Logging_Log_dropped_packets_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35252-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogDroppedPackets" }
    its("LogDroppedPackets") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.10_L1_Ensure_Windows_Firewall_Domain_Logging_Log_successful_connections_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35306-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogSuccessfulConnections" }
    its("LogSuccessfulConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.1_L1_Ensure_Windows_Firewall_Private_Firewall_state_is_set_to_On_recommended" do
  title "(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
  desc  "
    Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.
    
    The recommended state for this setting is: On (recommended).
    
    Rationale: If the firewall is turned off all traffic will be able to access the system and an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  tag cce: "CCE-33066-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.2_L1_Ensure_Windows_Firewall_Private_Inbound_connections_is_set_to_Block_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
  desc  "
    This setting determines the behavior for inbound connections that do not match an inbound firewall rule. The default behavior is to block connections unless there are firewall rules to allow the connection.
    
    The recommended state for this setting is: Block (default).
    
    Rationale: If the firewall allows all traffic to access the system then an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  tag cce: "CCE-33161-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "DefaultInboundAction" }
    its("DefaultInboundAction") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.3_L1_Ensure_Windows_Firewall_Private_Outbound_connections_is_set_to_Allow_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
  desc  "
    This setting determines the behavior for outbound connections that do not match an outbound firewall rule. The default behavior is to allow connections unless there are firewall rules that block the connection.
    
    **Important:** If you set Outbound connections to Block and then deploy the firewall policy by using a GPO, computers that receive the GPO settings cannot receive subsequent Group Policy updates unless you create and deploy an outbound rule that enables Group Policy to work. Predefined rules for Core Networking include outbound rules that enable Group Policy to work. Ensure that these outbound rules are active, and thoroughly test firewall profiles before deploying.
    
    The recommended state for this setting is: Allow (default).
    
    Rationale: Some people believe that it is prudent to block all outbound connections except those specifically approved by the user or administrator. Microsoft disagrees with this opinion, blocking outbound connections by default will force users to deal with a large number of dialog boxes prompting them to authorize or block applications such as their web browser or instant messaging software. Additionally, blocking outbound traffic has little value because if an attacker has compromised the system they can reconfigure the firewall anyway.
  "
  impact 1.0
  tag cce: "CCE-33162-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "DefaultOutboundAction" }
    its("DefaultOutboundAction") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.4_L1_Ensure_Windows_Firewall_Private_Settings_Display_a_notification_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
  desc  "
    Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.
    
    **Note:** When the Apply local firewall rules setting is configured to No, it's recommended to also configure the Display a notification setting to No. Otherwise, users will continue to receive messages that ask if they want to unblock a restricted inbound connection, but the user's response will be ignored.
    
    The recommended state for this setting is: No.
    
    Rationale: Firewall notifications can be complex and may confuse the end users, who would not be able to address the alert.
  "
  impact 1.0
  tag cce: "CCE-33065-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "DisableNotifications" }
    its("DisableNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.5_L1_Ensure_Windows_Firewall_Private_Settings_Apply_local_firewall_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  tag cce: "CCE-35702-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "AllowLocalPolicyMerge" }
    its("AllowLocalPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.6_L1_Ensure_Windows_Firewall_Private_Settings_Apply_local_connection_security_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  tag cce: "CCE-33064-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "AllowLocalIPsecPolicyMerge" }
    its("AllowLocalIPsecPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.7_L1_Ensure_Windows_Firewall_Private_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallprivatefw.log" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log'"
  desc  "
    Use this option to specify the path and name of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-33437-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogFilePath" }
    its("LogFilePath") { should cmp "%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.8_L1_Ensure_Windows_Firewall_Private_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  "
    Use this option to specify the size limit of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: 16,384 KB or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-34356-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogFileSize" }
    its("LogFileSize") { should cmp >= 16384 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.9_L1_Ensure_Windows_Firewall_Private_Logging_Log_dropped_packets_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-33436-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogDroppedPackets" }
    its("LogDroppedPackets") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.10_L1_Ensure_Windows_Firewall_Private_Logging_Log_successful_connections_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-34177-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogSuccessfulConnections" }
    its("LogSuccessfulConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.1_L1_Ensure_Windows_Firewall_Public_Firewall_state_is_set_to_On_recommended" do
  title "(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
  desc  "
    Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.
    
    The recommended state for this setting is: On (recommended).
    
    Rationale: If the firewall is turned off all traffic will be able to access the system and an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  tag cce: "CCE-35703-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.2_L1_Ensure_Windows_Firewall_Public_Inbound_connections_is_set_to_Block_default" do
  title "(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
  desc  "
    This setting determines the behavior for inbound connections that do not match an inbound firewall rule. The default behavior is to block connections unless there are firewall rules to allow the connection.
    
    The recommended state for this setting is: Block (default).
    
    Rationale: If the firewall allows all traffic to access the system then an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  tag cce: "CCE-33069-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "DefaultInboundAction" }
    its("DefaultInboundAction") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.3_L1_Ensure_Windows_Firewall_Public_Outbound_connections_is_set_to_Allow_default" do
  title "(L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
  desc  "
    This setting determines the behavior for outbound connections that do not match an outbound firewall rule. The default behavior is to allow connections unless there are firewall rules that block the connection.
    
    **Important:** If you set Outbound connections to Block and then deploy the firewall policy by using a GPO, computers that receive the GPO settings cannot receive subsequent Group Policy updates unless you create and deploy an outbound rule that enables Group Policy to work. Predefined rules for Core Networking include outbound rules that enable Group Policy to work. Ensure that these outbound rules are active, and thoroughly test firewall profiles before deploying.
    
    The recommended state for this setting is: Allow (default).
    
    Rationale: Some people believe that it is prudent to block all outbound connections except those specifically approved by the user or administrator. Microsoft disagrees with this opinion, blocking outbound connections by default will force users to deal with a large number of dialog boxes prompting them to authorize or block applications such as their web browser or instant messaging software. Additionally, blocking outbound traffic has little value because if an attacker has compromised the system they can reconfigure the firewall anyway.
  "
  impact 1.0
  tag cce: "CCE-33070-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "DefaultOutboundAction" }
    its("DefaultOutboundAction") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.4_L1_Ensure_Windows_Firewall_Public_Settings_Display_a_notification_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'"
  desc  "
    Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.
    
    **Note:** When the Apply local firewall rules setting is configured to Yes, it is also recommended to also configure the Display a notification setting to Yes. Otherwise, users will not receive messages that ask if they want to unblock a restricted inbound connection.
    
    The recommended state for this setting is: Yes.
    
    Rationale: Some organizations may prefer to avoid alarming users when firewall rules block certain types of network activity. However, notifications can be helpful when troubleshooting network issues involving the firewall.
  "
  impact 1.0
  tag cce: "CCE-33068-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "DisableNotifications" }
    its("DisableNotifications") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.5_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_firewall_rules_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
  desc  "
    This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.
    
    The recommended state for this setting is: No.
    
    Rationale: When in the Public profile, there should be no special local firewall exceptions per computer. These settings should be managed by a centralized policy.
  "
  impact 1.0
  tag cce: "CCE-35537-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "AllowLocalPolicyMerge" }
    its("AllowLocalPolicyMerge") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.6_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_connection_security_rules_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
  desc  "
    This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.
    
    The recommended state for this setting is: No.
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  tag cce: "CCE-33099-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "AllowLocalIPsecPolicyMerge" }
    its("AllowLocalIPsecPolicyMerge") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.7_L1_Ensure_Windows_Firewall_Public_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallpublicfw.log" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log'"
  desc  "
    Use this option to specify the path and name of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35117-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogFilePath" }
    its("LogFilePath") { should cmp "%SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.8_L1_Ensure_Windows_Firewall_Public_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  "
    Use this option to specify the size limit of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: 16,384 KB or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35421-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogFileSize" }
    its("LogFileSize") { should cmp >= 16384 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.9_L1_Ensure_Windows_Firewall_Public_Logging_Log_dropped_packets_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35116-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogDroppedPackets" }
    its("LogDroppedPackets") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.10_L1_Ensure_Windows_Firewall_Public_Logging_Log_successful_connections_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-33734-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogSuccessfulConnections" }
    its("LogSuccessfulConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.1.1_L1_Ensure_Audit_Credential_Validation_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
  desc  "
    This subcategory reports the results of validation tests on credentials submitted for a user account logon request. These events occur on the computer that is authoritative for the credentials. For domain accounts, the domain controller is authoritative, whereas for local accounts, the local computer is authoritative. In domain environments, most of the Account Logon events occur in the Security log of the domain controllers that are authoritative for the domain accounts. However, these events can occur on other computers in the organization when local accounts are used to log on. Events for this subcategory include:
    
    * 4774: An account was mapped for logon.
    * 4775: An account could not be mapped for logon.
    * 4776: The domain controller attempted to validate the credentials for an account.
    * 4777: The domain controller failed to validate the credentials for an account.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35494-4"
  describe audit_policy do
    its("Credential Validation") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.2.1_L1_Ensure_Audit_Application_Group_Management_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
  desc  "
    This policy setting allows you to audit events generated by changes to application groups such as the following:
    
    * Application group is created, changed, or deleted.
    * Member is added or removed from an application group.
    Application groups are utilized by Windows Authorization Manager, which is a flexible framework created by Microsoft for integrating role-based access control (RBAC) into applications. More information on Windows Authorization Manager is available at [MSDN - Windows Authorization Manager](https://msdn.microsoft.com/en-us/library/bb897401.aspx).
    
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing events in this category may be useful when investigating an incident.
  "
  impact 1.0
  tag cce: "CCE-32932-6"
  describe audit_policy do
    its("Application Group Management") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.2.2_L1_Ensure_Audit_Computer_Account_Management_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'"
  desc  "
    This subcategory reports each event of computer account management, such as when a computer account is created, changed, deleted, renamed, disabled, or enabled. Events for this subcategory include:
    
    * 4741: A computer account was created.
    * 4742: A computer account was changed.
    * 4743: A computer account was deleted.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing events in this category may be useful when investigating an incident.
  "
  impact 1.0
  tag cce: "CCE-33410-2"
  describe audit_policy do
    its("Computer Account Management") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.2.3_L1_Ensure_Audit_Other_Account_Management_Events_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'"
  desc  "
    This subcategory reports other account management events. Events for this subcategory include:
    
    * 4782: The password hash an account was accessed.
    * 4793: The Password Policy Checking API was called.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35497-7"
  describe audit_policy do
    its("Other Account Management Events") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.2.4_L1_Ensure_Audit_Security_Group_Management_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
  desc  "
    This subcategory reports each event of security group management, such as when a security group is created, changed, or deleted or when a member is added to or removed from a security group. If you enable this Audit policy setting, administrators can track events to detect malicious, accidental, and authorized creation of security group accounts. Events for this subcategory include:
    
    * 4727: A security-enabled global group was created.
    * 4728: A member was added to a security-enabled global group.
    * 4729: A member was removed from a security-enabled global group.
    * 4730: A security-enabled global group was deleted.
    * 4731: A security-enabled local group was created.
    * 4732: A member was added to a security-enabled local group.
    * 4733: A member was removed from a security-enabled local group.
    * 4734: A security-enabled local group was deleted.
    * 4735: A security-enabled local group was changed.
    * 4737: A security-enabled global group was changed.
    * 4754: A security-enabled universal group was created.
    * 4755: A security-enabled universal group was changed.
    * 4756: A member was added to a security-enabled universal group.
    * 4757: A member was removed from a security-enabled universal group.
    * 4758: A security-enabled universal group was deleted.
    * 4764: A group's type was changed.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35498-5"
  describe audit_policy do
    its("Security Group Management") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.2.5_L1_Ensure_Audit_User_Account_Management_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'"
  desc  "
    This subcategory reports each event of user account management, such as when a user account is created, changed, or deleted; a user account is renamed, disabled, or enabled; or a password is set or changed. If you enable this Audit policy setting, administrators can track events to detect malicious, accidental, and authorized creation of user accounts. Events for this subcategory include:
    
    * 4720: A user account was created.
    * 4722: A user account was enabled.
    * 4723: An attempt was made to change an account's password.
    * 4724: An attempt was made to reset an account's password.
    * 4725: A user account was disabled.
    * 4726: A user account was deleted.
    * 4738: A user account was changed.
    * 4740: A user account was locked out.
    * 4765: SID History was added to an account.
    * 4766: An attempt to add SID History to an account failed.
    * 4767: A user account was unlocked.
    * 4780: The ACL was set on accounts which are members of administrators groups.
    * 4781: The name of an account was changed:
    * 4794: An attempt was made to set the Directory Services Restore Mode.
    * 5376: Credential Manager credentials were backed up.
    * 5377: Credential Manager credentials were restored from a backup.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35499-3"
  describe audit_policy do
    its("User Account Management") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success" do
  title "(L1) Ensure 'Audit PNP Activity' is set to 'Success'"
  desc  "
    This policy setting allows you to audit when plug and play detects an external device.
    
    The recommended state for this setting is: Success.
    
    **Note:** A Windows 10, Server 2016 or higher OS is required to access and set this value in Group Policy.
    
    Rationale: Enabling this setting will allow a user to audit events when a device is plugged into a system. This can help alert IT staff if unapproved devices are plugged in.
  "
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_17.3.2_L1_Ensure_Audit_Process_Creation_is_set_to_Success" do
  title "(L1) Ensure 'Audit Process Creation' is set to 'Success'"
  desc  "
    This subcategory reports the creation of a process and the name of the program or user that created it. Events for this subcategory include:
    
    * 4688: A new process has been created.
    * 4696: A primary token was assigned to process.
    Refer to Microsoft Knowledge Base article 947226: [Description of security events in Windows Vista and in Windows Server 2008](https://support.microsoft.com/en-us/kb/947226) for the most recent information about this setting.
    
    The recommended state for this setting is: Success.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-33040-7"
  describe audit_policy do
    its("Process Creation") { should eq "Success" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.5.1_L1_Ensure_Audit_Account_Lockout_is_set_to_Success" do
  title "(L1) Ensure 'Audit Account Lockout' is set to 'Success'"
  desc  "
    This subcategory reports when a user's account is locked out as a result of too many failed logon attempts. Events for this subcategory include:
    
    * 4625: An account failed to log on.
    The recommended state for this setting is: Success.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35504-0"
  describe audit_policy do
    its("Account Lockout") { should eq "Success" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.5.2_L1_Ensure_Audit_Group_Membership_is_set_to_Success" do
  title "(L1) Ensure 'Audit Group Membership' is set to 'Success'"
  desc  "
    This policy allows you to audit the group membership information in the user#x2019;s logon token. Events in this subcategory are generated on the computer on which a logon session is created. For an interactive logon, the security audit event is generated on the computer that the user logged on to. For a network logon, such as accessing a shared folder on the network, the security audit event is generated on the computer hosting the resource.
    
    The recommended state for this setting is: Success.
    
    **Note:** A Windows 10, Server 2016 or higher OS is required to access and set this value in Group Policy.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
end

control "xccdf_org.cisecurity.benchmarks_rule_17.5.3_L1_Ensure_Audit_Logoff_is_set_to_Success" do
  title "(L1) Ensure 'Audit Logoff' is set to 'Success'"
  desc  "
    This subcategory reports when a user logs off from the system. These events occur on the accessed computer. For interactive logons, the generation of these events occurs on the computer that is logged on to. If a network logon takes place to access a share, these events generate on the computer that hosts the accessed resource. If you configure this setting to No auditing, it is difficult or impossible to determine which user has accessed or attempted to access organization computers. Events for this subcategory include:
    
    * 4634: An account was logged off.
    * 4647: User initiated logoff.
    The recommended state for this setting is: Success.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35507-3"
  describe audit_policy do
    its("Logoff") { should eq "Success" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.5.4_L1_Ensure_Audit_Logon_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Logon' is set to 'Success and Failure'"
  desc  "
    This subcategory reports when a user attempts to log on to the system. These events occur on the accessed computer. For interactive logons, the generation of these events occurs on the computer that is logged on to. If a network logon takes place to access a share, these events generate on the computer that hosts the accessed resource. If you configure this setting to No auditing, it is difficult or impossible to determine which user has accessed or attempted to access organization computers. Events for this subcategory include:
    
    * 4624: An account was successfully logged on.
    * 4625: An account failed to log on.
    * 4648: A logon was attempted using explicit credentials.
    * 4675: SIDs were filtered.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35508-1"
  describe audit_policy do
    its("Logon") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.5.5_L1_Ensure_Audit_Other_LogonLogoff_Events_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
  desc  "
    This subcategory reports other logon/logoff-related events, such as Terminal Services session disconnects and reconnects, using RunAs to run processes under a different account, and locking and unlocking a workstation. Events for this subcategory include:
    
    * 4649: A replay attack was detected.
    * 4778: A session was reconnected to a Window Station.
    * 4779: A session was disconnected from a Window Station.
    * 4800: The workstation was locked.
    * 4801: The workstation was unlocked.
    * 4802: The screen saver was invoked.
    * 4803: The screen saver was dismissed.
    * 5378: The requested credentials delegation was disallowed by policy.
    * 5632: A request was made to authenticate to a wireless network.
    * 5633: A request was made to authenticate to a wired network.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35510-7"
  describe audit_policy do
    its("Other Logon/Logoff Events") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.5.6_L1_Ensure_Audit_Special_Logon_is_set_to_Success" do
  title "(L1) Ensure 'Audit Special Logon' is set to 'Success'"
  desc  "
    This subcategory reports when a special logon is used. A special logon is a logon that has administrator-equivalent privileges and can be used to elevate a process to a higher level. Events for this subcategory include:
    
    * 4964 : Special groups have been assigned to a new logon.
    The recommended state for this setting is: Success.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35511-5"
  describe audit_policy do
    its("Special Logon") { should eq "Success" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.6.1_L1_Ensure_Audit_Removable_Storage_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
  desc  "
    This policy setting allows you to audit user attempts to access file system objects on a removable storage device. A security audit event is generated only for all objects for all types of access requested. If you configure this policy setting, an audit event is generated each time an account accesses a file system object on a removable storage. Success audits record successful attempts and Failure audits record unsuccessful attempts. If you do not configure this policy setting, no audit event is generated when an account accesses a file system object on a removable storage.
    
    The recommended state for this setting is: Success and Failure.
    **Note:** A Windows 8, Server 2012 (non-R2) or higher OS is required to access and set this value in Group Policy.
    
    Rationale: Auditing removable storage may be useful when investigating an incident. For example, if an individual is suspected of copying sensitive information onto a USB drive.
  "
  impact 1.0
  tag cce: "CCE-35520-6"
  describe audit_policy do
    its("Removable Storage") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.7.1_L1_Ensure_Audit_Audit_Policy_Change_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'"
  desc  "
    This subcategory reports changes in audit policy including SACL changes. Events for this subcategory include:
    
    * 4715: The audit policy (SACL) on an object was changed.
    * 4719: System audit policy was changed.
    * 4902: The Per-user audit policy table was created.
    * 4904: An attempt was made to register a security event source.
    * 4905: An attempt was made to unregister a security event source.
    * 4906: The CrashOnAuditFail value has changed.
    * 4907: Auditing settings on object were changed.
    * 4908: Special Groups Logon table modified.
    * 4912: Per User Audit Policy was changed.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35521-4"
  describe audit_policy do
    its("Audit Policy Change") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.7.2_L1_Ensure_Audit_Authentication_Policy_Change_is_set_to_Success" do
  title "(L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'"
  desc  "
    This subcategory reports changes in authentication policy. Events for this subcategory include:
    
    * 4706: A new trust was created to a domain.
    * 4707: A trust to a domain was removed.
    * 4713: Kerberos policy was changed.
    * 4716: Trusted domain information was modified.
    * 4717: System security access was granted to an account.
    * 4718: System security access was removed from an account.
    * 4739: Domain Policy was changed.
    * 4864: A namespace collision was detected.
    * 4865: A trusted forest information entry was added.
    * 4866: A trusted forest information entry was removed.
    * 4867: A trusted forest information entry was modified.
    The recommended state for this setting is: Success.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-33091-0"
  describe audit_policy do
    its("Authentication Policy Change") { should eq "Success" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.8.1_L1_Ensure_Audit_Sensitive_Privilege_Use_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
  desc  "
    This subcategory reports when a user account or service uses a sensitive privilege. A sensitive privilege includes the following user rights: Act as part of the operating system, Back up files and directories, Create a token object, Debug programs, Enable computer and user accounts to be trusted for delegation, Generate security audits, Impersonate a client after authentication, Load and unload device drivers, Manage auditing and security log, Modify firmware environment values, Replace a process-level token, Restore files and directories, and Take ownership of files or other objects. Auditing this subcategory will create a high volume of events. Events for this subcategory include:
    
    * 4672: Special privileges assigned to new logon.
    * 4673: A privileged service was called.
    * 4674: An operation was attempted on a privileged object.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35524-8"
  describe audit_policy do
    its("Sensitive Privilege Use") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.9.1_L1_Ensure_Audit_IPsec_Driver_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
  desc  "
    This subcategory reports on the activities of the Internet Protocol security (IPsec) driver. Events for this subcategory include:
    
    * 4960: IPsec dropped an inbound packet that failed an integrity check. If this problem persists, it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations.
    * 4961: IPsec dropped an inbound packet that failed a replay check. If this problem persists, it could indicate a replay attack against this computer.
    * 4962: IPsec dropped an inbound packet that failed a replay check. The inbound packet had too low a sequence number to ensure it was not a replay.
    * 4963: IPsec dropped an inbound clear text packet that should have been secured. This is usually due to the remote computer changing its IPsec policy without informing this computer. This could also be a spoofing attack attempt.
    * 4965: IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If these errors persist, verify that the packets sent from the remote computer are the same as those received by this computer. This error may also indicate interoperability problems with other IPsec implementations. In that case, if connectivity is not impeded, then these events can be ignored.
    * 5478: IPsec Services has started successfully.
    * 5479: IPsec Services has been shut down successfully. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
    * 5480: IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
    * 5483: IPsec Services failed to initialize RPC server. IPsec Services could not be started.
    * 5484: IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
    * 5485: IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35525-5"
  describe audit_policy do
    its("IPsec Driver") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.9.2_L1_Ensure_Audit_Other_System_Events_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'"
  desc  "
    This subcategory reports on other system events. Events for this subcategory include:
    
    * 5024 : The Windows Firewall Service has started successfully.
    * 5025 : The Windows Firewall Service has been stopped.
    * 5027 : The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.
    * 5028 : The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.
    * 5029: The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.
    * 5030: The Windows Firewall Service failed to start.
    * 5032: Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network.
    * 5033 : The Windows Firewall Driver has started successfully.
    * 5034 : The Windows Firewall Driver has been stopped.
    * 5035 : The Windows Firewall Driver failed to start.
    * 5037 : The Windows Firewall Driver detected critical runtime error. Terminating.
    * 5058: Key file operation.
    * 5059: Key migration operation.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Capturing these audit events may be useful for identifying when the Windows Firewall is not performing as expected.
  "
  impact 1.0
  tag cce: "CCE-32936-7"
  describe audit_policy do
    its("Other System Events") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.9.3_L1_Ensure_Audit_Security_State_Change_is_set_to_Success" do
  title "(L1) Ensure 'Audit Security State Change' is set to 'Success'"
  desc  "
    This subcategory reports changes in security state of the system, such as when the security subsystem starts and stops. Events for this subcategory include:
    
    * 4608: Windows is starting up.
    * 4609: Windows is shutting down.
    * 4616: The system time was changed.
    * 4621: Administrator recovered system from CrashOnAuditFail. Users who are not administrators will now be allowed to log on. Some audit-able activity might not have been recorded.
    The recommended state for this setting is: Success.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-33043-1"
  describe audit_policy do
    its("Security State Change") { should eq "Success" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.9.4_L1_Ensure_Audit_Security_System_Extension_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'"
  desc  "
    This subcategory reports the loading of extension code such as authentication packages by the security subsystem. Events for this subcategory include:
    
    * 4610: An authentication package has been loaded by the Local Security Authority.
    * 4611: A trusted logon process has been registered with the Local Security Authority.
    * 4614: A notification package has been loaded by the Security Account Manager.
    * 4622: A security package has been loaded by the Local Security Authority.
    * 4697: A service was installed in the system.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35526-3"
  describe audit_policy do
    its("Security System Extension") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_17.9.5_L1_Ensure_Audit_System_Integrity_is_set_to_Success_and_Failure" do
  title "(L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'"
  desc  "
    This subcategory reports on violations of integrity of the security subsystem. Events for this subcategory include:
    
    * 4612 : Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.
    * 4615 : Invalid use of LPC port.
    * 4618 : A monitored security event pattern has occurred.
    * 4816 : RPC detected an integrity violation while decrypting an incoming message.
    * 5038 : Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.
    * 5056: A cryptographic self test was performed.
    * 5057: A cryptographic primitive operation failed.
    * 5060: Verification operation failed.
    * 5061: Cryptographic operation.
    * 5062: A kernel-mode cryptographic self test was performed.
    The recommended state for this setting is: Success and Failure.
    
    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  impact 1.0
  tag cce: "CCE-35527-1"
  describe audit_policy do
    its("System Integrity") { should eq "Success and Failure" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc  "
    Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Disabling the lock screen camera extends the protection afforded by the lock screen to camera features.
  "
  impact 1.0
  tag cce: "CCE-35799-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenCamera" }
    its("NoLockScreenCamera") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc  "
    Disables the lock screen slide show settings in PC Settings and prevents a slide show from playing on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Disabling the lock screen slide show extends the protection afforded by the lock screen to slide show contents.
  "
  impact 1.0
  tag cce: "CCE-35800-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenSlideshow" }
    its("NoLockScreenSlideshow") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.1.2.1_L1_Ensure_Allow_Input_Personalization_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Input Personalization' is set to 'Disabled'"
  desc  "
    This policy enables the automatic learning component of input personalization that includes speech, inking, and typing. Automatic learning enables the collection of speech and handwriting patterns, typing history, contacts, and recent calendar information. It is required for the use of Cortana. Some of this collected information may be stored on the user's OneDrive, in the case of inking and typing; some of the information will be uploaded to Microsoft to personalize speech.
    
    The recommended state for this setting is: Disabled
    
    Rationale: If this setting is Enabled sensitive information could be stored in the cloud or sent to Microsoft.
  "
  impact 1.0
  tag cce: "CCE-41387-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization") do
    it { should have_property "AllowInputPersonalization" }
    its("AllowInputPersonalization") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed" do
  title "(L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}") do
    it { should have_property "DllName" }
    its("DllName") { should eq "C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled" do
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
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PwdExpirationProtectionEnabled" }
    its("PwdExpirationProtectionEnabled") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled" do
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
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "AdmPwdEnabled" }
    its("AdmPwdEnabled") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters" do
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
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordComplexity" }
    its("PasswordComplexity") { should cmp == 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more" do
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
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordLength" }
    its("PasswordLength") { should cmp >= 15 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer" do
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
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordAgeDays" }
    its("PasswordAgeDays") { should cmp <= 30 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled" do
  title "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc  "
    This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group.
    
    For additional information, see Microsoft Knowledge Base article 324737: [How to turn on automatic logon in Windows](https://support.microsoft.com/en-us/kb/324737).
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks that the computer is connected to. Also, if you enable automatic logon, the password is stored in the registry in plaintext. The specific registry key that stores this setting is remotely readable by the Authenticated Users group. As a result, this entry is appropriate only if the computer is physically secured and if you ensure that untrusted users cannot remotely see the registry.
  "
  impact 1.0
  tag cce: "CCE-35438-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "AutoAdminLogon" }
    its("AutoAdminLogon") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled" do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should follow through the network.
    
    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.
    
    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  tag cce: "CCE-33790-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled" do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should take through the network. It is recommended to configure this setting to Not Defined for enterprise environments and to Highest Protection for high security environments to completely disable source routing.
    
    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.
    
    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  tag cce: "CCE-33816-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.5_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled" do
  title "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc  "
    Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host routes. These routes override the Open Shortest Path First (OSPF) generated routes.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: This behavior is expected. The problem is that the 10 minute time-out period for the ICMP redirect-plumbed routes temporarily creates a network situation in which traffic will no longer be routed properly for the affected host. Ignoring such ICMP redirects will limit the system's exposure to attacks that will impact its ability to participate on the network.
  "
  impact 1.0
  tag cce: "CCE-34597-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "EnableICMPRedirect" }
    its("EnableICMPRedirect") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.7_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled" do
  title "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc  "
    NetBIOS over TCP/IP is a network protocol that among other things provides a way to easily resolve NetBIOS names that are registered on Windows-based systems to the IP addresses that are configured on those systems. This setting determines whether the computer releases its NetBIOS name when it receives a name-release request.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The NetBT protocol is designed not to use authentication, and is therefore vulnerable to spoofing. Spoofing makes a transmission appear to come from a user other than the user who performed the action. A malicious user could exploit the unauthenticated nature of the protocol to send a name-conflict datagram to a target computer, which would cause the computer to relinquish its name and not respond to queries.
    
    The result of such an attack could be to cause intermittent connectivity issues on the target computer, or even to prevent the use of Network Neighborhood, domain logons, the NET SEND command, or additional NetBIOS name resolution.
  "
  impact 1.0
  tag cce: "CCE-35405-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters") do
    it { should have_property "nonamereleaseondemand" }
    its("nonamereleaseondemand") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.9_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled" do
  title "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc  "
    The DLL search order can be configured to search for DLLs that are requested by running processes in one of two ways:
    
    * Search folders specified in the system path first, and then search the current working folder.
    * Search current working folder first, and then search the folders specified in the system path.
    When enabled, the registry value is set to 1. With a setting of 1, the system first searches the folders that are specified in the system path and then searches the current working folder. When disabled the registry value is set to 0 and the system first searches the current working folder and then searches the folders that are specified in the system path.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user unknowingly executes hostile code that was packaged with additional files that include modified versions of system DLLs, the hostile code could load its own versions of those DLLs and potentially increase the type and degree of damage the code can render.
  "
  impact 1.0
  tag cce: "CCE-34022-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager") do
    it { should have_property "SafeDllSearchMode" }
    its("SafeDllSearchMode") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.10_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds" do
  title "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc  "
    Windows includes a grace period between when the screen saver is launched and when the console is actually locked automatically when screen saver locking is enabled.
    
    The recommended state for this setting is: Enabled: 5 or fewer seconds.
    
    Rationale: The default grace period that is allowed for user movement before the screen saver lock takes effect is five seconds. If you leave the default grace period configuration, your computer is vulnerable to a potential attack from someone who could approach the console and attempt to log on to the computer before the lock takes effect. An entry to the registry can be made to adjust the length of the grace period.
  "
  impact 1.0
  tag cce: "CCE-34619-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "ScreenSaverGracePeriod" }
    its("ScreenSaverGracePeriod") { should cmp <= 5 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.13_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less" do
  title "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc  "
    This setting can generate a security audit in the Security event log when the log reaches a user-defined threshold.
    
    **Note:** If log settings are configured to Overwrite events as needed or Overwrite events older than x days, this event will not be generated.
    
    The recommended state for this setting is: Enabled: 90% or less.
    
    Rationale: If the Security log reaches 90 percent of its capacity and the computer has not been configured to overwrite events as needed, more recent events will not be written to the log. If the log reaches its capacity and the computer has been configured to shut down when it can no longer record events to the Security log, the computer will shut down and will no longer be available to provide network services.
  "
  impact 1.0
  tag cce: "CCE-35406-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security") do
    it { should have_property "WarningLevel" }
    its("WarningLevel") { should cmp <= 90 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.7.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled" do
  title "(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
  desc  "
    This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Insecure guest logons are used by file servers to allow unauthenticated access to shared folders.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation") do
    it { should have_property "AllowInsecureGuestAuth" }
    its("AllowInsecureGuestAuth") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.10.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled" do
  title "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc  "
    You can use this procedure to enable or disable the user's ability to install and configure a network bridge.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing users to create a network bridge increases the risk and attack surface from the bridged network.
  "
  impact 1.0
  tag cce: "CCE-33107-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_AllowNetBridge_NLA" }
    its("NC_AllowNetBridge_NLA") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.10.3_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled" do
  title "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc  "
    This policy setting determines whether to require domain users to elevate when setting a network's location.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing regular users to set a network location increases the risk and attack surface.
  "
  impact 1.0
  tag cce: "CCE-35554-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_StdDomainUserSetLocation" }
    its("NC_StdDomainUserSetLocation") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.13.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares" do
  title "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc  "
    This policy setting configures secure access to UNC paths.
    
    The recommended state for this setting is: Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares.
    
    **Note:** If the environment exclusively contains Windows 8.0 / Server 2012 or higher systems, then the \"Privacy\" setting may (optionally) also be set to enable SMB encryption. However, using SMB encryption will render the targeted share paths completely inaccessible by older OSes, so only use this additional option with caution and thorough testing.
    
    Rationale: In February 2015, Microsoft released a new control mechanism to mitigate a security risk in Group Policy as part of [MS15-011](https://technet.microsoft.com/library/security/MS15-011) / [MSKB 3000483](https://support.microsoft.com/en-us/kb/3000483). This mechanism requires both the installation of the new security update and also the deployment of specific group policy settings to all computers on the domain from Vista/Server 2008 or higher (the associated security patch to enable this feature was not released for Server 2003). A new group policy template (NetworkProvider.admx/adml) was also provided with the security update.
    
    Once the new GPO template is in place, the following are the minimum requirements to remediate the Group Policy security risk:
    \\\\*\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1
    \\\\*\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1
    
    **Note:** A reboot may be required after the setting is applied to a client machine to access the above paths.
    
    Additional guidance on the deployment of this security setting is available from the Microsoft Premier Field Engineering (PFE) Platforms TechNet Blog here: [Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx).
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\NETLOGON" }
    its("\\\\*\\NETLOGON") { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\SYSVOL" }
    its("\\\\*\\SYSVOL") { should match(/[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1/) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.20.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled" do
  title "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
  desc  "
    This policy setting prevents computers from establishing multiple simultaneous connections to either the Internet or to a Windows domain.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Blocking simultaneous connections can help prevent a user unknowingly allowing network traffic to flow between the Internet and the corporate network.
  "
  impact 1.0
  tag cce: "CCE-35242-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    it { should have_property "fMinimizeConnections" }
    its("fMinimizeConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.20.2_L1_Ensure_Prohibit_connection_to_non-domain_networks_when_connected_to_domain_authenticated_network_is_set_to_Enabled" do
  title "(L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
  desc  "
    This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The potential concern is that a user would unknowingly allow network traffic to flow between the insecure public network and the managed corporate network.
  "
  impact 1.0
  tag cce: "CCE-35375-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    it { should have_property "fBlockNonDomain" }
    its("fBlockNonDomain") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.22.2.1_L1_Ensure_Allow_Windows_to_automatically_connect_to_suggested_open_hotspots_to_networks_shared_by_contacts_and_to_hotspots_offering_paid_services_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users can enable the following WLAN settings: \"Connect to suggested open hotspots,\" \"Connect to networks shared by my contacts,\" and \"Enable paid services\".
    
    \"Connect to suggested open hotspots\" enables Windows to automatically connect users to open hotspots it knows about by crowdsourcing networks that other people using Windows have connected to.
    
    \"Connect to networks shared by my contacts\" enables Windows to automatically connect to networks that the user's contacts have shared with them, and enables users on this device to share networks with their contacts.
    
    \"Enable paid services\" enables Windows to temporarily connect to open hotspots to determine if paid services are available.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** These features are also known by the name \"**Wi-Fi Sense**\".
    
    Rationale: Automatically connecting to an open hotspot or network can introduce the system to a rogue network with malicious intent.
  "
  impact 1.0
  tag cce: "CCE-41378-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config") do
    it { should have_property "AutoConnectAllowedOEM" }
    its("AutoConnectAllowedOEM") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled" do
  title "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
  desc  "
    This setting controls whether local accounts can be used for remote administration via network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.
    
    **Enabled:** Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.
    
    **Disabled:** Allows local accounts to have full administrative rights when authenticating via network logon, by configuring the LocalAccountTokenFilterPolicy registry value to 1.
    
    For more information about local accounts and credential theft, review the \"[Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036)\" documents.
    
    For more information about LocalAccountTokenFilterPolicy, see Microsoft Knowledge Base article 951016: [Description of User Account Control and remote restrictions in Windows Vista](https://support.microsoft.com/en-us/kb/951016).
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Ensuring this policy is Enabled significantly reduces that risk.
  "
  impact 1.0
  tag cce: "CCE-35486-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "LocalAccountTokenFilterPolicy" }
    its("LocalAccountTokenFilterPolicy") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.6.2_L1_Ensure_WDigest_Authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc  "
    When WDigest authentication is enabled, Lsass.exe retains a copy of the user's plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.
    
    For more information about local accounts and credential theft, review the \"[Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036)\" documents.
    
    For more information about UseLogonCredential, see Microsoft Knowledge Base article 2871997: [Microsoft Security Advisory Update to improve credentials protection and management May 13, 2014](https://support.microsoft.com/en-us/kb/2871997).
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Preventing the plaintext storage of credentials in memory may reduce opportunity for credential theft.
  "
  impact 1.0
  tag cce: "CCE-35815-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest") do
    it { should have_property "UseLogonCredential" }
    its("UseLogonCredential") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.2.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled" do
  title "(L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
  desc  "
    This policy setting determines what information is logged in security audit events when a new process has been created.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: When this policy setting is enabled, any user who has read access to the security events can read the command-line arguments for any successfully created process. Command-line arguments may contain sensitive or private information such as passwords or user data.
  "
  impact 1.0
  tag cce: "CCE-35802-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit") do
    it { should have_property "ProcessCreationIncludeCmdLine_Enabled" }
    its("ProcessCreationIncludeCmdLine_Enabled") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.11.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical" do
  title "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc  "
    This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:
    
    * Good: The driver has been signed and has not been tampered with.
    * Bad: The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
    * Bad, but required for boot: The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
    * Unknown: This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.
    If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.
    
    If you disable or do not configure this policy setting, the boot start drivers determined to be Good, Unknown or Bad but Boot Critical are initialized and the initialization of drivers determined to be Bad is skipped.
    
    If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.
    
    The recommended state for this setting is: Enabled: Good, unknown and bad but critical.
    
    Rationale: This policy setting helps reduce the impact of malware that has already infected your system.
  "
  impact 1.0
  tag cce: "CCE-33231-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
    it { should have_property "DriverLoadPolicy" }
    its("DriverLoadPolicy") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE" do
  title "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc  "
    The \"Do not apply during periodic background processing\" option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart.
    
    The recommended state for this setting is: Enabled: FALSE (unchecked).
    
    Rationale: Setting this option to false (unchecked) will ensure that domain policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  tag cce: "CCE-35384-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoBackgroundPolicy" }
    its("NoBackgroundPolicy") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE" do
  title "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc  "
    The \"Process even if the Group Policy objects have not changed\" option updates and reapplies policies even if the policies have not changed.
    
    The recommended state for this setting is: Enabled: TRUE (checked).
    
    Rationale: Setting this option to true (checked) will ensure unauthorized changes that might have been configured locally are forced to match the domain-based Group Policy settings again.
  "
  impact 1.0
  tag cce: "CCE-35384-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoGPOListChanges" }
    its("NoGPOListChanges") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.4_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc  "
    This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users and domain controllers.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Setting this option to false (unchecked) will ensure that group policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  tag cce: "CCE-35776-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should_not have_property "DisableBkGndGroupPolicy" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.1_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control whether anyone can interact with available networks UI on the logon screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An unauthorized user could disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.
  "
  impact 1.0
  tag cce: "CCE-33822-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontDisplayNetworkSelectionUI" }
    its("DontDisplayNetworkSelectionUI") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.2_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc  "
    This policy setting prevents connected users from being enumerated on domain-joined computers.
    
    If you enable this policy setting, the Logon UI will not enumerate any connected users on domain-joined computers.
    
    If you disable or do not configure this policy setting, connected users will be enumerated on domain-joined computers.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  tag cce: "CCE-35207-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontEnumerateConnectedUsers" }
    its("DontEnumerateConnectedUsers") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.3_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled" do
  title "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc  "
    This policy setting allows local users to be enumerated on domain-joined computers.
    
    If you enable this policy setting, Logon UI will enumerate all local users on domain-joined computers.
    
    If you disable or do not configure this policy setting, the Logon UI will not enumerate local users on domain-joined computers.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  tag cce: "CCE-34838-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnumerateLocalUsers" }
    its("EnumerateLocalUsers") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.4_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting allows you to prevent app notifications from appearing on the lock screen.
    
    If you enable this policy setting, no app notifications are displayed on the lock screen.
    
    If you disable or do not configure this policy setting, users can choose which apps display notifications on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: App notifications might display sensitive business or personal data.
  "
  impact 1.0
  tag cce: "CCE-34837-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DisableLockScreenAppNotifications" }
    its("DisableLockScreenAppNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.5_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc  "
    This policy setting allows you to control whether a domain user can sign in using a convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security properties. To configure Passport for domain users, use the policies under Computer configuration\\Administrative Templates\\Windows Components\\Microsoft Passport for Work.
    
    If you enable this policy setting, a domain user can set up and sign in with a convenience PIN.
    
    If you disable or don't configure this policy setting, a domain user can't set up and use a convenience PIN.
    
    Note that the user's domain password will be cached in the system vault when using this feature.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A PIN is created from a much smaller selection of characters than a password, so in most cases a PIN will be much less robust than a password.
  "
  impact 1.0
  tag cce: "CCE-35095-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "AllowDomainPINLogon" }
    its("AllowDomainPINLogon") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.1_L1_Ensure_Untrusted_Font_Blocking_is_set_to_Enabled_Block_untrusted_fonts_and_log_events" do
  title "(L1) Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'"
  desc  "
    This security feature provides a global setting to prevent programs from loading untrusted fonts. Untrusted fonts are any font installed outside of the %windir%\\Fonts directory. This feature can be configured to be in 3 modes: On, Off, and Audit.
    
    The recommended state for this setting is: Enabled: Block untrusted fonts and log events
    
    Rationale: Blocking untrusted fonts helps prevent both remote (web-based or email-based) and local EOP attacks that can happen during the font file-parsing process.
  "
  impact 1.0
  tag cce: "CCE-41386-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions") do
    it { should have_property "MitigationOptions_FontBocking" }
    its("MitigationOptions_FontBocking") { should eq "1000000000000" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.28.4.3_L1_Ensure_Require_a_password_when_a_computer_wakes_on_battery_is_set_to_Enabled" do
  title "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
  desc  "
    Specifies whether or not the user is prompted for a password when the system resumes from sleep.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting ensures that anyone who wakes an unattended computer from sleep state will have to provide logon credentials before they can access the system.
  "
  impact 1.0
  tag cce: "CCE-33782-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "DCSettingIndex" }
    its("DCSettingIndex") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.28.4.4_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled" do
  title "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
  desc  "
    Specifies whether or not the user is prompted for a password when the system resumes from sleep.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting ensures that anyone who wakes an unattended computer from sleep state will have to provide logon credentials before they can access the system.
  "
  impact 1.0
  tag cce: "CCE-35462-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "ACSettingIndex" }
    its("ACSettingIndex") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.30.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled" do
  title "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.
    
    If you enable this policy setting, users on this computer can get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.
    
    If you disable this policy setting, users on this computer cannot get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.
    
    If you do not configure this policy setting, users on this computer cannot get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.
    
    If you enable this policy setting, you have two ways to allow helpers to provide Remote Assistance: \"Allow helpers to only view the computer\" or \"Allow helpers to remotely control the computer.\" When you configure this policy setting, you also specify the list of users or user groups that are allowed to offer remote assistance.
    
    To configure the list of helpers, click \"Show.\" In the window that opens, you can enter the names of the helpers. Add each user or group one by one. When you enter the name of the helper user or user groups, use the following format:
    
    <Domain>\\<User> or
    <Domain>\\<Group>
    
    If you enable this policy setting, you should also enable firewall exceptions to allow Remote Assistance communications. The firewall exceptions required for Offer (Unsolicited) Remote Assistance depend on the version of Windows you are running:
    
    Windows Vista and later:
    Enable the Remote Assistance exception for the domain profile. The exception must contain:
    Port 135:TCP
    %WINDIR%\\System32\\msra.exe
    %WINDIR%\\System32\\raserver.exe
    
    Windows XP with Service Pack 2 (SP2) and Windows XP Professional x64 Edition with Service Pack 1 (SP1):
    Port 135:TCP
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpsvc.exe
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpctr.exe
    %WINDIR%\\System32\\Sessmgr.exe
    
    For computers running Windows Server 2003 with Service Pack 1 (SP1)
    Port 135:TCP
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpsvc.exe
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpctr.exe
    Allow Remote Desktop Exception
    
    The recommended state for this setting is: Disabled.</Group></Domain></User></Domain>
    
    Rationale: A user might be tricked and accept an unsolicited Remote Assistance offer from a malicious user.
  "
  impact 1.0
  tag cce: "CCE-33801-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowUnsolicited" }
    its("fAllowUnsolicited") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.30.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled" do
  title "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.
    
    If you enable this policy setting, users on this computer can use email or file transfer to ask someone for help. Also, users can use instant messaging programs to allow connections to this computer, and you can configure additional Remote Assistance settings.
    
    If you disable this policy setting, users on this computer cannot use email or file transfer to ask someone for help. Also, users cannot use instant messaging programs to allow connections to this computer.
    
    If you do not configure this policy setting, users can turn on or turn off Solicited (Ask for) Remote Assistance themselves in System Properties in Control Panel. Users can also configure Remote Assistance settings.
    
    If you enable this policy setting, you have two ways to allow helpers to provide Remote Assistance: \"Allow helpers to only view the computer\" or \"Allow helpers to remotely control the computer.\"
    
    The \"Maximum ticket time\" policy setting sets a limit on the amount of time that a Remote Assistance invitation created by using email or file transfer can remain open.
    
    The \"Select the method for sending email invitations\" setting specifies which email standard to use to send Remote Assistance invitations. Depending on your email program, you can use either the Mailto standard (the invitation recipient connects through an Internet link) or the SMAPI (Simple MAPI) standard (the invitation is attached to your email message). This policy setting is not available in Windows Vista since SMAPI is the only method supported.
    
    If you enable this policy setting you should also enable appropriate firewall exceptions to allow Remote Assistance communications.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: There is slight risk that a rogue administrator will gain access to another user's desktop session, however, they cannot connect to a user's computer unannounced or control it without permission from the user. When an expert tries to connect, the user can still choose to deny the connection or give the expert view-only privileges. The user must explicitly click the Yes button to allow the expert to remotely control the workstation.
  "
  impact 1.0
  tag cce: "CCE-35331-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowToGetHelp" }
    its("fAllowToGetHelp") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.31.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled" do
  title "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
  desc  "
    This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call they are making contains authentication information. The Endpoint Mapper Service on computers running Windows NT4 (all service packs) cannot process authentication information supplied in this manner.
    
    If you disable this policy setting, RPC clients will not authenticate to the Endpoint Mapper Service, but they will be able to communicate with the Endpoint Mapper Service on Windows NT4 Server.
    
    If you enable this policy setting, RPC clients will authenticate to the Endpoint Mapper Service for calls that contain authentication information. Clients making such calls will not be able to communicate with the Windows NT4 Server Endpoint Mapper Service.
    
    If you do not configure this policy setting, it remains disabled. RPC clients will not authenticate to the Endpoint Mapper Service, but they will be able to communicate with the Windows NT4 Server Endpoint Mapper Service.
    
    **Note:** This policy will not be applied until the system is rebooted.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Anonymous access to RPC services could result in accidental disclosure of information to unauthenticated users.
  "
  impact 1.0
  tag cce: "CCE-35392-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "EnableAuthEpResolution" }
    its("EnableAuthEpResolution") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.31.2_L1_Ensure_Restrict_Unauthenticated_RPC_clients_is_set_to_Enabled_Authenticated" do
  title "(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
  desc  "
    This policy setting controls how the RPC server runtime handles unauthenticated RPC clients connecting to RPC servers.
    
    This policy setting impacts all RPC applications. In a domain environment this policy setting should be used with caution as it can impact a wide range of functionality including group policy processing itself. Reverting a change to this policy setting can require manual intervention on each affected machine. **This policy setting should never be applied to a domain controller.**
    
    If you disable this policy setting, the RPC server runtime uses the value of \"Authenticated\" on Windows Client, and the value of \"None\" on Windows Server versions that support this policy setting.
    
    If you do not configure this policy setting, it remains disabled. The RPC server runtime will behave as though it was enabled with the value of \"Authenticated\" used for Windows Client and the value of \"None\" used for Server SKUs that support this policy setting.
    
    If you enable this policy setting, it directs the RPC server runtime to restrict unauthenticated RPC clients connecting to RPC servers running on a machine. A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically requested to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy setting.
    
    -- \"**None**\" allows all RPC clients to connect to RPC Servers running on the machine on which the policy setting is applied.
    -- \"**Authenticated**\" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. Exemptions are granted to interfaces that have requested them.
    -- \"**Authenticated without exceptions**\" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. No exceptions are allowed. **This value has the potential to cause serious problems and is not recommended.**
    
    **Note:** This policy setting will not be applied until the system is rebooted.
    
    The recommended state for this setting is: Enabled: Authenticated.
    
    Rationale: Unauthenticated RPC communication can create a security vulnerability.
  "
  impact 1.0
  tag cce: "CCE-35391-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "RestrictRemoteClients" }
    its("RestrictRemoteClients") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled" do
  title "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc  "
    This policy setting lets you control whether Microsoft accounts are optional for Windows Store apps that require an account to sign in. This policy only affects Windows Store apps that support it. If you enable this policy setting, Windows Store apps that typically require a Microsoft account to sign in will allow users to sign in with an enterprise account instead. If you disable or do not configure this policy setting, users will need to sign in with a Microsoft account.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting allows an organization to use their enterprise user accounts instead of using their Microsoft accounts when accessing Windows store apps. This provides the organization with greater control over relevant credentials. Microsoft accounts cannot be centrally managed and as such enterprise credential security policies cannot be applied to them, which could put any information accessed by using Microsoft accounts at risk.
  "
  impact 1.0
  tag cce: "CCE-35803-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "MSAOptional" }
    its("MSAOptional") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc  "
    This policy setting disallows AutoPlay for MTP devices like cameras or phones.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  tag cce: "CCE-35289-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoAutoplayfornonVolume" }
    its("NoAutoplayfornonVolume") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands" do
  title "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc  "
    This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.
    
    The recommended state for this setting is: Enabled: Do not execute any autorun commands.
    
    Rationale: Prior to Windows Vista, when media containing an autorun command is inserted, the system will automatically execute the program without user intervention. This creates a major security concern as code may be executed without user's knowledge. The default behavior starting with Windows Vista is to prompt the user whether autorun command is to be run. The autorun command is represented as a handler in the Autoplay dialog.
  "
  impact 1.0
  tag cce: "CCE-34771-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "NoAutorun" }
    its("NoAutorun") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives" do
  title "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc  "
    Autoplay starts to read from a drive as soon as you insert media in the drive, which causes the setup file for programs or audio media to start immediately. An attacker could use this feature to launch a program to damage the computer or data on the computer. You can enable the Turn off Autoplay setting to disable the Autoplay feature. Autoplay is disabled by default on some removable drive types, such as floppy disk and network drives, but not on CD-ROM drives.
    
    **Note:** You cannot use this policy setting to enable Autoplay on computer drives in which it is disabled by default, such as floppy disk and network drives.
    
    The recommended state for this setting is: Enabled: All drives.
    
    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  tag cce: "CCE-33791-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "NoDriveTypeAutoRun" }
    its("NoDriveTypeAutoRun") { should cmp == 255 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.10.1.1_L1_Ensure_Use_enhanced_anti-spoofing_when_available_is_set_to_Enabled" do
  title "(L1) Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled'"
  desc  "
    This policy setting determines whether enhanced anti-spoofing is configured for devices which support it.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enterprise environments are now supporting a wider range of mobile devices, increasing the security on these devices will help protect against unauthorized access on your network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures") do
    it { should have_property "EnhancedAntiSpoofing" }
    its("EnhancedAntiSpoofing") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.12.1_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc  "
    This policy setting turns off experiences that help consumers make the most of their devices and Microsoft account.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Having apps silently installed in an environment is not good security practice - especially if the apps send data back to a 3rd party.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent") do
    it { should have_property "DisableWindowsConsumerFeatures" }
    its("DisableWindowsConsumerFeatures") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.13.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure the display of the password reveal button in password entry user experiences.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: This is a useful feature when entering a long and complex password, especially when using a touchscreen. The potential risk is that someone else may see your password while surreptitiously observing your screen.
  "
  impact 1.0
  tag cce: "CCE-32965-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI") do
    it { should have_property "DisablePasswordReveal" }
    its("DisablePasswordReveal") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.13.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled" do
  title "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc  "
    By default, all administrator accounts are displayed when you attempt to elevate a running application.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users could see the list of administrator accounts, making it slightly easier for a malicious user who has logged onto a console session to try to crack the passwords of those accounts.
  "
  impact 1.0
  tag cce: "CCE-35194-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI") do
    it { should have_property "EnumerateAdministrators" }
    its("EnumerateAdministrators") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only" do
  title "(L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]'"
  desc  "
    This policy setting determines the amount of diagnostic and usage data reported to Microsoft.
    
    A value of 0 will send minimal data to Microsoft. This data includes Malicious Software Removal Tool (MSRT)  Windows Defender data, if enabled, and telemetry client settings. Setting a value of 0 applies to enterprise, EDU, IoT and server devices only. Setting a value of 0 for other devices is equivalent to choosing a value of 1. A value of 1 sends only a basic amount of diagnostic and usage data. Note that setting values of 0 or 1 will degrade certain experiences on the device. A value of 2 sends enhanced diagnostic and usage data. A value of 3 sends the same data as a value of 2, plus additional diagnostics data, including the files and content that may have caused the problem. Windows 10 telemetry settings applies to the Windows operating system and some first party apps. This setting does not apply to third party apps running on Windows 10.
    
    If you disable or do not configure this policy setting, users can configure the Telemetry level in Settings.
    
    The recommended state for this setting is: Enabled: 0 - Security [Enterprise Only].
    
    Rationale: Sending any data to a 3rd party vendor is a security concern and should only be done on an as needed basis.
  "
  impact 1.0
  tag cce: "CCE-41400-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection") do
    it { should have_property "AllowTelemetry" }
    its("AllowTelemetry") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.2_L1_Ensure_Disable_pre-release_features_or_settings_is_set_to_Disabled" do
  title "(L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'"
  desc  "
    This policy setting determines the level that Microsoft can experiment with the product to study user preferences or device behavior. A value of 1 permits Microsoft to configure device settings only. A value of 2 allows Microsoft to conduct full experimentations.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: It can be dangerous in an Enterprise environment if experimental features are allowed because this can introduce bugs and security holes into systems, making it easier for an attacker to gain access.
  "
  impact 1.0
  tag cce: "CCE-41379-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds") do
    it { should have_property "EnableConfigFlighting" }
    its("EnableConfigFlighting") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.3_L1_Ensure_Do_not_show_feedback_notifications_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
  desc  "
    This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: In an enterprise environment users should not be sending any feedback to 3rd party vendors.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection") do
    it { should have_property "DoNotShowFeedbackNotifications" }
    its("DoNotShowFeedbackNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.4_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled" do
  title "(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users can access the Insider build controls in the Advanced Options for Windows Update. These controls are located under \"Get Insider builds,\" and enable users to make their devices available for downloading and installing Windows preview software.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** This policy setting applies only to devices running Windows 10 Pro, Windows 10 Enterprise, or Server 2016.
    
    Rationale: It can be dangerous in an Enterprise environment if experimental features are allowed because this can introduce bugs and security holes into systems allowing an attacker to gain access.
  "
  impact 1.0
  tag cce: "CCE-41380-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds") do
    it { should have_property "AllowBuildPreview" }
    its("AllowBuildPreview") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.15.1_L1_Ensure_Download_Mode_is_set_to_Enabled_None_or_LAN_or_Group_or_Disabled" do
  title "(L1) Ensure 'Download Mode' is set to 'Enabled: None or LAN or Group' or 'Disabled'"
  desc  "
    Set this policy to configure the use of Windows Update Delivery Optimization in downloads of Windows Apps and Updates. Available mode are: 0=disable 1=peers on same NAT only 2=Local Network / Private Peering (PCs in the same domain by default) 3= Internet Peering
    
    The recommended state for this setting is: Enabled: None or LAN or Group or Disabled.
    
    Rationale: Do to privacy concerns and security risks, updates should only be downloaded from a trusted machine on the internal network that received its updates from a trusted source and approved by the network administrator.
  "
  impact 1.0
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      it { should have_property "DODownloadMode" }
      its("DODownloadMode") { should cmp <= 2 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
      it { should_not have_property "DODownloadMode" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.1_L1_Ensure_EMET_5.5_or_higher_is_installed" do
  title "(L1) Ensure 'EMET 5.5' or higher is installed"
  desc  "
    The Enhanced Mitigation Experience Toolkit (EMET) is free, supported, software developed by Microsoft that allows an enterprise to apply exploit mitigations to applications that run on Windows.
    
    Rationale: EMET mitigations help reduce the reliability of exploits that target vulnerable software running on Windows
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\EMET_Service") do
    it { should have_property "Start" }
    its("Start") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.2_L1_Ensure_Default_Action_and_Mitigation_Settings_is_set_to_Enabled_plus_subsettings" do
  title "(L1) Ensure 'Default Action and Mitigation Settings' is set to 'Enabled' (plus subsettings)"
  desc  "
    This setting configures the default action after detection and advanced ROP mitigation.
    
    The recommended state for this setting is:
    
    Default Action and Mitigation Settings - Enabled
    Deep Hooks - Enabled
    Anti Detours - Enabled
    Banned Functions - Enabled
    Exploit Action - User Configured
    
    Rationale: These advanced mitigations for ROP mitigations apply to all configured software in EMET.
    **Deep Hooks** protects critical APIs and the subsequent lower level APIs used by the top level critical API.
    **Anti Detours** renders ineffective exploits that evade hooks by executing a copy of the hooked function prologue and then jump to the function past the prologue.
    **Banned Functions** will block calls to **ntdll!LdrHotPatchRoutine** to mitigate potential exploits abusing the API.
  "
  impact 1.0
  tag cce: "CCE-35473-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "AntiDetours" }
    its("AntiDetours") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "BannedFunctions" }
    its("BannedFunctions") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "DeepHooks" }
    its("DeepHooks") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "ExploitAction" }
    its("ExploitAction") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.3_L1_Ensure_Default_Protections_for_Internet_Explorer_is_set_to_Enabled" do
  title "(L1) Ensure 'Default Protections for Internet Explorer' is set to 'Enabled'"
  desc  "
    This settings determine if EMET mitigations are applied to Internet Explorer.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Applying EMET mitigations to Internet Explorer will help reduce the reliability of exploits that target it.
  "
  impact 1.0
  tag cce: "CCE-35474-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "IE" }
    its("IE") { should eq "*\\Internet Explorer\\iexplore.exe" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.4_L1_Ensure_Default_Protections_for_Popular_Software_is_set_to_Enabled" do
  title "(L1) Ensure 'Default Protections for Popular Software' is set to 'Enabled'"
  desc  "
    This settings determine if EMET mitigations are applied to other popular software.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Applying EMET mitigations to popular software packages will help reduce the reliability of exploits that target them.
  "
  impact 1.0
  tag cce: "CCE-35476-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "7z" }
    its("7z") { should match(/^\*\\7\-Zip\\7z\.exe/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "7zFM" }
    its("7zFM") { should match(/^\*\\7\-Zip\\7zFM\.exe/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "7zGUI" }
    its("7zGUI") { should match(/^\*\\7\-Zip\\7zG\.exe/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Chrome" }
    its("Chrome") { should eq "*\\Google\\Chrome\\Application\\chrome.exe -SEHOP" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Firefox" }
    its("Firefox") { should eq "*\\Mozilla Firefox\\firefox.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "FirefoxPluginContainer" }
    its("FirefoxPluginContainer") { should eq "*\\Mozilla Firefox\\plugin-container.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "FoxitReader" }
    its("FoxitReader") { should eq "*\\Foxit Reader\\Foxit Reader.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "GoogleTalk" }
    its("GoogleTalk") { should eq "*\\Google\\Google Talk\\googletalk.exe -DEP -SEHOP" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "iTunes" }
    its("iTunes") { should eq "*\\iTunes\\iTunes.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "LiveWriter" }
    its("LiveWriter") { should eq "*\\Windows Live\\Writer\\WindowsLiveWriter.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "LyncCommunicator" }
    its("LyncCommunicator") { should eq "*\\Microsoft Lync\\communicator.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "mIRC" }
    its("mIRC") { should eq "*\\mIRC\\mirc.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Opera" }
    its("Opera") { should eq "*\\Opera\\opera.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "PhotoGallery" }
    its("PhotoGallery") { should eq "*\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Photoshop" }
    its("Photoshop") { should eq "*\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Pidgin" }
    its("Pidgin") { should eq "*\\Pidgin\\pidgin.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "QuickTimePlayer" }
    its("QuickTimePlayer") { should match(/^\*\\QuickTime\\QuickTimePlayer\.exe/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "RealConverter" }
    its("RealConverter") { should eq "*\\Real\\RealPlayer\\realconverter.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "RealPlayer" }
    its("RealPlayer") { should eq "*\\Real\\RealPlayer\\realplay.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Safari" }
    its("Safari") { should eq "*\\Safari\\Safari.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "SkyDrive" }
    its("SkyDrive") { should eq "*\\SkyDrive\\SkyDrive.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Skype" }
    its("Skype") { should eq "*\\Skype\\Phone\\Skype.exe -EAF" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Thunderbird" }
    its("Thunderbird") { should match(/^\*\\Mozilla Thunderbird\thunderbird\.exe/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "ThunderbirdPluginContainer" }
    its("ThunderbirdPluginContainer") { should eq "*\\Mozilla Thunderbird\\plugin-container.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "UnRAR" }
    its("UnRAR") { should eq "*\\WinRAR\\unrar.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "VLC" }
    its("VLC") { should eq "*\\VideoLAN\\VLC\\vlc.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Winamp" }
    its("Winamp") { should eq "*\\Winamp\\winamp.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "WindowsMediaPlayer" }
    its("WindowsMediaPlayer") { should match(/^\*\\Windows Media Player\\wmplayer\.exe/) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "WinRARConsole" }
    its("WinRARConsole") { should eq "*\\WinRAR\\rar.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "WinRARGUI" }
    its("WinRARGUI") { should eq "*\\WinRAR\\winrar.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Winzip" }
    its("Winzip") { should eq "*\\WinZip\\winzip32.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Winzip64" }
    its("Winzip64") { should eq "*\\WinZip\\winzip64.exe" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.5_L1_Ensure_Default_Protections_for_Recommended_Software_is_set_to_Enabled" do
  title "(L1) Ensure 'Default Protections for Recommended Software' is set to 'Enabled'"
  desc  "
    This settings determine if recommended EMET mitigations are applied to WordPad, applications that are part of the Microsoft Office suite, Adobe Acrobat, Adobe Reader, and Oracle Java.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Applying EMET mitigations to recommended software will help reduce the reliability of exploits that target them.
  "
  impact 1.0
  tag cce: "CCE-35479-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Access" }
    its("Access") { should eq "*\\OFFICE1*\\MSACCESS.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Acrobat" }
    its("Acrobat") { should eq "*\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "AcrobatReader" }
    its("AcrobatReader") { should eq "*\\Adobe\\Reader*\\Reader\\AcroRd32.exe" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Excel" }
    its("Excel") { should eq "*\\OFFICE1*\\EXCEL.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "InfoPath" }
    its("InfoPath") { should eq "*\\OFFICE1*\\INFOPATH.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "jre6_java" }
    its("jre6_java") { should eq "*\\Java\\jre6\\bin\\java.exe -HeapSpray" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "jre6_javaw" }
    its("jre6_javaw") { should eq "*\\Java\\jre6\\bin\\javaw.exe -HeapSpray" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "jre6_javaws" }
    its("jre6_javaws") { should eq "*\\Java\\jre6\\bin\\javaws.exe -HeapSpray" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "jre7_java" }
    its("jre7_java") { should eq "*\\Java\\jre7\\bin\\java.exe -HeapSpray" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "jre7_javaw" }
    its("jre7_javaw") { should eq "*\\Java\\jre7\\bin\\javaw.exe -HeapSpray" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "jre7_javaws" }
    its("jre7_javaws") { should eq "*\\Java\\jre7\\bin\\javaws.exe -HeapSpray" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Lync" }
    its("Lync") { should eq "*\\OFFICE1*\\LYNC.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Outlook" }
    its("Outlook") { should eq "*\\OFFICE1*\\OUTLOOK.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Picture Manager" }
    its("Picture Manager") { should eq "*\\OFFICE1*\\OIS.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "PowerPoint" }
    its("PowerPoint") { should eq "*\\OFFICE1*\\POWERPNT.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "PPTViewer" }
    its("PPTViewer") { should eq "*\\OFFICE1*\\PPTVIEW.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Publisher" }
    its("Publisher") { should eq "*\\OFFICE1*\\MSPUB.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Visio" }
    its("Visio") { should eq "*\\OFFICE1*\\VISIO.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "VisioViewer" }
    its("VisioViewer") { should eq "*\\OFFICE1*\\VPREVIEW.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Word" }
    its("Word") { should eq "*\\OFFICE1*\\WINWORD.EXE" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "Wordpad" }
    its("Wordpad") { should eq "*\\Windows NT\\Accessories\\wordpad.exe" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.6_L1_Ensure_System_ASLR_is_set_to_Enabled_Application_Opt-In" do
  title "(L1) Ensure 'System ASLR' is set to 'Enabled: Application Opt-In'"
  desc  "
    This setting determines how applications become enrolled in address space layout randomization (ASLR).
    
    The recommended state for this setting is: Enabled: Application Opt-In.
    
    Rationale: ASLR reduces the predictability of process memory, which in-turn helps reduce the reliability of exploits targeting memory corruption vulnerabilities.
  "
  impact 1.0
  tag cce: "CCE-35483-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "ASLR" }
    its("ASLR") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.7_L1_Ensure_System_DEP_is_set_to_Enabled_Application_Opt-Out" do
  title "(L1) Ensure 'System DEP' is set to 'Enabled: Application Opt-Out'"
  desc  "
    This setting determines how applications become enrolled in data execution protection (DEP).
    
    The recommended state for this setting is: Enabled: Application Opt-Out.
    
    Rationale: DEP marks pages of application memory as non-executable, which reduces a given exploit's ability to run attacker-controlled code.
  "
  impact 1.0
  tag cce: "CCE-35484-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "DEP" }
    its("DEP") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.8_L1_Ensure_System_SEHOP_is_set_to_Enabled_Application_Opt-Out" do
  title "(L1) Ensure 'System SEHOP' is set to 'Enabled: Application Opt-Out'"
  desc  "
    This setting determines how applications become enrolled in structured exception handler overwrite protection (SEHOP).
    
    The recommended state for this setting is: Enabled: Application Opt-Out.
    
    Rationale: When a software component suffers from a memory corruption vulnerability, an exploit may be able to overwrite memory that contains data structures that control how the software handles exceptions. By corrupting these structures in a controlled manner, an exploit may be able to execute arbitrary code. SEHOP verifies the integrity of those structures before they are used to handle exceptions, which reduces the reliability of exploits that leverage structured exception handler overwrites.
  "
  impact 1.0
  tag cce: "CCE-35485-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "SEHOP" }
    its("SEHOP") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size. If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost. If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-34169-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "Retention" }
    its("Retention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-33975-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost.
    
    If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-35090-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "Retention" }
    its("Retention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater" do
  title "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 196,608 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-33428-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 196608 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost.
    
    If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-34170-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    it { should have_property "Retention" }
    its("Retention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  tag cce: "CCE-35091-8"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost.
    
    If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  tag cce: "CCE-33729-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "Retention" }
    its("Retention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  tag cce: "CCE-35288-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.2_L1_Ensure_Configure_Windows_SmartScreen_is_set_to_Enabled_Require_approval_from_an_administrator_before_running_downloaded_unknown_software" do
  title "(L1) Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'"
  desc  "
    This policy setting allows you to manage the behavior of Windows SmartScreen. Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.
    
    If you enable this policy setting, Windows SmartScreen behavior may be controlled by setting one of the following options:
    
    * Require approval from an administrator before running downloaded unknown software
    * Give user a warning before running downloaded unknown software
    * Turn off SmartScreen
    If you disable or do not configure this policy setting, Windows SmartScreen behavior is managed by administrators on the PC by using Windows SmartScreen Settings in Action Center.
    
    The recommended state for this setting is: Enabled: Require approval from an administrator before running downloaded unknown software.
    
    Rationale: Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. However, due to the fact that some information is sent to Microsoft about files and programs run on PCs some organizations may prefer to disable it.
  "
  impact 1.0
  tag cce: "CCE-34026-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnableSmartScreen" }
    its("EnableSmartScreen") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.3_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc  "
    Disabling data execution prevention can allow certain legacy plug-in applications to function without terminating Explorer.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Data Execution Prevention is an important security feature supported by Explorer that helps to limit the impact of certain types of malware.
  "
  impact 1.0
  tag cce: "CCE-33608-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoDataExecutionPrevention" }
    its("NoDataExecutionPrevention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.4_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc  "
    Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Allowing an application to function after its session has become corrupt increases the risk posture to the system.
  "
  impact 1.0
  tag cce: "CCE-33745-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoHeapTerminationOnCorruption" }
    its("NoHeapTerminationOnCorruption") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.5_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc  "
    This policy setting allows you to configure the amount of functionality that the shell protocol can have. When using the full functionality of this protocol applications can open folders and launch files. The protected mode reduces the functionality of this protocol allowing applications to only open a limited set of folders. Applications are not able to open files with this protocol when it is in the protected mode. It is recommended to leave this protocol in the protected mode to increase the security of Windows.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Limiting the opening of files and folders to a limited set reduces the attack surface of the system.
  "
  impact 1.0
  tag cce: "CCE-33764-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "PreXPSP2ShellProtocolBehavior" }
    its("PreXPSP2ShellProtocolBehavior") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.31.1_L1_Ensure_Prevent_the_computer_from_joining_a_homegroup_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'"
  desc  "
    By default, users can add their computer to a homegroup on a home network.
    
    If you enable this policy setting, a user on this computer will not be able to add this computer to a homegroup. This setting does not affect other network sharing features.
    
    If you disable or do not configure this policy setting, a user can add this computer to a homegroup. However, data on a domain-joined computer is not shared with the homegroup. Configure this setting in a manner that is consistent with security and operational requirements of your organization.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: By default, domain joined computers can be joined to a HomeGroup. While resources on a domain-joined computer cannot be shared to the HomeGroup, information from the domain-joined computer can be leaked to other computers in the HomeGroup.
  "
  impact 1.0
  tag cce: "CCE-34776-5"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup") do
    it { should have_property "DisableHomeGroup" }
    its("DisableHomeGroup") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.1_L1_Ensure_Configure_Cookies_is_set_to_Enabled_Block_only_3rd-party_cookies._or_higher" do
  title "(L1) Ensure 'Configure Cookies' is set to 'Enabled: Block only 3rd-party cookies.' or higher"
  desc  "
    This setting lets you configure how your company deals with cookies.
    
    The recommended state for this setting is: Enabled: Block only 3rd-party cookies. Configuring this setting to Enabled: Block all cookies. also conforms with the benchmark.
    
    Rationale: Cookies can pose a serious privacy concern, many websites depend on them for operation. It is recommended when possible to block 3rd party cookies in order to reduce tracking.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    it { should have_property "Cookies" }
    its("Cookies") { should cmp <= 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.4_L1_Ensure_Dont_allow_WebRTC_to_share_the_LocalHost_IP_address_is_set_to_Enabled" do
  title "(L1) Ensure 'Don't allow WebRTC to share the LocalHost IP address' is set to 'Enabled'"
  desc  "
    This setting lets you decide whether an employee's LocalHost IP address shows while making phone calls using the WebRTC protocol.
    
    The recommended state for this setting is: Enabled
    
    Rationale: WebRTC is a Real-Time Communications open source project supported by all major browsers. Allowing a system's local IP address to be shared may be considered a privacy concern.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    it { should have_property "HideLocalHostIP" }
    its("HideLocalHostIP") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.5_L1_Ensure_Turn_off_address_bar_search_suggestions_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off address bar search suggestions' is set to 'Disabled'"
  desc  "
    This setting lets you decide whether search suggestions should appear in the Address bar of Microsoft Edge.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Having search suggestions sent out to be processed is considered a privacy concern.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\SearchScopes") do
    it { should have_property "ShowSearchSuggestionsGlobal" }
    its("ShowSearchSuggestionsGlobal") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.7_L1_Ensure_Turn_off_Password_Manager_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Password Manager' is set to 'Disabled'"
  desc  "
    This setting lets you decide whether employees can save their passwords locally, using Password Manager.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Using Password Manager can potentially makes it easier for an unauthorized user who gains access to the user#x2019;s desktop (including a coworker who sits down at a user#x2019;s desk soon after the user walks away and forgets to lock their workstation), to log in to sites as the user, without needing to know or enter the password
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    it { should have_property "FormSuggest Passwords" }
    its("FormSuggest Passwords") { should cmp "no" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.9_L1_Ensure_Turn_off_the_SmartScreen_Filter_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off the SmartScreen Filter' is set to 'Enabled'"
  desc  "
    This setting lets you decide whether to turn on SmartScreen Filter. SmartScreen Filter provides warning messages to help protect your employees from potential phishing scams and malicious software.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: SmartScreen serves an important purpose as it helps to warn users of possible malicious sites and files. Allowing users to turn off this setting can make the browser become more vulnerable to compromise.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter") do
    it { should have_property "EnabledV9" }
    its("EnabledV9") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.43.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc  "
    This policy setting lets you prevent apps and features from working with files on OneDrive.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting prevents users from accidentally uploading confidential or sensitive corporate information to OneDrive cloud service.
  "
  impact 1.0
  tag cce: "CCE-33826-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive") do
    it { should have_property "DisableFileSyncNGSC" }
    its("DisableFileSyncNGSC") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc  "
    This policy setting helps prevent Remote Desktop Services / Terminal Services clients from saving passwords on a computer. Note If this policy setting was previously configured as Disabled or Not configured, any previously saved passwords will be deleted the first time a Terminal Services client disconnects from any server.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An attacker with physical access to the computer may be able to break the protection guarding saved passwords. An attacker who compromises a user's account and connects to their computer could use saved passwords to gain access to additional hosts.
  "
  impact 1.0
  tag cce: "CCE-34506-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DisablePasswordSaving" }
    its("DisablePasswordSaving") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc  "
    This policy setting prevents users from sharing the local drives on their client computers to Terminal Servers that they access. Mapped drives appear in the session folder tree in Windows Explorer in the following format:
    
    [
                                  \\\\TSClient\\
                                  
    <driveletter>
                                  $
                               ](file://\\\\TSClient\\<driveletter>$)
    
    If local drives are shared they are left vulnerable to intruders who want to exploit the data that is stored on them.
    
    The recommended state for this setting is: Enabled.</driveletter></driveletter>
    
    Rationale: Data could be forwarded from the user's Terminal Server session to the user's local computer without any direct user interaction.
  "
  impact 1.0
  tag cce: "CCE-34697-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fDisableCdm" }
    its("fDisableCdm") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled" do
  title "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether Terminal Services always prompts the client computer for a password upon connection. You can use this policy setting to enforce a password prompt for users who log on to Terminal Services, even if they already provided the password in the Remote Desktop Connection client. By default, Terminal Services allows users to automatically log on if they enter a password in the Remote Desktop Connection client.
    
    **Note:** If you do not configure this policy setting, the local computer administrator can use the Terminal Services Configuration tool to either allow or prevent passwords from being automatically sent.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Users have the option to store both their username and password when they create a new Remote Desktop connection shortcut. If the server that runs Terminal Services allows users who have used this feature to log on to the server but not enter their password, then it is possible that an attacker who has gained physical access to the user's computer could connect to a Terminal Server through the Remote Desktop connection shortcut, even though they may not know the user's password.
  "
  impact 1.0
  tag cce: "CCE-33960-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fPromptForPassword" }
    its("fPromptForPassword") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled" do
  title "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to specify whether a terminal server requires secure remote procedure call (RPC) communication with all clients or allows unsecured communication.
    
    You can use this policy setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing unsecure RPC communication can exposes the server to man in the middle attacks and data disclosure attacks.
  "
  impact 1.0
  tag cce: "CCE-35723-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fEncryptRPCTraffic" }
    its("fEncryptRPCTraffic") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level" do
  title "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc  "
    This policy setting specifies whether the computer that is about to host the remote connection will enforce an encryption level for all data sent between it and the client computer for the remote session.
    
    The recommended state for this setting is: Enabled: High Level.
    
    Rationale: If Terminal Server client connections are allowed that use low level encryption, it is more likely that an attacker will be able to decrypt any captured Terminal Services network traffic.
  "
  impact 1.0
  tag cce: "CCE-35578-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "MinEncryptionLevel" }
    its("MinEncryptionLevel") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
  desc  "
    By default, Remote Desktop Services creates a separate temporary folder on the RD Session Host server for each active session that a user maintains on the RD Session Host server. The temporary folder is created on the RD Session Host server in a Temp folder under the user's profile folder and is named with the \"sessionid.\" This temporary folder is used to store individual temporary files.
    
    To reclaim disk space, the temporary folder is deleted when the user logs off from a session.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: By Disabling this setting you are keeping the cached data independent for each session, both reducing the chance of problems from shared cached data between sessions, and keeping possibly sensitive data separate to each user session.
  "
  impact 1.0
  tag cce: "CCE-34531-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "PerSessionTempDir" }
    its("PerSessionTempDir") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Remote Desktop Services retains a user's per-session temporary folders at logoff.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Sensitive information could be contained inside the temporary folders and shared with other administrators that log into the system.
  "
  impact 1.0
  tag cce: "CCE-34136-2"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DeleteTempDirsOnExit" }
    its("DeleteTempDirsOnExit") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.49.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc  "
    This policy setting prevents the user from having enclosures (file attachments) downloaded from a feed to the user's computer.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing attachments to be downloaded through the RSS feed can introduce files that could have malicious intent.
  "
  impact 1.0
  tag cce: "CCE-34822-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
    it { should have_property "DisableEnclosureDownload" }
    its("DisableEnclosureDownload") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.50.2_L1_Ensure_Allow_Cortana_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Cortana' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Cortana is allowed on the device.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If Cortana is enabled, sensitive information could be contained in search history and sent out to Microsoft.
  "
  impact 1.0
  tag cce: "CCE-41421-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowCortana" }
    its("AllowCortana") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.50.3_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc  "
    This policy setting allows encrypted items to be indexed. If you enable this policy setting, indexing will attempt to decrypt and index the content (access restrictions will still apply). If you disable this policy setting, the search service components (including non-Microsoft components) are expected not to index encrypted items or encrypted stores. This policy setting is not configured by default. If you do not configure this policy setting, the local setting, configured through Control Panel, will be used. By default, the Control Panel setting is set to not index encrypted content. When this setting is enabled or disabled, the index is rebuilt completely. Full volume encryption (such as BitLocker Drive Encryption or a non-Microsoft solution) must be used for the location of the index to maintain security for encrypted files.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Indexing and allowing users to search encrypted files could potentially reveal confidential data stored within the encrypted files.
  "
  impact 1.0
  tag cce: "CCE-35314-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowIndexingEncryptedStoresOrItems" }
    its("AllowIndexingEncryptedStoresOrItems") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.50.4_L1_Ensure_Allow_search_and_Cortana_to_use_location_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether search and Cortana can provide location aware search and Cortana results.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: In an Enterprise having Cortana and Search having access to location is unnecessary. Organizations may not want this information shared out.
  "
  impact 1.0
  tag cce: "CCE-41372-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowSearchToUseLocation" }
    its("AllowSearchToUseLocation") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.58.2_L1_Ensure_Turn_off_Automatic_Download_and_Install_of_updates_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
  desc  "
    This setting enables or disables the automatic download and installation of app updates.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Keeping your system properly patched can help protect against 0 day vulnerabilities.
  "
  impact 1.0
  tag cce: "CCE-35807-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    it { should have_property "AutoDownload" }
    its("AutoDownload") { should cmp == 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.58.3_L1_Ensure_Turn_off_the_offer_to_update_to_the_latest_version_of_Windows_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
  desc  "
    Enables or disables the Store offer to update to the latest version of Windows.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Unplanned OS upgrades can lead to more preventable support calls. IT should be pushing only approved updates to the machine.
  "
  impact 1.0
  tag cce: "CCE-35809-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    it { should have_property "DisableOSUpgrade" }
    its("DisableOSUpgrade") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.68.1_L1_Ensure_Enables_or_disables_Windows_Game_Recording_and_Broadcasting_is_set_to_Disabled" do
  title "(L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
  desc  "
    This setting enables or disables the Windows Game Recording and Broadcasting features. If you disable this setting, Windows Game Recording will not be allowed. If the setting is enabled or not configured, then Recording and Broadcasting (streaming) will be allowed.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If this setting is allowed users could record and broadcast session info to external sites which is a privacy concern.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR") do
    it { should have_property "AllowGameDVR" }
    its("AllowGameDVR") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.69.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc  "
    Permits users to change installation options that typically are available only to system administrators. The security features of Windows Installer prevent users from changing installation options typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: In an Enterprise environment, only IT staff with administrative rights should be installing or changing software on a system. Allowing users the ability can risk unapproved software from being installed our removed from a system which could cause the system to become vulnerable.
  "
  impact 1.0
  tag cce: "CCE-35431-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "EnableUserControl" }
    its("EnableUserControl") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.69.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled" do
  title "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  "
    Directs Windows Installer to use system permissions when it installs any program on the system.
    
    This setting extends elevated privileges to all programs. These privileges are usually reserved for programs that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available in Add or Remove Programs in Control Panel. This setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    
    If you disable this setting or do not configure it, the system applies the current user's permissions when it installs programs that a system administrator does not distribute or offer.
    
    **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.
    
    **Caution:** Skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users with limited privileges can exploit this feature by creating a Windows Installer installation package that creates a new local account that belongs to the local built-in Administrators group, adds their current account to the local built-in Administrators group, installs malicious software, or performs other unauthorized activities.
  "
  impact 1.0
  tag cce: "CCE-35400-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "AlwaysInstallElevated" }
    its("AlwaysInstallElevated") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.70.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled" do
  title "(L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
  desc  "
    This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system. If you enable or do not configure this policy setting the device securely saves the user's credentials (including the user name domain and encrypted password) to configure automatic sign-in after a Windows Update restart. After the Windows Update restart the user is automatically signed-in and the session is automatically locked with all the lock screen apps configured for that user. If you disable this policy setting the device does not store the user's credentials for automatic sign-in after a Windows Update restart. The users' lock screen apps are not restarted after the system restarts.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Disabling this feature will prevent the caching of user's credentials and unauthorized use of the device, and also ensure the user is aware of the restart.
  "
  impact 1.0
  tag cce: "CCE-33891-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "DisableAutomaticRestartSignOn" }
    its("DisableAutomaticRestartSignOn") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.79.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
  desc  "
    This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Due to the potential risks of capturing passwords in the logs. This setting should only be needed for debugging purposes, and not in normal operation, it is important to ensure this is set to Disabled.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging") do
    it { should have_property "EnableScriptBlockLogging" }
    its("EnableScriptBlockLogging") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.79.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
  desc  "
    This Policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If this setting is enabled there is a risk that passwords could get stored in plain text in the PowerShell_transcript output file.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription") do
    it { should have_property "EnableTranscripting" }
    its("EnableTranscripting") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Basic authentication.
    
    If you enable this policy setting, the WinRM client will use Basic authentication. If WinRM is configured to use HTTP transport, then the user name and password are sent over the network as clear text.
    
    If you disable or do not configure this policy setting, then the WinRM client will not use Basic authentication.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  tag cce: "CCE-35258-3"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowBasic" }
    its("AllowBasic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client sends and receives unencrypted messages over the network.
    
    If you enable this policy setting, the WinRM client sends and receives unencrypted messages over the network.
    
    If you disable or do not configure this policy setting, the WinRM client sends or receives only encrypted messages over the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  tag cce: "CCE-34458-0"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowUnencryptedTraffic" }
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client will not use Digest authentication.
    
    If you enable this policy setting, the WinRM client will not use Digest authentication.
    
    If you disable or do not configure this policy setting, the WinRM client will use Digest authentication.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Digest authentication is less robust than other authentication methods available in WinRM, an attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  tag cce: "CCE-34778-1"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowDigest" }
    its("AllowDigest") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.
    
    If you enable this policy setting, the WinRM service will accept Basic authentication from a remote client.
    
    If you disable or do not configure this policy setting, the WinRM service will not accept Basic authentication from a remote client.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  tag cce: "CCE-34779-9"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowBasic" }
    its("AllowBasic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.
    
    If you enable this policy setting, the WinRM client sends and receives unencrypted messages over the network.
    
    If you disable or do not configure this policy setting, the WinRM client sends or receives only encrypted messages over the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  tag cce: "CCE-35054-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowUnencryptedTraffic" }
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.3_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will not allow RunAs credentials to be stored for any plug-ins.
    
    If you enable this policy setting, the WinRM service will not allow the RunAsUser or RunAsPassword configuration values to be set for any plug-ins. If a plug-in has already set the RunAsUser and RunAsPassword configuration values, the RunAsPassword configuration value will be erased from the credential store on this computer.
    
    If you disable or do not configure this policy setting, the WinRM service will allow the RunAsUser and RunAsPassword configuration values to be set for plug-ins and the RunAsPassword value will be stored securely.
    
    If you enable and then disable this policy setting, any values that were previously configured for RunAsPassword will need to be reset.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Although the ability to store RunAs credentials is a convenient feature it increases the risk of account compromise slightly. For example, if you forget to lock your desktop before leaving it unattended for a few minutes another person could access not only the desktop of your computer but also any hosts you manage via WinRM with cached RunAs credentials.
  "
  impact 1.0
  tag cce: "CCE-35416-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "DisableRunAs" }
    its("DisableRunAs") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.1_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled" do
  title "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.
    
    After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:
    - Notify before downloading any updates and notify again before installing them.
    - Download the updates automatically and notify when they are ready to be installed. (Default setting)
    - Automatically download updates and install them on the schedule specified below.
    
    If you disable this policy setting, you will need to download and manually install any available updates from Windows Update.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  tag cce: "CCE-35111-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "NoAutoUpdate" }
    its("NoAutoUpdate") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.2_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day" do
  title "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc  "
    This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.
    
    After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:
    - Notify before downloading any updates and notify again before installing them.
    - Download the updates automatically and notify when they are ready to be installed. (Default setting)
    - Automatically download updates and install them on the schedule specified below.
    
    If you disable this policy setting, you will need to download and manually install any available updates from Windows Update.
    
    The recommended state for this setting is: 0 - Every day.
    
    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  tag cce: "CCE-35111-4"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "ScheduledInstallDay" }
    its("ScheduledInstallDay") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.3_L1_Ensure_Defer_Upgrades_and_Updates_is_set_to_Enabled_8_months_0_weeks" do
  title "(L1) Ensure 'Defer Upgrades and Updates' is set to 'Enabled: 8 months, 0 weeks'"
  desc  "
    If you enable this policy setting, in Pro and Enterprise SKUs you can defer upgrades till the next upgrade period (at least a few months). If you do not have it set you will receive upgrades once they are available that will be installed as part of your update policies. Security updates will not be impacted by this policy. For more information on available upgrades see [windows.com/itpro](http://windows.com/itpro).
    
    The recommended state for this setting is:
    
    Defer Upgrades and Updates - **Enabled**
    Defer upgrades for the following duration (months) - **8 months**
    Defer updates for the following duration (weeks) - **0 weeks**
    Pause Upgrades and Updates - **unchecked**
    
    Rationale: Forcing upgrades to features without testing in your environment could cause software incompatibilities as well as introducing new bugs into the operating system.
  "
  impact 1.0
  tag cce: "CCE-41427-6"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should have_property "DeferUpgrade" }
    its("DeferUpgrade") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should have_property "DeferUpgradePeriod" }
    its("DeferUpgradePeriod") { should cmp == 8 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should have_property "DeferUpdatePeriod" }
    its("DeferUpdatePeriod") { should cmp == 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should_not have_property "PauseDeferrals" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled" do
  title "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
  desc  "
    This policy setting specifies that Automatic Updates will wait for computers to be restarted by the users who are logged on to them to complete a scheduled installation.
    
    If you enable the No auto-restart for scheduled Automatic Updates installations setting, Automatic Updates does not restart computers automatically during scheduled installations. Instead, Automatic Updates notifies users to restart their computers to complete the installations. You should note that Automatic Updates will not be able to detect future updates until restarts occur on the affected computers. If you disable or do not configure this setting, Automatic Updates will notify users that their computers will automatically restart in 5 minutes to complete the installations.
    
    The possible values for the No auto-restart for scheduled Automatic Updates installations setting are:
    - Enabled
    - Disabled
    - Not Configured
    
    **Note:** This setting applies only when you configure Automatic Updates to perform scheduled update installations. If you configure the Configure Automatic Updates setting to Disabled, this setting has no effect.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Sometimes updates require updated computers to be restarted to complete an installation. If the computer cannot restart automatically, then the most recent update will not completely install and no new updates will download to the computer until it is restarted.
  "
  impact 1.0
  tag cce: "CCE-33813-7"
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "NoAutoRebootWithLoggedOnUsers" }
    its("NoAutoRebootWithLoggedOnUsers") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.1_L1_Ensure_Enable_screen_saver_is_set_to_Enabled" do
  title "(L1) Ensure 'Enable screen saver' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether or not screen savers run. If the Screen Saver setting is disabled screen savers do not run and the screen saver section of the Screen Saver tab in Display in Control Panel is disabled. If this setting is enabled a screen saver will run if the following two conditions are met: first, that a valid screen saver is specified on the client via the Screen Saver Executable Name group policy setting or Control Panel on the client. Second, the screensaver timeout is set to a value greater than zero via the Screen Saver Timeout group policy setting or Control Panel on the client.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  tag cce: "CCE-33164-5"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaveActive") { should eq "1" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.2_L1_Ensure_Force_specific_screen_saver_Screen_saver_executable_name_is_set_to_Enabled_scrnsave.scr" do
  title "(L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'"
  desc  "
    This policy setting allows you to manage whether or not screen savers run. If the Screen Saver setting is disabled screen savers do not run and the screen saver section of the Screen Saver tab in Display in Control Panel is disabled. If this setting is enabled a screen saver will run if the following two conditions are met: first, that a valid screen saver is specified on the client via the Screen Saver Executable Name group policy setting or Control Panel on the client. Second, the screensaver timeout is set to a value greater than zero via the Screen Saver Timeout group policy setting or Control Panel on the client.
    
    The recommended state for this setting is: Enabled: scrnsave.scr.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  tag cce: "CCE-33105-8"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("SCRNSAVE.EXE") { should eq "scrnsave.scr" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.3_L1_Ensure_Password_protect_the_screen_saver_is_set_to_Enabled" do
  title "(L1) Ensure 'Password protect the screen saver' is set to 'Enabled'"
  desc  "
    If the Password protect the screen saver setting is enabled, then all screen savers are password protected, if it is disabled then password protection cannot be set on any screen saver.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user forgets to lock their computer when they walk away it is possible that a passerby will hijack it.
  "
  impact 1.0
  tag cce: "CCE-32938-3"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaverIsSecure") { should eq "1" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.4_L1_Ensure_Screen_saver_timeout_is_set_to_Enabled_900_seconds_or_fewer_but_not_0" do
  title "(L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
  desc  "
    If the Screen Saver Timeout setting is enabled, then the screen saver will be launched when the specified amount of time has passed since the last user action. Valid values range from 1 to 89,400 seconds (24 hours). The setting has no effect if the wait time is set to zero or no screen saver has been specified.
    
    The recommended state for this setting is: Enabled: 900 seconds or fewer, but not 0.
    
    Rationale: If a user forgets to lock their computer when they walk away it is possible that a passerby will hijack it.
  "
  impact 1.0
  tag cce: "CCE-33168-6"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaveTimeOut") { should cmp <= 900 }
    end
  end
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaveTimeOut") { should cmp != 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.5.1.1_L1_Ensure_Turn_off_toast_notifications_on_the_lock_screen_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting turns off toast notifications on the lock screen. If you enable this policy setting, applications will not be able to raise toast notifications on the lock screen. If you disable or do not configure this policy setting, toast notifications on the lock screen are enabled and can be turned off by the administrator or user. No reboots or service restarts are required for this policy setting to take effect.
    
    The recommended state for this setting is Enabled.
    
    Rationale: While this feature can be handy for users applications that provide toast notifications might display sensitive personal or business data while the device is unattended.
  "
  impact 1.0
  tag cce: "CCE-33727-9"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications/).each do |entry|
    describe registry_key(entry) do
      its("NoToastApplicationNotificationOnLockScreen") { should cmp == 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.4.1_L1_Ensure_Do_not_preserve_zone_information_in_file_attachments_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether Windows marks file attachments from Internet Explorer or Microsoft Outlook' Express with information about their zone of origin (such as restricted, Internet, intranet, or local). This policy setting requires that files be downloaded to NTFS disk partitions to function correctly. If zone information is not preserved, Windows cannot make proper risk assessments based on the zone where the attachment came from.
    
    If the Do not preserve zone information in file attachments setting is enabled, file attachments are not marked with their zone information. If this policy setting is disabled, Windows is forced to store file attachments with their zone information.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A file that is downloaded from a computer in the Internet or Restricted Sites zone may be moved to a location that makes it appear safe, like an intranet file share, and executed by an unsuspecting user.
  "
  impact 1.0
  tag cce: "CCE-34810-2"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments/).each do |entry|
    describe registry_key(entry) do
      its("SaveZoneInformation") { should cmp == 2 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.4.2_L1_Ensure_Notify_antivirus_programs_when_opening_attachments_is_set_to_Enabled" do
  title "(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
  desc  "
    Antivirus programs are mandatory in many environments and provide a strong defense against attack.
    
    The Notify antivirus programs when opening attachments setting allows you to manage how registered antivirus programs are notified. When enabled, this policy setting configures Windows to call the registered antivirus program and have it scan file attachments when they are opened by users. If the antivirus scan fails, the attachments are blocked from being opened. If this policy setting is disabled, Windows does not call the registered antivirus program when file attachments are opened.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** An updated antivirus program must be installed for this policy setting to function properly.
    
    Rationale: Antivirus programs that do not perform on-access checks may not be able to scan downloaded files.
  "
  impact 1.0
  tag cce: "CCE-33799-8"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments/).each do |entry|
    describe registry_key(entry) do
      its("ScanWithAntiVirus") { should cmp == 3 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.25.1_L1_Ensure_Prevent_users_from_sharing_files_within_their_profile._is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether users can share files within their profile. By default users are allowed to share files within their profile to other users on their network after an administrator opts in the computer. An administrator can opt in the computer by using the sharing wizard to share a file within their profile.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If not properly controlled a user could accidentally share sensitive data with unauthorized users. In a corporate environment, the company should provide a managed location for file sharing, such as a file server or SharePoint.
  "
  impact 1.0
  tag cce: "CCE-33490-4"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer/).each do |entry|
    describe registry_key(entry) do
      its("NoInplaceSharing") { should cmp == 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.37.1_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled" do
  title "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  "
    Directs Windows Installer to use system permissions when it installs any program on the system.
    
    This setting extends elevated privileges to all programs. These privileges are usually reserved for programs that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available in Add or Remove Programs in Control Panel. This setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    
    If you disable this setting or do not configure it, the system applies the current user's permissions when it installs programs that a system administrator does not distribute or offer.
    
    **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.
    
    **Caution:** Skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users with limited privileges can exploit this feature by creating a Windows Installer installation package that creates a new local account that belongs to the local built-in Administrators group, adds their current account to the local built-in Administrators group, installs malicious software, or performs other unauthorized activities.
  "
  impact 1.0
  tag cce: "CCE-34788-0"
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Installer/).each do |entry|
    describe registry_key(entry) do
      its("AlwaysInstallElevated") { should cmp == 0 }
    end
  end
end