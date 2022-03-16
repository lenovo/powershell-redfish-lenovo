###
#
# Lenovo Redfish examples - set manager LDAP server
#
# Copyright Notice:
#
# Copyright 2022 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


###
#  Import utility libraries
###
Import-module $PSScriptRoot\lenovo_utils.psm1

function parse_ldapserver
{
    param(
        [Parameter(Mandatory=$False)]
        [string[]]$ldapserver=@()
    )
    $serverlist = @()
    $portlist = @()
    foreach ($server in $ldapserver)
    {
        if ($server.Contains(":"))
        {
            $addr = $server.split(':')[0]
            $port = $server.split(':')[-1]
        }
        else 
        {
            $addr = $server
            $port = '389'
        }
        
        $serverlist += $addr
        $portlist += $port
    }
    return ($serverlist, $portlist)
}


function lenovo_set_bmc_external_ldap
{
   <#
   .Synopsis
    Cmdlet used to set manager LDAP server
   .DESCRIPTION
    Cmdlet used to set manager LDAP server from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - ldapserver: 
        If you choose the pre-configured option, at least one server must be configured.
        Manually configure LDAP servers by entering each server IP/hostname with port(up to 4 servers allowed). 
        The format should be IP:port. If port is not specified, default port 389 will be used. 
        e.g. -ldapserver 10.10.10.1:389 10.10.10.2. 
    - clientdn: 
        Specify the Client Distinguished Name(DN) to be used for the initial bind. 
        If DN is not specified, try to bind anonymous. Note that LDAP Binding Method must be set to "Configured". 
    - clientpwd: 
        Specify password for binding LDAP server with a DN and password. 
        Note that LDAP Binding Method must be set to "Configured".
    - rootdn: 
        BMC uses the "ROOT DN" field in Distinguished Name format as root entry of directory tree. 
        This DN will be used as the base object for all searches.
    - uid_search_attribute: 
        This search request must specify the attribute name used to represent user IDs on that server.
        On Active Directory servers, this attribute name is usually sAMAccountName.
        On Novell eDirectory and OpenLDAP servers, it is usually uid.
        Default is uid. Allowable values for ThinkSystem SR635/SR655 should be cn or uid.
    - group_filter: 
        This field is used for group authentication, limited to 511 characters, and consists of one or more group names. 
        This parameter is not for ThinkSystem SR635/SR655.
    - group_search_attribute: 
        This field is used by the search algorithm to find group membership infomation for a specific user. 
        Default is memberof. This parameter is not for ThinkSystem SR635/SR655.
    - config_file: Pass in configuration file path, default configuration file is config.ini
    .EXAMPLE
    lenovo_set_bmc_external_ldap -ip 10.10.10.10 -username USERID -password PASSW0RD -ldapserver @("10.10.10.1:389", "10.10.10.2")
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string[]]$ldapserver=@(),
        [Parameter(Mandatory=$False)]
        [string]$clientdn="",
        [Parameter(Mandatory=$False)]
        [string]$clientpwd="",
        [Parameter(Mandatory=$False)]
        [string]$rootdn=$null,
        [Parameter(Mandatory=$False)]
        [string]$uid_search_attribute="uid",
        [Parameter(Mandatory=$False)]
        [string]$group_filter="",
        [Parameter(Mandatory=$False)]
        [string]$group_search_attribute="memberof",
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini"
    )
        
    # Get configuration info from config file
    $ht_config_ini_info = read_config -config_file $config_file

    # If the parameter is not specified via command line, use the setting from configuration file
    if ($ip -eq "")
    {
        $ip = [string]($ht_config_ini_info['BmcIp'])
    }
    if ($username -eq "")
    {
        $username = [string]($ht_config_ini_info['BmcUsername'])
    }
    if ($password -eq "")
    {
        $password = [string]($ht_config_ini_info['BmcUserpassword'])
    }
    # Check user specified parameter
    if (($clientdn -ne "") -and ($clientpwd -eq ""))
    {
        [String]::Format("bindpassword for binddn must be configured.")
        return $False
    }
    if ($ldapserver.length -gt 4)
    {
        [String]::Format("Users can only specify up to 4 LDAP servers.")
        return $False
    }
    try
    {
        $session_key = ""

        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $JsonHeader = @{"X-Auth-Token" = $session_key}

        # Get the base url via Invoke-WebRequest
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert base response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $base_hash_table = @{}
        $converted_object.psobject.properties | ForEach { $base_hash_table[$_.Name] = $_.Value }

        # Use standard API for LDAP in AccountService first
        $account_service_url_string = "https://$ip"+$base_hash_table.AccountService.'@odata.id'
        # Get the AccountService url via Invoke-WebRequest
        $response_account_service = Invoke-WebRequest -Uri $account_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_service content to hash table
        $converted_account_service_object = $response_account_service.Content | ConvertFrom-Json
        
        # Set for SR635/SR655 using standard API with some oem properties
        if ($null -ne $converted_account_service_object.Oem)
        {
            if ($null -ne $converted_account_service_object.Oem.'Ami')
            {
                try
                {
                    $encryption_type = $converted_account_service_object.'LDAP'.'Authentication'.'Oem'.'Ami'.'EncryptionType'
                }
                catch
                {
                    $encryption_type = 'NoEncryption'
                }
                # Build request body for set ldap server
                $body = @{}
                $body['ServiceEnabled'] = $True # Enable the LDAP service for user to use
                $body['Authentication'] = @{}
                $body['Authentication']['Oem'] = @{}
                $body['Authentication']['Oem']['Ami'] = @{}
                $body['Authentication']['Oem']['Ami']['EncryptionType'] = $encryption_type
                $body['Authentication']['Oem']['Ami']['CommonNameType'] = 'IPAddress'
                if ("" -ne $clientdn)
                { 
                    $body['Authentication']['Username'] = $clientdn
                    $body['Authentication']['Password'] = $clientpwd
                    $body['Authentication']['Oem']['Ami']['BindingMethod'] = 'PreConfiguredCredential'
                }
                else 
                {
                    $body['Authentication']['Oem']['Ami']['BindingMethod'] = 'LoginCredential'
                }
                $body['LDAPService'] = @{}
                $body['LDAPService']['SearchSettings'] = @{}

                if ( [string]::IsNullOrEmpty($rootdn) ){
                    $body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = @($nothing)
                }
                else{
                    $body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = @()
                    $body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] += $rootdn
                }
                
                $body['LDAPService']['SearchSettings']['GroupsAttribute'] = $uid_search_attribute
                $body['ServiceAddresses'] = @()
                $serverlist, $portlist = parse_ldapserver($ldapserver)
                foreach ($i in @(0..($serverlist.length-1)))
                {
                    $server_info = $serverlist[$i] + ":" + $portlist[$i]
                    $body['ServiceAddresses'] += $server_info
                }

                # Patch the new LDAP setting
                $request_body = @{}
                $request_body['LDAP'] = $body
                $json_body = $request_body | ConvertTo-Json -Depth 10
                $Header = @{ "If-Match" = "*"; "X-Auth-Token" = $session_key}
                $response = Invoke-WebRequest -Uri $account_service_url_string -Headers $Header -Method patch -Body $json_body -ContentType 'application/json'
            
                [String]::Format("- PASS, statuscode {0} returned successfully to configured LDAP server.",$response.StatusCode)
                return 
            }
        }

        # Set for servers except SR635/SR655
        if ($null -ne $converted_account_service_object.LDAP)
        {
            if ($null -ne $converted_account_service_object.LDAP.'LDAPService')
            {
                # Build request body for set ldap server
                $body = @{}
                $body['ServiceEnabled'] = $True # Enable the LDAP service for user to use
                if ("" -ne $clientdn)
                { 
                    $body['Authentication'] = @{}
                    $body['Authentication']['Username'] = $clientdn
                    $body['Authentication']['Password'] = $clientpwd
                    $body['Authentication']['AuthenticationType'] = "UsernameAndPassword"
                }
                $body['LDAPService'] = @{}
                $body['LDAPService']['SearchSettings'] = @{}
                if ( [string]::IsNullOrEmpty($rootdn) ){
                    $body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = @($nothing)
                }
                else{
                    $body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] = @()
                    $body['LDAPService']['SearchSettings']['BaseDistinguishedNames'] += $rootdn
                }
                $body['LDAPService']['SearchSettings']['GroupsAttribute'] = $group_filter
                $body['LDAPService']['SearchSettings']['GroupNameAttribute'] = $group_search_attribute
                $body['LDAPService']['SearchSettings']['UsernameAttribute'] = $uid_search_attribute
                $body['ServiceAddresses'] = @()
                $serverlist, $portlist = parse_ldapserver($ldapserver)
                foreach ($i in @(0..($serverlist.length-1)))
                {
                    $server_info = $serverlist[$i] + ":" + $portlist[$i]
                    $body['ServiceAddresses'] += $server_info
                }
                
                # Patch the new LDAP setting
                $request_body = @{}
                $request_body['LDAP'] = $body 
                $json_body = $request_body | ConvertTo-Json -Depth 10
                $response = Invoke-WebRequest -Uri $account_service_url_string -Headers $JsonHeader -Method patch -Body $json_body -ContentType 'application/json'
            
                [String]::Format("- PASS, statuscode {0} returned successfully to configured LDAP server.",$response.StatusCode)
                return 
            }
        }
               
        # Use Oem API /redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/LDAPClient
        $managers_url = "https://$ip"+$base_hash_table.Managers.'@odata.id'

        # Get the managers url(/redfish/v1/Managers) via Invoke-WebRequest
        $response_managers_url = Invoke-WebRequest -Uri $managers_url -Headers $JsonHeader -Method Get -UseBasicParsing
        
        # Convert response_managers_url content to hash table
        $converted_managers_object = $response_managers_url.Content | ConvertFrom-Json
        $managers_hash_table = @{}
        $converted_managers_object.psobject.properties | Foreach { $managers_hash_table[$_.Name] = $_.Value }
        
        foreach ($i in $managers_hash_table.Members)
        {
            $s_manager_url = "https://$ip" + $i.'@odata.id'

            # Get the single manager url(/redfish/v1/Managers/1) via Invoke-WebRequest
            $response_s_manager_url = Invoke-WebRequest -Uri $s_manager_url -Headers $JsonHeader -Method Get -UseBasicParsing
        
            # Convert response_s_manager_url content to hash table
            $converted_s_manager_object = $response_s_manager_url.Content | ConvertFrom-Json
            $s_hash_table = @{}
            $converted_s_manager_object.psobject.properties | Foreach { $s_hash_table[$_.Name] = $_.Value }
            
            # Access /redfish/v1/Managers/1/NetworkProtocol
            if ($s_hash_table.keys -notcontains "NetworkProtocol")
            {
                continue
            }

            $network_protocol_url = "https://$ip"+$s_hash_table.NetworkProtocol.'@odata.id'

            # Get the network_protocol_url (/redfish/v1/Managers/1/NetworkProtocol) via Invoke-WebRequest
            $response_network_protocol_url = Invoke-WebRequest -Uri $network_protocol_url -Headers $JsonHeader -Method Get -UseBasicParsing
    
            # Convert response_network_protocol_url content to hash table
            $converted_network_protocol_object = $response_network_protocol_url.Content | ConvertFrom-Json
            $network_protocol_hash_table = @{}
            $converted_network_protocol_object.psobject.properties | Foreach { $network_protocol_hash_table[$_.Name] = $_.Value }
            
            # Access /redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/LDAPClient
            if ($network_protocol_hash_table.keys -notcontains "Oem")
            {
                continue
            }
            if ($null -ne $converted_network_protocol_object.Oem.'Lenovo')
            {
                if ($null -ne $converted_network_protocol_object.Oem.'Lenovo'.'LDAPClient')
                {
                    $ldap_client_uri = "https://$ip"+$network_protocol_hash_table.Oem.'Lenovo'.'LDAPClient'.'@odata.id'

                    # Build request body for set ldap server
                    $body = @{}
                    if ($null -eq $clientdn -or "" -eq $clientdn)
                    {
                        $binding_method = 'Anonymously'
                    }
                    else 
                    {
                        $binding_method = 'Configured'
                    }
                    $body["BindingMethod"] = @{}
                    $body["BindingMethod"]["ClientDN"] = $clientdn
                    $body["BindingMethod"]["ClientPassword"] = $clientpwd
                    $body["BindingMethod"]["Method"] = $binding_method
                    $body["RootDN"] = $rootdn
                    $body["GroupFilter"] = $group_filter
                    $body["GroupSearchAttribute"] = $group_search_attribute
                    $body["UIDSearchAttribute"] = $uid_search_attribute

                    $server_info = @{}
                    $server_info["Method"] = "Pre_Configured"
                    $serverlist, $portlist = parse_ldapserver($ldapserver)
                    foreach ($i in @(0..($serverlist.length-1)))
                    {
                        $server_info["Server"+ ($i+1) +"HostName_IPAddress"] = $serverlist[$i]
                        $server_info["Server"+ ($i+1) +"Port"] = $portlist[$i]
                    }
                    $body["LDAPServers"] = $server_info

                    # Patch the new LDAP setting
                    $request_body = $body
                    $json_body = $request_body | ConvertTo-Json -Depth 10
                    $response = Invoke-WebRequest -Uri $ldap_client_uri -Headers $JsonHeader -Method patch -Body $json_body -ContentType 'application/json'
                
                    [String]::Format("- PASS, statuscode {0} returned successfully to configured LDAP server.",$response.StatusCode)
                    return 
                }
            }
        }

        # No LDAP resource found
        return "LDAP is not supported"
    }
    catch
    {
        # Handle http exception response
        if($_.Exception.Response)
        {
            $_.Exception.Response 
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            if ($_.Exception.Response.StatusCode.Value__ -eq 401)
            {
                Write-Host "Error message: You are required to log on Web Server with valid credentials first."
            }
            elseif ($_.ErrorDetails.Message)
            {
                $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                Write-Host "Error message:" $response_j.Resolution
            }
        }
        # Handle system exception response
        elseif($_.Exception)
        {
            Write-Host "Error message:" $_.Exception.Message
            Write-Host "Please check arguments or server status."
        }
        return $False
    }
    # Delete existing session whether script exit successfully or not
    finally
    {
        if ($session_key -ne "")
        {
            delete_session -ip $ip -session $session
        }
    }
}
    
