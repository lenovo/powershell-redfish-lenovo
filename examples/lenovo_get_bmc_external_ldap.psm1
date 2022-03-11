###
#
# Lenovo Redfish examples - get manager external account provider LDAP information
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

function lenovo_get_bmc_external_ldap
{
   <#
   .Synopsis
    Cmdlet used to get bmc external LDAP information
   .DESCRIPTION
    Cmdlet used to get get bmc external LDAP information from BMC using Redfish API. BMC external LDAP info will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_get_bmc_external_ldap -ip 10.10.10.10 -username USERID -password PASSW0RD
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
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
        $account_service_url_string = "https://$ip"+$base_hash_table.AccountService.'@odata.id'

        # Get the AccountService url via Invoke-WebRequest
        $response_account_service = Invoke-WebRequest -Uri $account_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_service content to hash table
        $converted_account_service_object = $response_account_service.Content | ConvertFrom-Json
        
        $ldap_client_info = @{}

        # Use standard API for LDAP in AccountService first
        $properties = @('LDAPService', 'ServiceEnabled', 'ServiceAddresses', 'Authentication')
        if ($null -ne $converted_account_service_object.LDAP)
        {
            foreach($item_name in $properties)
            {
                $ldap_client_info[$item_name] = $converted_account_service_object.LDAP.$item_name
            }
           
            $ldap_client_info | ConvertTo-Json -Depth 10
            return
        }

        # Use Oem API /redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/LDAPClient if standard API not present 
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

                    # Get the ldap_client_uri via Invoke-WebRequest
                    $response_ldap_client_uri = Invoke-WebRequest -Uri $ldap_client_uri -Headers $JsonHeader -Method Get -UseBasicParsing
            
                    # Convert response_ldap_client_uri content to hash table
                    $converted_ldap_client_object = $response_ldap_client_uri.Content | ConvertFrom-Json
                    $ldap_client_hash_table = @{}
                    $converted_ldap_client_object.psobject.properties | Foreach { $ldap_client_hash_table[$_.Name] = $_.Value }
            
                    $Authentication = @{}
                    $Authentication["AuthenticationType"] = 'UsernameAndPassword'
                    $ldap_client_info["Authentication"] = $Authentication

                    $SearchSettings = @{}

                    if ($ldap_client_hash_table.keys -contains "RootDN")
                    {
                        $SearchSettings["BaseDistinguishedNames"] = @()
                        $SearchSettings["BaseDistinguishedNames"] += $converted_ldap_client_object.RootDN
                    }
                    if ($ldap_client_hash_table.keys -contains "GroupSearchAttribute")
                    {
                        $SearchSettings["GroupNameAttribute"] = $converted_ldap_client_object.GroupSearchAttribute
                    }
                    if ($ldap_client_hash_table.keys -contains "GroupFilter")
                    {
                        $SearchSettings["GroupsAttribute"] = $converted_ldap_client_object.GroupFilter
                    }
                    if ($ldap_client_hash_table.keys -contains "UIDSearchAttribute")
                    {
                        $SearchSettings["UsernameAttribute"] = $converted_ldap_client_object.UIDSearchAttribute
                    }
                    if ($ldap_client_hash_table.keys -contains "ProtocolEnabled")
                    {
                        $ldap_client_info["ServiceEnabled"] = $converted_ldap_client_object.ProtocolEnabled
                    }

                    $LDAPService = @{}
                    $LDAPService["SearchSettings"] =$SearchSettings
                    $ldap_client_info["LDAPService"] = $LDAPService

                    if ($ldap_client_hash_table.keys -contains "LDAPServers")
                    {
                        $servers = @('Server1', 'Server2', 'Server3', 'Server4')
                        $ServiceAddresses = @()
                        foreach($s_server in $servers)
                        {
                            $server_hostname_ipaddr = $s_server + 'HostName_IPAddress'
                            $server_port = $s_server + 'Port'
                            if ($null -ne $converted_ldap_client_object.LDAPServers.$server_hostname_ipaddr)
                            {
                                $serviceaddr = $converted_ldap_client_object.LDAPServers.$server_hostname_ipaddr + ":" + $converted_ldap_client_object.LDAPServers.$server_port
                            }
                            else 
                            {
                                $serviceaddr = ":" + $converted_ldap_client_object.LDAPServers.$server_port
                            }
                            $ServiceAddresses += $serviceaddr
                        }
                        $ldap_client_info['ServiceAddresses'] = $ServiceAddresses
                    }

                    $ldap_client_info | ConvertTo-Json -Depth 10

                    return
                }
            }
        }

        return "LDAP is not supported"
    }
    catch
    {
        # Handle http exception response
        if($_.Exception.Response)
        {
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
    
