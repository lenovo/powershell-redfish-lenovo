###
#
# Lenovo Redfish examples - disable security LDAP to use certificate
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
###get
Import-module $PSScriptRoot\lenovo_utils.psm1

function lenovo_ldap_certificate_disable
{
    <#
   .Synopsis
    Cmdlet used to disable LDAP certificate
   .DESCRIPTION
    Cmdlet used to disable LDAP certificate from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - binddn: Specify DN for binding LDAP server with a DN and password. If DN is not specified, try to bind anonymous. Only ThinkSystem SR635/SR655 need to specify binddn/bindpassword.
    - bindpassword: Specify password for binding LDAP server with a DN and password. Only ThinkSystem SR635/SR655 need to specify binddn/bindpassword.
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_ldap_certificate_disable -ip 10.10.10.10 -username USERID -password PASSW0RD
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$binddn="",
        [Parameter(Mandatory=$False)]
        [array]$bindpassword="",
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
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

        # Get the base url via Invoke-WebRequest
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert base response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $base_hash_table = @{}
        $converted_object.psobject.properties | ForEach { $base_hash_table[$_.Name] = $_.Value }

        # Use Oem API /redfish/v1/Managers/1/Oem/Lenovo/Security
        $managers_url = "https://$ip"+$base_hash_table.Managers.'@odata.id'

        # Get the managers url(/redfish/v1/Managers) via Invoke-WebRequest
        $response_managers_url = Invoke-WebRequest -Uri $managers_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_managers_url content to hash table
        $converted_managers_object = $response_managers_url.Content | ConvertFrom-Json
        $managers_hash_table = @{}
        $converted_managers_object.psobject.properties | Foreach { $managers_hash_table[$_.Name] = $_.Value }

        foreach ($i in $managers_hash_table.Members)
        {
            # Access /redfish/v1/Managers/1
            $s_manager_url = "https://$ip" + $i.'@odata.id'

            # Get the single manager url(/redfish/v1/Managers/1) via Invoke-WebRequest
            $response_s_manager_url = Invoke-WebRequest -Uri $s_manager_url -Headers $JsonHeader -Method Get -UseBasicParsing

            # Convert response_s_manager_url content to hash table
            $converted_s_manager_object = $response_s_manager_url.Content | ConvertFrom-Json
            $s_hash_table = @{}
            $converted_s_manager_object.psobject.properties | Foreach { $s_hash_table[$_.Name] = $_.Value }

            # Check /redfish/v1/Managers/1/Oem/Lenovo/Security existing
            if ($s_hash_table.keys -notcontains "Oem")
            {
                continue
            }
            if ($null -eq $converted_s_manager_object.Oem.'Lenovo')
            {
                continue
            }
            if ($null -eq $converted_s_manager_object.Oem.'Lenovo'.'Security')
            {
                continue
            }
            if ($null -eq $converted_s_manager_object.Oem.'Lenovo'.'Security'.'@odata.id')
            {
                continue
            }

            # Access /redfish/v1/Managers/1/Oem/Lenovo/Security to confirm current setting
            $security_url = "https://$ip"+$s_hash_table.Oem.'Lenovo'.'Security'.'@odata.id'

            # Get the security_url via Invoke-WebRequest
            $response_security_url = Invoke-WebRequest -Uri $security_url -Headers $JsonHeader -Method Get -UseBasicParsing
    
            # Convert response_security_url content to hash table
            $converted_security_object = $response_security_url.Content | ConvertFrom-Json
            $security_hash_table = @{}
            $converted_security_object.psobject.properties | Foreach { $security_hash_table[$_.Name] = $_.Value }

            $enable_ldap = $False
            if ($null -ne $converted_security_object.SSLSettings)
            {
                if ($null -ne $converted_security_object.SSLSettings.'EnableLDAPS')
                {
                    $enable_ldap = $converted_security_object.SSLSettings.'EnableLDAPS'
                }
            }
            if ($enable_ldap -eq $False)
            {
                return "LDAP certificate security is already disabled."
            }

            # Create request body
            $Body = @{}
            $Body['SSLSettings'] = @{}
            $Body['SSLSettings']['EnableLDAPS'] = $False
            $json_body = $Body | ConvertTo-Json

            # Perform patch to disable LDAP SSL
            $response = Invoke-WebRequest -Uri $security_url -Headers $JsonHeader -Method patch -Body $json_body -ContentType 'application/json'
         
            [String]::Format("- PASS, statuscode {0} returned successfully to set ldap certificate disable.",$response.StatusCode)
            return 
        }

        # Disable LDAP for SR635/SR655
        $account_service_url = "https://$ip"+$base_hash_table.AccountService.'@odata.id'

        # Get the AccountService url via Invoke-WebRequest
        $response_account_service = Invoke-WebRequest -Uri $account_service_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_service content to hash table
        $converted_account_service_object = $response_account_service.Content | ConvertFrom-Json
        $account_service_hash_table = @{}
        $converted_account_service_object.psobject.properties | Foreach { $account_service_hash_table[$_.Name] = $_.Value }

        # Access /redfish/v1/AccountService/LDAP/Authentication/Oem/Ami/EncryptionType to confirm current setting
        if ($account_service_hash_table.keys -contains "LDAP")
        {
            if ($null -ne $account_service_hash_table.LDAP.'Authentication')
            {
                if ($null -ne $account_service_hash_table.LDAP.'Authentication'.'Oem')
                {
                    if ($null -ne $account_service_hash_table.LDAP.'Authentication'.'Oem'.'Ami')
                    {        
                        if ($null -ne $account_service_hash_table.LDAP.'Authentication'.'Oem'.'Ami'.'EncryptionType')
                        {
                            $encryption_type = $converted_account_service_object.LDAP.'Authentication'.'Oem'.'Ami'.'EncryptionType'
                            if ($encryption_type -eq 'NoEncryption')
                            {
                                return "LDAP certificate security is already disabled."
                            }
                            elseif ($encryption_type -eq 'SSL' -or $encryption_type -eq 'StartTLS')
                            {
                                if ($null -eq $binddn -or $null -eq $bindpassword)
                                {
                                    return "Parameter binddn and bindpassword are needed for disabling LDAP certificate security.."
                                }

                                # Create request body
                                $ldap_body = @{}
                                $ldap_body['LDAP'] = @{}
                                $ldap_body['LDAP']['Authentication'] = @{}
                                $ldap_body['LDAP']['Authentication']['Username'] = $binddn
                                $ldap_body['LDAP']['Authentication']['Password'] = $bindpassword
                                $ldap_body['LDAP']['Authentication']['Oem'] = @{}
                                $ldap_body['LDAP']['Authentication']['Oem']['Ami'] = @{}
                                $ldap_body['LDAP']['Authentication']['Oem']['Ami']['EncryptionType'] = "NoEncryption"
                                $ldap_body['LDAP']['Authentication']['Oem']['Ami']['CommonNameType'] = "IPAddress"

                                # Perform patch to disable LDAP SSL
                                $json_body = $ldap_body | ConvertTo-Json
                                $response = Invoke-WebRequest -Uri $account_service_url -Headers $JsonHeader -Method patch -Body $json_body -ContentType 'application/json'
                            
                                [String]::Format("- PASS, statuscode {0} returned successfully to set ldap certificate disable.",$response.StatusCode)
                                return 
                            }
                        }
                    }
                }
            }
        }
        
        # No LDAP certificate resource found
        return 'LDAP certificate is not supported'
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
            else
            {
                Write-Host "Error message:" $_.Exception.Message
                Write-Host "Please check arguments or server status."        
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