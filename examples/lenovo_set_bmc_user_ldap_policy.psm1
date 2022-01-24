###
#
# Lenovo Redfish examples - Set BMC authentication policy (LocalOnly, LDAPOnly, LocalFirstThenLDAP, or LDAPFirstThenLocal)
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

function lenovo_set_bmc_user_ldap_policy
{
   <#
   .Synopsis
    Cmdlet used to set authentication policy
   .DESCRIPTION
    Cmdlet used to set authentication policy from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - policy: Specify how the user attempt to login should be authenticated(LocalOnly, LDAPOnly, LocalFirstThenLDAP, or LDAPFirstThenLocal)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_set_bmc_user_ldap_policy -ip 10.10.10.10 -username USERID -password PASSW0RD -policy LocalOnly
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$policy="",
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

        # Check whether the policy value is valid
        $policy_list = ("LocalOnly", "LDAPOnly", "LocalFirstThenLDAP", "LDAPFirstThenLocal")
        if ($policy_list -notcontains $policy)
        {
            return "Invalid. The value of policy must be in LocalOnly/LDAPOnly/LocalFirstThenLDAP/LDAPFirstThenLocal"
        }

        # Get the base url via Invoke-WebRequest
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert base response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $base_hash_table = @{}
        $converted_object.psobject.properties | ForEach { $base_hash_table[$_.Name] = $_.Value }

        # Get the AccountService url via Invoke-WebRequest
        $account_service_url = "https://$ip"+$base_hash_table.AccountService.'@odata.id'
        $response_account_service = Invoke-WebRequest -Uri $account_service_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_service content to hash table
        $converted_account_service_object = $response_account_service.Content | ConvertFrom-Json
        $account_service_hash_table = @{}
        $converted_account_service_object.psobject.properties | Foreach { $account_service_hash_table[$_.Name] = $_.Value }

        $request_body = $null

        # Use standard property LocalAccountAuth first
        if ($account_service_hash_table.keys -contains "LocalAccountAuth")
        {
            $current_value = $converted_account_service_object.LocalAccountAuth
            $mapdict = @{}
            $mapdict['LocalOnly'] = "Enabled"
            $mapdict['LDAPOnly'] = "Disabled"
            $mapdict['LDAPFirstThenLocal'] = "Fallback"
            $mapdict['LocalFirstThenLDAP'] = "LocalFirst"

            if ($mapdict[$policy] -eq $current_value)
            {
                return "Current policy is already " + $policy + ", no need to set"
            }
            # Create request body
            $request_body = @{}
            $request_body["LocalAccountAuth"] = $mapdict[$policy]
        }

        # Use Oem property AuthenticationMethod instead if standard not existing
        if ($account_service_hash_table.keys -contains "Oem")
        {
            if ($null -ne $account_service_hash_table.Oem."Lenovo")
            {
                if ($null -ne $account_service_hash_table.Oem.'Lenovo'.'AuthenticationMethod')
                {
                    $current_value = $converted_account_service_object.Oem.'Lenovo'.'AuthenticationMethod'         
                    if ($policy -eq $current_value)
                    {
                        return "Current policy is already " + $policy + ", no need to set"
                    }
                    # Create request body
                    $request_body = @{}
                    $request_body["Oem"] = @{}
                    $request_body["Oem"]["Lenovo"] = @{}
                    $request_body["Oem"]["Lenovo"]["AuthenticationMethod"] = $policy
                }
            }
        }

        # No related resource found
        if ($null -eq $request_body)
        {
            # For ThinkSystem SR635/SR655
            if ($account_service_hash_table.keys -contains "Oem")
            {
                if ($null -ne $account_service_hash_table.Oem."Ami")
                {
                    return "Both local user and ldap can be supported. But policy setting is not supported."
                }
            }

            return "Only local user is supported."
        }
        
        # Send patch to change the allowable login policy
        $json_body = $request_body | ConvertTo-Json
        $response = Invoke-WebRequest -Uri $account_service_url -Headers $JsonHeader -Method patch -Body $json_body -ContentType 'application/json'
    
        [String]::Format("- PASS, statuscode {0} returned successfully set logon policy to {1}", $response.StatusCode, $policy)
        return 
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
    
