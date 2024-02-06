###
#
# Lenovo Redfish examples - Get the current BMC user accounts
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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

function lenovo_get_bmc_user_accounts
{
   <#
   .Synopsis
    Cmdlet used to get bmc user accounts
   .DESCRIPTION
    Cmdlet used to get bmc user accounts from BMC using Redfish API. BMC user info will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_get_bmc_user_accounts -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        $session_location = ""

        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location
        $JsonHeader = @{"X-Auth-Token" = $session_key}

        # Get the account server url via Invoke-WebRequest
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $account_server_url_string = "https://$ip"+$hash_table.AccountService.'@odata.id'

        # Get the accounts url via Invoke-WebRequest
        $response_account_server = Invoke-WebRequest -Uri $account_server_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_server content to hash table
        $converted_object = $response_account_server.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $accounts_url_string = "https://$ip"+$hash_table.Accounts.'@odata.id'

        # Get the account url via Invoke-WebRequest
        $response_accounts_url = Invoke-WebRequest -Uri $accounts_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_accounts_url content to hash table
        $converted_object = $response_accounts_url.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        # Create an null array for result return
        $bmc_user_collection = @()
        foreach ($i in $hash_table.Members)
        {
            $account_url = "https://$ip" + $i.'@odata.id'
            
            # Get account information if account is valid (UserName not blank)
            $response_account_x_url = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method Get -UseBasicParsing
            # Convert response_account_x_url content to hash table
            $converted_object = $response_account_x_url.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $bmc_user = @{}
            if ($converted_object.UserName -ne '')
            {
                $bmc_user['Id'] = $converted_object.Id
                $bmc_user['UserName'] = $converted_object.UserName
                $bmc_user['Enabled'] = $converted_object.Enabled
                $bmc_user['Locked'] = $converted_object.Locked
                $bmc_user['AccountTypes'] = $converted_object.AccountTypes
                $bmc_user['SNMP'] = $converted_object.SNMP
                $bmc_user['RoleId'] = $converted_object.RoleId
                if($hash_table.Keys -contains "Links")
                {
                    $accounts_role_url ="https://$ip" + $hash_table.Links.'Role'.'@odata.id'
                    $response_accounts_role_url = Invoke-WebRequest -Uri $accounts_role_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response_accounts_role_url.Content | ConvertFrom-Json
                    $bmc_user['AssignedPrivileges'] = $converted_object.AssignedPrivileges
                    $bmc_user['OemPrivileges'] = $converted_object.OemPrivileges
                }
                # Output result
                ConvertOutputHashTableToObject $bmc_user | ConvertTo-Json -Depth 5   
            }
        }
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
