###
#
# Lenovo Redfish examples - Update BMC User Password
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


function update_bmc_user_password
{
   <#
   .Synopsis
    Cmdlet used to update BMC user password
   .DESCRIPTION
    Cmdlet used to update BMC user password using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - userid: Pass in BMC username to be updated
    - password_value: Pass in BMC user password to be updated
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    update_bmc_user_password -ip 10.10.10.10 -username USERID -password PASSW0RD -userid XXX -password_value XXX
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$userid="",
        [Parameter(Mandatory=$False)]
        [string]$password_value="",
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini"
        )
        
    # get configuration info from config file
    $ht_config_ini_info = read_config -config_file $config_file

    # if the parameter is not specified via command line, use the setting from configuration file
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
        # create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        #build headers with sesison key for authentication
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

        # check connrction
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        
        # convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $account_server_url_string = "https://$ip"+$hash_table.AccountService.'@odata.id'

        # get the accounts url via Invoke-WebRequest
        $response_account_server = Invoke-WebRequest -Uri $account_server_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # convert response_account_server content to hash table
        $converted_object = $response_account_server.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $accounts_url_string = "https://$ip"+$hash_table.Accounts.'@odata.id'

        # get the account url via Invoke-WebRequest
        $response_accounts_url = Invoke-WebRequest -Uri $accounts_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # convert response_accounts_url content to hash table
        $converted_object = $response_accounts_url.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        foreach ($i in $hash_table.Members)
        {
            $account_url = "https://$ip" + $i.'@odata.id'
            
            # Get account information if account is valid (UserName not blank)
            $response_account_x_url = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method Get -UseBasicParsing

            # convert response_account_x_url content to hash table
            $converted_object = $response_account_x_url.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            if($hash_table.UserName -eq $userid)
            {

                if($hash_table.'@odata.etag' -ne $null)
                {
                    $JsonHeader = @{ "If-Match" = $hash_table.'@odata.etag'
                    "X-Auth-Token" = $session_key
                    }

                    $JsonBody = @{ "Password" = $password_value
                        } | ConvertTo-Json -Compress
                }
                else
                {
                    $JsonHeader = @{ "If-Match" = ""
                    "X-Auth-Token" = $session_key
                        }

                    $JsonBody = @{ 
                        "UserName" = $userid
                        "Password" = $password_value
                        } | ConvertTo-Json -Compress
                }

                $response = Invoke-WebRequest -Uri $account_url -Method Patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'

                Write-Host
                [String]::Format("- PASS, statuscode {0} returned successfully to updated user password.",$response.StatusCode)

                return $True
            }
        }
    }
    catch
    {
        if($_.Exception.Response)
        {
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            if ($_.Exception.Response.StatusCode.Value__ -eq 401)
            {
                Write-Host "Error message: You are required to log on Web Server with valid credentials first."
            }
            if ($_.ErrorDetails.Message)
            {
                $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                Write-Host "Error message:" $response_j.Resolution
            }
        } 
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
    