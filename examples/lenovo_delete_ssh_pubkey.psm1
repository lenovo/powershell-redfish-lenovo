###
#
# Lenovo Redfish examples - Delete SSH Pubkey
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


Import-module $PSScriptRoot\lenovo_utils.psm1


function lenovo_delete_ssh_pubkey
{
    <#
   .Synopsis
    Cmdlet used to delete ssh pubkey
   .DESCRIPTION
    Cmdlet used to delete ssh pubkey from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - user_name: Pass in the pubkey user name to delete
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_delete_ssh_pubkey -ip 10.10.10.10 -username USERID -password PASSW0RD -user_name NAME
    
   #>

   param
    (
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$user_name="",
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
    if ($user_name -eq "")
    {
        $user_name = $username
    }
    try {
        $session_key = ""
        $session_location = ""

        # Create session 
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with session key for authentication
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

        # Get ServiceBase resource
        $response_base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $response_base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json


        $account_service_url = $converted_object.AccountService.'@odata.id'
        $response_account_service_url = "https://$ip"+ $account_service_url
        $response = Invoke-WebRequest -Uri $response_account_service_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        $accounts_url = $hash_table.Accounts.'@odata.id'
        $accounts_url_response = "https://$ip"+ $accounts_url
        $response = Invoke-WebRequest -Uri $accounts_url_response -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        # Get all BMC user account
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        # Loop through Accounts and print info
        foreach ($account_dict in $hash_table.Members)
        {
            $account_url = "https://$ip"+ $account_dict."@odata.id"
            $response_account = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response_account.Content | ConvertFrom-Json
            $account_url_response = @{}
            $converted_object.psobject.properties | Foreach { $account_url_response[$_.Name] = $_.Value }
            if ($user_name -eq $account_url_response['UserName'])
            {
                try
                {
                    $account_url_response_Oem = @{}
                    $account_url_response.Oem.psobject.properties | Foreach { $account_url_response_Oem[$_.Name] = $_.Value }

                    $account_url_response_Lenovo = @{}
                    $account_url_response_Oem.Lenovo.psobject.properties | Foreach { $account_url_response_Lenovo[$_.Name] = $_.Value }
                    $temp = $account_url_response_Lenovo['SSHPublicKey']
                }
                catch
                {
                    Write-Host 'Not support resource Oem.Lenovo.SSHPublicKey in Account'
                    return
                }
                if($account_url_response.keys -contains '@odata.etag')
                {
                    $etag = $account_url_response.'@odata.etag'
                }
                else
                {
                    $etag = ""
                }                
                $JsonHeader = @{"X-Auth-Token" = $session_key; "If-Match" = $etag}
                $sshkey = @{'SSHPublicKey'= @($null, $null, $null, $null)}
                $lenovo = @{'Lenovo' = $sshkey}
                $body = @{'Oem' = $lenovo}
                $JsonBody = $body | ConvertTo-Json -Depth 10 
                $response = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method Patch  -Body $JsonBody -ContentType 'application/json'
                if ($response.StatusCode -eq 200)
                {
                    Write-Host 'Delete ssh public key successfully'
                    return $True
                }
                else
                {
                    [String]::Format("Url '{0}' response Error code ",$account_url)
                    return $False
                }    
            }
            else
            {
                continue
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