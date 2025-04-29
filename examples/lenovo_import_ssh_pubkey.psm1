###
#
# Lenovo Redfish examples - Import SSH Pubkey
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

function lenovo_import_ssh_pubkey
{
    <#
   .Synopsis
    Cmdlet used to import ssh pubkey
   .DESCRIPTION
    Cmdlet used to import ssh pubkey from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - user_name: The user name you want to import. If not specified, login username will be used
    - sshpubkey: Ssh pubkey you want to set
    - sshpubkeyfile: File which contain ssh pubkey you want to set
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_import_ssh_pubkey -ip 10.10.10.10 -username USERID -password PASSW0RD -sshpubkey PUBKEY(-sshpubkeyfile PUBKEY PATH) -user_name NAME
    
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
        [Parameter(ParameterSetName='sshpubkey', Mandatory=$True)]
        [string]$sshpubkey,
        [Parameter(ParameterSetName='sshpubkeyfile', Mandatory=$True)]
        [string]$sshpubkeyfile,
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
    $pb_command = @{}
    if($sshpubkey)
    {
        $pb_command['sshpubkey'] = $sshpubkey
    }
    else
    {
        $pb_command["sshpubkeyfile"] = $sshpubkeyfile
    }
    $sshpubkey = ""
    foreach ($key in $pb_command.keys)
    {
        if($key -eq "sshpubkey")
        {
            $sshpubkey = $pb_command[$key]
        }
        else
        {
            try
            {
                $file = Get-Content $pb_command[$key]
                $sshpubkey = $file.Split("`n")[0]
            }
            catch
            {
                [String]::Format("Open file:{0} fail,please check your input",$pb_command[$key])
                return $False
            }
        }
    }
    if ($user_name -eq "")
    {
        $user_name = $username
    }
    try
    {
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
        
        # Get all BMC user account
        $accounts_url = $converted_object.Accounts.'@odata.id'
        $accounts_url_response = "https://$ip"+ $accounts_url
        $response = Invoke-WebRequest -Uri $accounts_url_response -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
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
                # Check existing SSH public keys, add new key to pubkeys collection
                try
                {
                    $account_url_response_Oem = @{}
                    $account_url_response.Oem.psobject.properties | Foreach { $account_url_response_Oem[$_.Name] = $_.Value }

                    $account_url_response_Lenovo = @{}
                    $account_url_response_Oem.Lenovo.psobject.properties | Foreach { $account_url_response_Lenovo[$_.Name] = $_.Value }

                    $pubkeys = $account_url_response_Lenovo['SSHPublicKey']
                }
                catch
                {
                    Write-Host 'Not support resource Oem.Lenovo.SSHPublicKey in Account'
                    return $False
                }
                if ($pubkeys -contains $sshpubkey)
                {
                    Write-Host 'The ssh public key has already imported'
                    return $True
                }
                foreach($index in 1..$pubkeys.Length)
                {
                    if ($pubkeys[$index] -eq "" -or $pubkeys[$index] -eq $null)
                    {
                        $pubkeys[$index] = $sshpubkey
                        break
                    }
                }
                if ($pubkeys -notcontains $sshpubkey)
                {
                    Write-Host 'The ssh public key for this user is full, only 4 keys are allowed'
                    return $True
                }
                # Perform patch to import the SSH public key
                if ($account_url_response.keys -contains '@odata.etag')
                {
                    $etag = $account_url_response['@odata.etag']
                }
                else 
                {
                    $etag = ""    
                }
                $JsonHeader = @{"X-Auth-Token" = $session_key; "If-Match"= $etag}
                $sshkey = @{'SSHPublicKey'= $pubkeys}
                $lenovo = @{'Lenovo' = $sshkey}
                $body = @{'Oem' = $lenovo}
                $JsonBody = $body | ConvertTo-Json -Depth 10
                $response = Invoke-WebRequest -Uri $account_url -Method patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
                if ($response.StatusCode -eq 200)
                {
                    Write-Host 'Import ssh public key successfully'
                    return $True
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