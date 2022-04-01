###
#
# Lenovo Redfish examples - Delete alert recipient specified (Email/Syslog Recipients)
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

function lenovo_del_alert_recipient
{
    <#
   .Synopsis
    Cmdlet used to delete alert recipient
   .DESCRIPTION
    Cmdlet used to delete alert recipient from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - index_id: Pass in the account index id to delete
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_del_alert_recipient -ip 10.10.10.10 -username USERID -password PASSW0RD -index_id 1
   #>

   param
    (
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$index_id="",
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
    try {
        $session_key = ""
        $session_location = ""

        # Create session 
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key }

        # Get ServiceBase resource
        $response_base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $response_base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        # Get Managers collection resource
        $managers_url = $converted_object.Managers.'@odata.id'
        $managers_url_string = "https://$ip"+ $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        # Get Manager resource
        $manager_url = $hash_table.Members[0].'@odata.id'
        $response_manager_url = "https://$ip" + $manager_url
        $response = Invoke-WebRequest -Uri $response_manager_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $Oem_hash_table = @{}
        $converted_object.psobject.properties | Foreach { $Oem_hash_table[$_.Name] = $_.Value }

        $lenovo_hash_table = @{}
        $Oem_hash_table.Oem.psobject.properties | Foreach { $lenovo_hash_table[$_.Name] = $_.Value }
        
        $recipients_hash_table = @{}
        $lenovo_hash_table.Lenovo.psobject.properties | Foreach { $recipients_hash_table[$_.Name] = $_.Value }
        
        # Get bmc recipients url
        if($Oem_hash_table.Keys -contains 'Oem' -and $lenovo_hash_table.keys -contains 'Lenovo' -and $recipients_hash_table.keys -contains 'Recipients')
        {
            $recipients_url = $recipients_hash_table.Recipients.'@odata.id'
        }
        else 
        {
            Write-Host 'No support alert recipient.'
            return
        }

        # Get alert recipients
        $response_recipients_url = "https://$ip" + $recipients_url
        $response = Invoke-WebRequest -Uri $response_recipients_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        if($hash_table.'Members@odata.count' -eq 0)
        {
            Write-Host 'No recipients exist.'
        }

        # Find url of the recipient specified
        $recipient_url = ''
        foreach($member in $hash_table.Members)
        {            
            $members = $member.'@odata.id'
            $members_split = $members -Split"/"
            $url_account = "https://$ip" + $members
            if($index_id -eq  $members_split[-1])
            {
                $recipient_url = $url_account
                break
            }
        }

        if($recipient_url -eq '')
        {
            Write-Host 'The recipient specified does not exist.'
            return
        }
        $JsonHeader = @{"X-Auth-Token" = $session_key; "Content-Type"= "application/json"}
        $response = Invoke-WebRequest -Uri $recipient_url -Headers $JsonHeader -Method Delete -UseBasicParsing
        [String]::Format("Delete alert recipient with Id {0} successfully.",$index_id)
        return $True

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