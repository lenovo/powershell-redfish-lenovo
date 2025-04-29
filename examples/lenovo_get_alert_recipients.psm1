###
#
# Lenovo Redfish examples - Get alert recipients (Email/Syslog Recipients)
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
###get
Import-module $PSScriptRoot\lenovo_utils.psm1

function lenovo_get_alert_recipients
{
    <#
   .Synopsis
    Cmdlet used to Get alert recipients
   .DESCRIPTION
    Cmdlet used to Get alert recipients from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_get_alert_recipients -ip 10.10.10.10 -username USERID -password PASSW0RD 
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

        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }
    
        # Get the manager url collection
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        # Get Managers collection resource
        $managers_url = $converted_object.Managers."@odata.id"
        $response_managers_url = "https://$ip" + $managers_url
        $response = Invoke-WebRequest -Uri $response_managers_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        # Get Manager resource
        $manager_url = $hash_table.Members[0].'@odata.id'
        $response_manager_url = "https://$ip" + $manager_url
        $response = Invoke-WebRequest -Uri $response_manager_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        $hash_table_oem = @{}
        $hash_table.Oem.psobject.properties | Foreach { $hash_table_oem[$_.Name] = $_.Value }

        $hash_table_lenovo = @{}
        $hash_table_oem.Lenovo.psobject.properties | Foreach { $hash_table_lenovo[$_.Name] = $_.Value }

        # Get bmc recipients url
        if($hash_table.Keys -contains 'Oem' -and $hash_table_oem.keys -contains 'Lenovo' -and $hash_table_lenovo.keys -contains 'Recipients')
        {
            $recipients_url = $hash_table_lenovo.Recipients.'@odata.id'
        }
        else 
        {
            Write-Host 'No support alert recipient.'
            return
        }
        
        # Get alert recipients
        $response_recipients = "https://$ip" + $recipients_url
        $response = Invoke-WebRequest -Uri $response_recipients -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $response_recipients_url = @{}
        $converted_object.psobject.properties | Foreach { $response_recipients_url[$_.Name] = $_.Value }
        if ($response_recipients_url.'Members@odata.count' -eq 0)
        {
            Write-Host 'No recipients exist.'
            return
        }
        $all_recipients = @()
        $items_excluded = @('@odata.type', '@odata.id', '@odata.etag')
        foreach ($member in $response_recipients_url.Members)
        {
            $recipient_url = $member.'@odata.id'
            $response_recipient = "https://$ip" + $recipient_url
            $recipient_response = Invoke-WebRequest -Uri $response_recipient -Headers $JsonHeader -Method Get -UseBasicParsing
            $recipient_converted_object = $recipient_response.Content | ConvertFrom-Json
            $response_recipient_url = @{}   
            $recipient_converted_object.psobject.properties | Foreach { $response_recipient_url[$_.Name] = $_.Value }
            $recipient_dict = @{}
            foreach ($key in $response_recipient_url.keys)
            {
                if ($items_excluded -notcontains $key)
                {
                    $recipient_dict[$key] = $response_recipient_url.$key
                }
            }
            $all_recipients += $recipient_dict
        }
        # Output result
        $all_recipients | ConvertTo-Json
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