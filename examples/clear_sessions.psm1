###
#
# Lenovo Redfish examples - Clear sessions
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

function clear_sessions
{
    <#
   .Synopsis
    Cmdlet used to clear sessions
   .DESCRIPTION
    Cmdlet used to clear sessions from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - session_name: Pass in the username to clear
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    clear_sessions -ip 10.10.10.10 -username USERID -password PASSW0RD -session_name username
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
        [string]$session_name="",
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

    try{
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

        # Get session service
        $session_service_url = $converted_object.SessionService.'@odata.id'
        $managers_url_string = "https://$ip"+ $session_service_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $response_session_service_url = @{}
        $converted_object.psobject.properties | Foreach { $response_session_service_url[$_.Name] = $_.Value }

        $sessions_url = $response_session_service_url.Sessions.'@odata.id'
        $managers_url_string = "https://$ip"+ $sessions_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $response_sessions_url = @{}
        $converted_object.psobject.properties | Foreach { $response_sessions_url[$_.Name] = $_.Value }

        $session_username = $False
        foreach($single_session in $response_sessions_url["Members"])
        {
            $single_session_url = $single_session.'@odata.id'
            $response_single = "https://$ip"+ $single_session_url
            if($session_name -ne $null -and $session_name.length -ne 0)
            {
                $response_clear = Invoke-WebRequest -Uri $response_single -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object_sessions = $response_clear.Content | ConvertFrom-Json
                $response_single_session = @{}
                $converted_object_sessions.psobject.properties | Foreach { $response_single_session[$_.Name] = $_.Value }
                if($response_single_session.keys -contains 'UserName')
                {
                    if($session_name -eq $response_single_session.'UserName')
                    {
                        $session_username = $True
                        $response_clear_session = Invoke-WebRequest -Uri $response_single -Headers $JsonHeader -Method Delete -UseBasicParsing
                    }
                }
            }
            else 
            {
                $session_username = $True
                $response_clear_session = Invoke-WebRequest -Uri $response_single -Headers $JsonHeader -Method Delete -UseBasicParsing
            }
        }
        if ($session_username -eq $False)
        {
            [String]::Format("Session {0} not exist.",$session_name)
        }
        else 
        {
            Write-Host 'Clear sessions successfully.'
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
        # Delete existing session when script exit exceptly
        if ($session_key -ne "")
        {
            delete_session -ip $ip -session $session
        }
        return $False
    }
}