###
#
# Lenovo Redfish examples - Get Sessions
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

function get_sessions
{
    <#
   .Synopsis
    Cmdlet used to Get sessions
   .DESCRIPTION
    Cmdlet used to Get sessions from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_sessions -ip 10.10.10.10 -username USERID -password PASSW0RD 
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

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key }

        # Get session service url
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $session_service_url = $converted_object.SessionService."@odata.id"

        #Get session url        
        $session_service_url_string = "https://$ip"+ $session_service_url
        $response = Invoke-WebRequest -Uri $session_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $sessions_url = $converted_object.Sessions."@odata.id"

        $sessions_url_string = "https://$ip"+ $sessions_url
        $response = Invoke-WebRequest -Uri $sessions_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        
        $session_url_collection = @()
        foreach($i in $converted_object.Members)
        { 
            $tmp_session_url_string = "https://$ip" + $i."@odata.id"
            $session_url_collection += $tmp_session_url_string
        }
        
        # Loop all session resource instance in $session_url_collection
        foreach($session_url_string in $session_url_collection)
        {
            #get session resource
            $response = Invoke-WebRequest -Uri $session_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            $hash_sessions = @{}
            $ht_sessions = @{}
            $converted_object.psobject.properties | Foreach { $hash_sessions[$_.Name] = $_.Value }
            foreach($key in $hash_sessions.Keys)
            {
                if("Name","UserName","Description","Id" -contains $key)
                {
                    $ht_sessions[$key] = $hash_sessions[$key]
                }               
            }
            # Output result
            ConvertOutputHashTableToObject $ht_sessions         
            
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