###
#
# Lenovo Redfish examples - Get chassis indicator led
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


function get_chassis_indicator_led
{
    <#
   .Synopsis
    Cmdlet used to get chassis indicator led status
   .DESCRIPTION
    Cmdlet used to get chassis indicator led status from BMC using Redfish API. Get result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_chassis_indicator_led -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        
        $chassis_url_list = get_chassis_urls $ip $session
        foreach($response_led_url in $chassis_url_list)
        {
            $response_IndicatorLED = Invoke-WebRequest -Uri $response_led_url -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object_IndicatorLED = $response_IndicatorLED.Content | ConvertFrom-Json
            $ht_IndicatorLED = @{}
            $converted_object_IndicatorLED.psobject.properties | Foreach { $ht_IndicatorLED[$_.Name] = $_.Value }
            if($chassis_url_collection.Length -gt 1 -and $ht_IndicatorLED.keys -notcontains 'IndicatorLED')
            {
                continue
            }
            $ht2 = @{}
            $ht_IndicatorLED."Links".psobject.properties | Foreach { $ht2[$_.Name] = $_.Value }
            if($ht2.keys -contains "ComputerSystems")
            {
                $indicator_status = @{}
                $IndicatorLED = $ht_IndicatorLED."IndicatorLED"
                $indicator_status["IndicatorLED"] = $IndicatorLED

                # Output result
                $indicator_status | ConvertTo-Json -Depth 10
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
