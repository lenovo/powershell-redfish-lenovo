###
#
# Lenovo Redfish examples - Set Power State
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


function lenovo_set_power_state
{
   <#
   .Synopsis
    Cmdlet used to set power state
   .DESCRIPTION
    Cmdlet used to set power state using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id: Pass in System resource instance id(none: first instance, all: all instances)
    - reset_type: Pass in Power state reset type, such as: On, ForceOff, GracefulRestart, GracefulShutdown
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_set_power_state -ip 10.10.10.10 -username USERID -password PASSW0RD -reset_type ForceOff
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$system_id="None",
        [Parameter(Mandatory=$True, HelpMessage='Input the set power status("On, ForceOff, GracefulRestart, GracefulShutdown")')]
        [string]$reset_type="",
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
    if ($reset_type -eq "")
    {
        Write-Host "Please input power reset type."
        return $False
    }
    if ($system_id -eq "")
    {
        $system_id = [string]($ht_config_ini_info['SystemId'])
    }
    
    try
    {
        $session_key = ""
        $session_location = ""

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with sesison key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }
        
        # Get the system url collection
        $system_url_collection = @()
        $system_url_collection = get_system_urls -bmcip $ip -session $session -system_id $system_id


        # Loop all System resource instance in $system_url_collection
        foreach ($system_url_string in $system_url_collection)
        {
            
            # Get Powerstate from the System resource instance
            $uri_address_system = "https://$ip"+$system_url_string
            if (-not $uri_address_system.EndsWith("/"))
            {
                $uri_address_system = $uri_address_system + "/"
            }
            
            $response = Invoke-WebRequest -Uri $uri_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            
            # If server power is on, block Power on requests
            if($hash_table.PowerState -eq "On")
            {
                if($reset_type -eq "On")
                {
                    Write-Host "The Server Power is On, Invalid Power option."
                    return $False
                }
            }

            # If server power is off, block Power off and restart requests
            if($hash_table.PowerState -eq "Off")
            {
                if(($reset_type -eq "ForceOff") -or ($reset_type -eq "GracefulRestart") -or ($reset_type -eq "GracefulShutdown"))
                {
                    Write-Host "The Server Power is Off , Invalid Power option."
                    return $False
                }
            }

            $JsonBody = @{"ResetType" = $reset_type
                } | ConvertTo-Json -Compress
            
            $temp = $hash_table."Actions"."#ComputerSystem.Reset"."target"
            $uri_set_power_state = "https://$ip"+$temp

            #Set selected power option with post request
            try 
            {
                $response = Invoke-WebRequest -Uri $uri_set_power_state -Method Post -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
            }
            catch 
            {
                # Handle http exception response for Post request
                if ($_.Exception.Response)
                {
                    Write-Host "Error occured, status code:" $_.Exception.Response.StatusCode.Value__
                    if($_.ErrorDetails.Message)
                    {
                        $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                        $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                        Write-Host "Error message:" $response_j.Resolution
                    }
                    Write-Host
                    Write-Host "Supported power control values are:`n`n- On`n- ForceOff`n- GracefulRestart`n- GracefulShutdown"
                }
                # Handle system exception response for Post request
                elseif($_.Exception)
                {
                    Write-Host "Error message:" $_.Exception.Message
                    Write-Host "Please check arguments or server status."
                }
                return $False
            }

            Write-Host
            [String]::Format("- PASS, statuscode {0} returned to successfully set power state",$response.StatusCode)

            return $True

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