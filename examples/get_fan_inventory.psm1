﻿###
#
# Lenovo Redfish examples - Get fan inventory
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

function get_fan_inventory
{
    <#
   .Synopsis
    Cmdlet used to Get fan inventory
   .DESCRIPTION
    Cmdlet used to Get fan inventory from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_fan_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD 
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

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }
        
        # Get the chassis url
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $chassis_url = $converted_object.Chassis."@odata.id"

        #Get chassis list 
        $chassis_url_collection = @()
        $chassis_url_string = "https://$ip"+ $chassis_url
        $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        foreach($i in $converted_object.Members)
        {
            $tmp_chassis_url_string = "https://$ip" + $i."@odata.id"
            $chassis_url_collection += $tmp_chassis_url_string
            
            $response_links = Invoke-WebRequest -Uri $tmp_chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object_links = $response_links.Content | ConvertFrom-Json
            $links_response = @{}
            $converted_object_links.psobject.properties | Foreach { $links_response[$_.Name] = $_.Value }
            if($chassis_url_collection.Length -gt 1 -and $links_response.keys -notcontains 'Links')
            {
                continue
            }
            else
            {
                $computersystems_response = @{}
                $links_response.Links.psobject.properties | Foreach { $computersystems_response[$_.Name] = $_.Value }
                if($computersystems_response.keys -notcontains 'ComputerSystems')
                {
                    continue
                }
            }
            $response = Invoke-WebRequest -Uri $tmp_chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            $links_info = $converted_object.Links
            $ht_links = @{}
            $links_info.psobject.properties | Foreach { $ht_links[$_.Name] = $_.Value }
            if($ht_links.Keys -notcontains "ComputerSystems")
            {
                continue
            }  

            #Get thermal_url resource
            $thermal_url = "https://$ip" + $converted_object.Thermal."@odata.id"
            $response = Invoke-WebRequest -Uri $thermal_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            #get Fans info
            $list_fans_info = $converted_object.Fans
            foreach($fans_info in $list_fans_info)
            {
                $hash_table = @{}
                $fans_info.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                $ht_fans_info = @{}
                foreach($key in $hash_table.Keys)
                {
                    if($key -eq "RelatedItem" -or $key -eq "@odata.type" -or $key -eq "@odata.id" -or $key -eq "Oem")
                    {
                        continue
                    }
                    $ht_fans_info[$key] = $hash_table[$key]
                }
                # Output result
                $ht_fans_info | ConvertTo-Json -Depth 10
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