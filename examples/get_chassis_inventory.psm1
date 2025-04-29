###
#
# Lenovo Redfish examples - Get chassis inventory
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

function get_chassis_inventory
{
    <#
   .Synopsis
    Cmdlet used to get chassis inventory 
   .DESCRIPTION
    Cmdlet used to get chassis inventory from BMC using Redfish API. Inventory will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_chassis_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD 
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

        $chassis_details = @{}
        # Get ComputerBase resource
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json

        # Get response_base_url
        $chassis_url = "https://$ip" + $converted_object.Chassis.'@odata.id'

        # Get response chassis url resource
        $response = Invoke-WebRequest -Uri $chassis_url -Header $JsonHeader -Method Get -UseBasicParsing
        $chassis_converted_object = $response.Content | ConvertFrom-Json

         # Get the chassis information
        for ($i = 0; $i -lt $chassis_converted_object.'Members@odata.count'; $i++) 
        {
            $chassis_one_url =  "https://$ip" + $chassis_converted_object.Members[$i].'@odata.id'
            $response_chassis = Invoke-WebRequest -Uri $chassis_one_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_chassis_object = $response_chassis.Content | ConvertFrom-Json
            $ht_chassis_members = @{}
            $converted_chassis_object.psobject.properties | Foreach { $ht_chassis_members[$_.Name] = $_.Value }

            if ($chassis_converted_object.'Members@odata.count' -gt 1 -and ($ht_chassis_members.Keys -notcontains 'Links' -or  $ht_chassis_members.Keys -notcontains 'Location')) 
            {
                continue
            }
            $chassis_inventory = $ht_chassis_members

            # Delete content with only url property
            foreach($property in ("Links", "@odata.etag", "@odata.id", "@odata.type", "LogServices",
            "Memory", "NetworkAdapters", "PCIeDevices", "PCIepythonSlots", "Power", "Thermal",
            "Controls", "EnvironmentMetrics", "PowerSubsystem", "Sensors", "ThermalSubsystem"))
            {
                if($chassis_inventory.Keys -contains $property) 
                {
                    $chassis_inventory.Remove($property)
                }   
            }     
            if ($chassis_inventory.Keys -contains "Oem") 
            {
                $hash_table = @{}
                $chassis_inventory.Oem.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

                $hash_table_oem= @{}
                $hash_table.Lenovo.psobject.properties | Foreach { $hash_table_oem[$_.Name] = $_.Value }
                if ($hash_table.Keys -contains "Lenovo")
                {
                    foreach($property in ("LEDs", "Sensors", "Slots", "@odata.type"))
                    {
                        if ($hash_table_oem.Keys -contains $property) 
                        {
                            $hash_table_oem.Remove($property)
                        }
                        $chassis_inventory.Oem.Lenovo =  $hash_table_oem
                    }
                }
            }
            $chassis_details += $chassis_inventory
            ConvertOutputHashTableToObject $chassis_details | ConvertTo-Json -Depth 5 
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