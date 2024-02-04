###
#
# Lenovo Redfish examples - Get the PSU information
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

function get_psu_inventory
{
    <#
   .Synopsis
    Cmdlet used to get power supply unit inventory
   .DESCRIPTION
    Cmdlet used to get power supply unit inventory from BMC using Redfish API.information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_psu_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD
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

        # Build headers with sesison key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }
        
        # Get the system url collection
        $system_url_collection = @()
        $system_url_collection = get_system_urls -bmcip $ip -session $session -system_id $system_id

        # Loop all System resource instance in $system_url_collection
        foreach($system_url_string in $system_url_collection)
        {
            # Get system resource
            $url_address_system = "https://$ip"+$system_url_string
            $response = Invoke-WebRequest -Uri $url_address_system -Headers $JsonHeader -Method Get -UseBasicParsing    
            $converted_object = $response.Content | ConvertFrom-Json
            
            # Get chassis resource 
            $chassis_url = "https://$ip" + $converted_object.Links.Chassis."@odata.id"  
            $chassis_response =   Invoke-WebRequest -Uri $chassis_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $chassis_converted_object = $chassis_response.Content | ConvertFrom-Json

            if ($chassis_converted_object.psobject.Properties.name -match "PowerSubsystem"){
                # Get powersubsystem resource 
                $powersubsystem_url = "https://$ip" + $chassis_converted_object.PowerSubsystem."@odata.id"
                $powersubsystem_response =   Invoke-WebRequest -Uri $powersubsystem_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $powersubsystem_converted_object = $powersubsystem_response.Content | ConvertFrom-Json
                
                # Get powersubsystem supply resource 
                $powersubsystemsupply_url = "https://$ip" + $powersubsystem_converted_object.PowerSupplies."@odata.id"
                $powersubsystemsupply_response =   Invoke-WebRequest -Uri $powersubsystemsupply_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $powersubsystemsupply_converted_object = $powersubsystemsupply_response.Content | ConvertFrom-Json

                $hash_table = @{}
                $powersubsystemsupply_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                #get powersubsystem supply info
                foreach ($i in $hash_table.Members)
                {
                    $powersubsystemsupply_x_url = "https://$ip" + $i."@odata.id"
                    $powersubsystemsupply__x_response = Invoke-WebRequest -Uri $powersubsystemsupply_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $powersubsystemsupply_x_converted_object = $powersubsystemsupply__x_response.Content | ConvertFrom-Json

                    $hash_table = @{}
                    $powersubsystemsupply_x_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                    $ht_powersubsystemsupply_info = @{}
                    foreach($key in $hash_table.Keys)
                    {
                        if($key -notin "@odata.id", "@odata.context", "@odata.type", "@odata.etag")
                        {
                            $ht_powersubsystemsupply_info[$key] = $hash_table[$key]
                        }
                    }

                    $metrics_url = "https://$ip" + $powersubsystemsupply_x_converted_object.Metrics."@odata.id"
                    $metrics_response = Invoke-WebRequest -Uri $metrics_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $metrics_converted_object = $metrics_response.Content | ConvertFrom-Json

                    $hash_tmp = @{}
                    $metrics_converted_object.psobject.properties | Foreach { $hash_tmp[$_.Name] = $_.Value }
                    $ht_metrics_info = @{}
                    foreach($key in $hash_tmp.Keys)
                    {
                        if($key -notin "@odata.id", "@odata.context", "@odata.type", "@odata.etag")
                        {
                            $ht_metrics_info[$key] = $hash_tmp[$key]
                        }
                    }
                    $ht_powersubsystemsupply_info["Metrics"] = $ht_metrics_info

                    # Output result
                    ConvertOutputHashTableToObject $ht_powersubsystemsupply_info                
                }
            }
            

            # Get power resource 
            $power_url = "https://$ip" + $chassis_converted_object.Power."@odata.id"
            $power_response =   Invoke-WebRequest -Uri $power_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $power_converted_object = $power_response.Content | ConvertFrom-Json
            # Get power supply list from power resource
            $power_supply_list = $power_converted_object.PowerSupplies

            # Loop power supply resource in power supply list
            foreach($power_supply in $power_supply_list)
            {
                # Get power supply info
                $ht_power_supply = @{}
                $ht_power_supply["Name"] = $power_supply.Name
                $ht_power_supply["SerialNumber"] = $power_supply.SerialNumber
                $ht_power_supply["PartNumber"] = $power_supply.PartNumber
                $ht_power_supply["FirmwareVersion"] = $power_supply.FirmwareVersion
                $ht_power_supply["PowerCapacityWatts"] = $power_supply.PowerCapacityWatts
                $ht_power_supply["PowerSupplyType"] = $power_supply.PowerSupplyType
                $ht_power_supply["State"] = $power_supply.Status.State
                $ht_power_supply["Health"] = $power_supply.Status.Health
                $ht_power_supply["Manufacturer"] = $power_supply.Manufacturer
                
                # Output result
                ConvertOutputHashTableToObject $ht_power_supply
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
