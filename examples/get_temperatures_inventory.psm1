###
#
# Lenovo Redfish examples - Get temperatures inventory
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

function get_temperatures_inventory
{
    <#
   .Synopsis
    Cmdlet used to Get temperatures inventory
   .DESCRIPTION
    Cmdlet used to Get temperatures inventory from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_temperatures_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD 
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
        $chassis_url_list = get_chassis_urls $ip $session
        foreach($chassis_url_string in $chassis_url_list)
        {
            #get chassis resource
            $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $ht_links = @{}
            $converted_object.psobject.properties | Foreach { $ht_links[$_.Name] = $_.Value }

            #Get thermal_url resource
            $thermalsubsystem_url = "https://$ip" + $converted_object.ThermalSubsystem."@odata.id"
            $response = Invoke-WebRequest -Uri $thermalsubsystem_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            #get temperatures info
            $thermalmetrics_url = "https://$ip" + $converted_object.ThermalMetrics."@odata.id"
            $thermalmetrics_response = Invoke-WebRequest -Uri $thermalmetrics_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $thermalmetrics_converted_object = $thermalmetrics_response.Content | ConvertFrom-Json

            foreach($temperaturereadingscelsius_url in $thermalmetrics_converted_object.TemperatureReadingsCelsius)
            {
                $temperaturereadingscelsius_x_url = "https://$ip" + $temperaturereadingscelsius_url.DataSourceUri
                $temperaturereadingscelsius_x_response = Invoke-WebRequest -Uri $temperaturereadingscelsius_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $temperaturereadingscelsius_x_converted_object = $temperaturereadingscelsius_x_response.Content | ConvertFrom-Json
                $hash_table = @{}
                $temperaturereadingscelsius_x_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                $ht_temperatures_info = @{}
                foreach($key in $hash_table.Keys)
                {
                    if($key -in "Description", "@odata.context", "@odata.id", "@odata.type","@odata.etag", "Links", "Actions", "RelatedItem")
                    {
                        continue
                    }
                    $ht_temperatures_info[$key] = $hash_table[$key]
                }
                # Output result
                $ht_temperatures_info | ConvertTo-Json -Depth 5
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