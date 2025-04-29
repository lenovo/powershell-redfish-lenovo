###
#
# Lenovo Redfish examples - Get the CPU information
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

function lenovo_get_cpu_inventory
{
    <#
   .Synopsis
    Cmdlet used to Get lenovo cpu inventory
   .DESCRIPTION
    Cmdlet used to Get cpu inventory from BMC using Redfish API. cpu info will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - system_id:Pass in Cpu member id
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_cpu_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        [string]$member_id="None",
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
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
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

            # Get processors resource
            $processors_url = "https://$ip" + $converted_object.Processors."@odata.id"      
            $processors_response =   Invoke-WebRequest -Uri $processors_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $processors_converted_object = $processors_response.Content | ConvertFrom-Json

            # Get cpu count
            $cpu_count = $processors_converted_object."Members@odata.count"
            if ($member_id -ne "None") 
            {
                if(($member_id -le 0) -or ($member_id -gt $cpu_count))
                {
                    
                    Write-Host "Invalid CPU member id, Please check arguments or server status."
                }
            }
            # Loop all cpu resource instance in processor resource
            for($i = 0;$i -lt $cpu_count ;$i++)
            {
                if(($member_id -ne "None") -and ($i -ne ($member_id - 1)))
                {
                    continue
                }
                # Get cpu resource
                $cpu_url = "https://$ip" + $processors_converted_object.Members[$i]."@odata.id"
                $cpu_response =   Invoke-WebRequest -Uri $cpu_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $cpu_converted_object = $cpu_response.Content | ConvertFrom-Json
                $ht_cpu_info = @{}
                $ht_cpu_info["Id"] = $cpu_converted_object.Id
                $ht_cpu_info["Name"] = $cpu_converted_object.Name
                $ht_cpu_info["TotalThreads"] = $cpu_converted_object.TotalThreads
                $ht_cpu_info["InstructionSet"] = $cpu_converted_object.InstructionSet
                $ht_cpu_info["Status"] = $cpu_converted_object.Status
                $ht_cpu_info["ProcessorType"] = $cpu_converted_object.ProcessorType
                $ht_cpu_info["TotalCores"] = $cpu_converted_object.TotalCores
                $ht_cpu_info["Manufacturer"] = $cpu_converted_object.Manufacturer
                $ht_cpu_info["MaxSpeedMHz"] = $cpu_converted_object.MaxSpeedMHz
                $ht_cpu_info["Model"] = $cpu_converted_object.Model
                $ht_cpu_info["Socket"] = $cpu_converted_object.Socket
                
                if ($null -ne $cpu_converted_object.Oem.Lenovo.CacheInfo)
                {
                    $ht_cpu_info["CacheInfo"] = $cpu_converted_object.Oem.Lenovo.CacheInfo
                }
                if ($null -ne $cpu_converted_object.Oem.Lenovo.CurrentClockSpeedMHz)
                {
                    $ht_cpu_info["CurrentClockSpeedMHz"] = $cpu_converted_object.Oem.Lenovo.CurrentClockSpeedMHz
                }
                # Return result
                ConvertOutputHashTableToObject $ht_cpu_info | ConvertTo-Json
                Write-Host " "
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