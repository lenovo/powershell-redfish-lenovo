﻿###
#
# Lenovo Redfish examples - Get the power metrics information
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

function get_power_metrics
{
    <#
   .Synopsis
    Cmdlet used to get power metrics
   .DESCRIPTION
    Cmdlet used to get power metrics from BMC using Redfish API. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_pci_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        }

        # Loop all System resource instance in $chassis_url_collection
        foreach($chassis_url_string in $chassis_url_collection)
        {
            # Get system resource
            $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            if ($hash_table.Keys -notcontains "Power")
            {
                continue   
            }
            # Get Power resource 
            $power_url = "https://$ip" + $converted_object.Power."@odata.id"
            $response = Invoke-WebRequest -Uri $power_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_power_object = $response.Content | ConvertFrom-Json
            # Get PowerControl count
            $powercontrol_x_count =$converted_power_object."PowerControl@odata.count"
            # Loop all pci resource instance in EthernetInterfaces resource
            for($i = 0;$i -lt $powercontrol_x_count;$i ++)
            {
                $ht_powercontrol = @{}
                $ht_powercontrol["MemberId"] = $converted_power_object.PowerControl[$i]."MemberId"
                $ht_powercontrol["Name"] = $converted_power_object.PowerControl[$i]."Name"
                $ht_powercontrol["PowerMetrics"] = $converted_power_object.PowerControl[$i]."PowerMetrics"

                # Retrun result
                ConvertOutputHashTableToObject $ht_powercontrol | ConvertTo-Json
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
                $sr = new-object System.IO.StreamReader $_.Exception.Response.GetResponseStream()
                $resobject = $sr.ReadToEnd() | ConvertFrom-Json
                $resobject.error.('@Message.ExtendedInfo')    
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
