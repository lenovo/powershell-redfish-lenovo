###
#
# Lenovo Redfish examples - Get BMC information
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

function get_bmc_inventory
{
    <#
   .Synopsis
    Cmdlet used to Get BMC inventory
   .DESCRIPTION
    Cmdlet used to Get BMC inventory from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_bmc_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD 
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
        # $session_location = ""

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        # $session_location = $session.Location

        # Build headers with sesison key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }
        
        # Get the system url collection
        $system_url_collection = @()
        $system_url_collection = get_system_urls -bmcip $ip -session $session -system_id $system_id

        # Loop all System resource instance in $system_url_collection
        foreach($system_url_string in $system_url_collection)
        {
            # Hash table of bmc info 
            $ht_bmc_info = @{}

            # Get system resource
            $url_address_system = "https://$ip"+$system_url_string
            $response = Invoke-WebRequest -Uri $url_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            # Get manager resource
            $manager_url = "https://$ip" + $converted_object.Links.ManagedBy."@odata.id"
            $manager_response =   Invoke-WebRequest -Uri $manager_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $manager_converted_object = $manager_response.Content | ConvertFrom-Json

            # Get url string
            $network_protocol_url  ="https://$ip" + $manager_converted_object.NetworkProtocol."@odata.id"
            $serial_url = "https://$ip" + $manager_converted_object.SerialInterfaces."@odata.id"
            $ethernet_url = "https://$ip" + $manager_converted_object.EthernetInterfaces."@odata.id"
            
            # Get info from manager resource instance
            $ht_bmc_info["FirmwareVersion"] = $manager_converted_object.FirmwareVersion
            $ht_bmc_info["Model"] = $manager_converted_object.Model
            $ht_bmc_info["DateTime"] = $manager_converted_object.DateTime
            $ht_bmc_info["DateTimeLocalOffset"] = $manager_converted_object.DateTimeLocalOffset

            # Get info from network_protocol resource instance
            $network_response = Invoke-WebRequest -Uri $network_protocol_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $network_converted_object = $network_response.Content | ConvertFrom-Json

            $ht_tmp = @{}
            $network_converted_object.psobject. properties | Foreach{ $ht_tmp[$_.Name] = $_.Value }
            foreach($key in $ht_tmp.Keys)
            {
                if($key -notin 'FQDN', 'HostName', 'HTTP', 'HTTPS', 'SSH', 'SNMP', 'KVMIP','IPMI', 'SSDP', 'VirtualMedia')
                {
                    continue
                }
                $ht_bmc_info[$key] = $ht_tmp[$key]
            }
            
            # Get info from serial resource instance
            $serial_response = Invoke-WebRequest -Uri $serial_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $serial_converted_object = $serial_response.Content | ConvertFrom-Json
            $serial_count = $serial_converted_object."Members@odata.count"
            $list_serial = @()
            
            # Loop all sub_serial resource instance in serial resource
            for($num =0;$num -lt $serial_count;$num++)
            {
                # Get sub serial resource
                $ht_serial = @{}
                $serial_x_url = "https://$ip" + $serial_converted_object.Members[$num]."@odata.id"
                $serial__x_response = Invoke-WebRequest -Uri $serial_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $serial_x_converted_object = $serial__x_response.Content | ConvertFrom-Json

                $ht_tmp = @{}
                $serial_x_converted_object.psobject. properties | Foreach{ $ht_tmp[$_.Name] = $_.Value }
                $ht_serial["Id"] = $ht_tmp["Id"]
                $ht_serial["BitRate"] = $ht_tmp["BitRate"]
                $ht_serial["Parity"] = $ht_tmp["Parity"]
                $ht_serial["StopBits"] = $ht_tmp["StopBits"]
                $ht_serial["FlowControl"] = $ht_tmp["FlowControl"]

                $list_serial += $ht_serial
            }

            # Output result
            $ht_bmc_info["serial_info"] = $list_serial

            # Get info from ethernet resource instance
            $ethernet_response = Invoke-WebRequest -Uri $ethernet_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $ethernet_converted_object = $ethernet_response.Content | ConvertFrom-Json
            $ethernet_count = $ethernet_converted_object."Members@odata.count"
            $list_ethernet = @()
            
            # Loop all sub_ethernet resource instance in ethernet resource
            for($num =0;$num -lt $ethernet_count;$num++)
            {
                # Get sub ethernet resource
                $ht_ethernet = @{}
                $ethernet_x_url = "https://$ip" + $ethernet_converted_object.Members[$num]."@odata.id"
                $ethernet__x_response = Invoke-WebRequest -Uri $ethernet_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $ethernet_x_converted_object = $ethernet__x_response.Content | ConvertFrom-Json

                $ht_tmp = @{}
                $ethernet_x_converted_object.psobject. properties | Foreach{ $ht_tmp[$_.Name] = $_.Value }
                foreach($key in $ht_tmp.Keys)
                {
                    if($key -in 'Id', 'Name', 'MACAddress', 'PermanentMACAddress', 'MTUSize', 'FQDN','AutoNeg', 'Status', 'InterfaceEnabled', 'SpeedMbps', 'NameServers', 'StaticNameServers','DHCPv4', 'DHCPv6', 'IPv4Addresses', 'IPv4StaticAddresses', 'IPv6Addresses', 'IPv6StaticAddresses')
                    {
                        $ht_ethernet[$key] = $ht_tmp[$key]
                    }
                }

                $list_ethernet += $ht_ethernet
            }

            # Output result
            $ht_bmc_info["ethernet_info"] = $list_ethernet

            ConvertOutputHashTableToObject $ht_bmc_info | ConvertTo-Json
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
