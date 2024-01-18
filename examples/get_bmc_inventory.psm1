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
        $bmc_details = @()
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
            
            # Get info from manager resource instance
            $hash_table= @{}
            $manager_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $BMC_Property = @('FirmwareVersion', 'Model', 'DateTime', 'DateTimeLocalOffset')
            foreach ($property in $BMC_Property) 
            {
                if($hash_table.keys -contains $property)
                {
                    $ht_bmc_info[$property] = $hash_table.$property
                }
            }

            # Get info from network_protocol resource instance
            $network_response = Invoke-WebRequest -Uri $network_protocol_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $network_converted_object = $network_response.Content | ConvertFrom-Json
            $hash_table= @{}
            $network_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $NetProtocol_Property = @('FQDN', 'HostName', 'HTTP', 'HTTPS', 'SSH', 'SNMP', 'KVMIP', 'IPMI', 'SSDP', 'VirtualMedia')
            foreach ($netproperty in $NetProtocol_Property) 
            {
                if($hash_table.keys -contains $netproperty)
                {
                    $ht_bmc_info[$netproperty] = $hash_table.$netproperty
                }
            }
            
            # Get info from serial resource instance
            $serial_response = Invoke-WebRequest -Uri $serial_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $serial_converted_object = $serial_response.Content | ConvertFrom-Json
            $serial_count = $serial_converted_object."Members@odata.count"
            
            # Loop all sub_serial resource instance in serial resource
            for($num =0;$num -lt $serial_count;$num++)
            {
                # Get sub serial resource
                $ht_serial = @{}
                $serial_x_url = "https://$ip" + $serial_converted_object.Members[$num]."@odata.id"
                $serial__x_response = Invoke-WebRequest -Uri $serial_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $serial_x_converted_object = $serial__x_response.Content | ConvertFrom-Json
                $hash_table= @{}
                $serial_x_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                $Serial_Property = @('Id', 'BitRate', 'Parity', 'StopBits', 'FlowControl')
                foreach ($property3 in $Serial_Property) 
                {
                    if($hash_table.keys -contains $property3)
                    {
                        $ht_serial[$property3] = $hash_table.$property3
                    }
                }
                $ht_bmc_info['serial_info'] += $ht_serial
            }
            $hash_table= @{}
            $manager_converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            if ($hash_table.Keys -contains "EthernetInterfaces")
            {
                $ethernet_url = "https://$ip" + $hash_table.EthernetInterfaces."@odata.id"
                $serial_response = Invoke-WebRequest -Uri $ethernet_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $serial_converted_object = $serial_response.Content | ConvertFrom-Json
                $serial_count = 0
                $serial_count = $serial_converted_object."Members@odata.count"
                $ethernet_info_list = @()
                for ($x = 0; $x -lt $serial_count; $x++) 
                {
                    $ethernet_info = @{}
                    $ethernet_x_url = $serial_converted_object.Members[$x]."@odata.id"
                    $response_ethernet_x_url = "https://$ip" + $ethernet_x_url
                    $serial_response = Invoke-WebRequest -Uri $response_ethernet_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $response_ethernet_x_data = $serial_response.Content | ConvertFrom-Json
                    $hash_table= @{}
                    $response_ethernet_x_data.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                    $properties = @('Id', 'Name', 'MACAddress', 'PermanentMACAddress', 'MTUSize', 'FQDN', 'AutoNeg', 'Status', 'InterfaceEnabled', 'SpeedMbps', 'NameServers', 'StaticNameServers', 'DHCPv4', 'DHCPv6', 'IPv4Addresses', 'IPv4StaticAddresses', 'IPv6Addresses', 'IPv6StaticAddresses')
                    foreach ($property in $properties) 
                    {
                        if($hash_table.Keys -contains $property)
                        {
                            $ethernet_info[$property] = $hash_table.$property
                        }
                    }
                    $ethernet_info_list += $ethernet_info
                }
                $ht_bmc_info['ethernet_info'] +=  $ethernet_info_list
            }

            # Output result
            $bmc_details = $ht_bmc_info
            $bmc_details | ConvertTo-Json -Depth 10
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