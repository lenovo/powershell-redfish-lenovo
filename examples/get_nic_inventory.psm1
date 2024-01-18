###
#
# Lenovo Redfish examples - Get the network information
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

function get_nic_inventory
{
    <#
   .Synopsis
    Cmdlet used to get nic inventory
   .DESCRIPTION
    Cmdlet used to get nic inventory from BMC using Redfish API. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_nic_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        $nic_details = @()
        foreach($chassis_url_string in $chassis_url_collection)
        {
            # GET the Chassis resource
            $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            if(-not $hash_table -or $hash_table.Keys -notcontains 'NetworkAdapters')
            {
                continue
            }
            # GET the NetworkAdapters resource from the Chassis resource
            $nic_adapter_url = "https://$ip" + $converted_object.NetworkAdapters."@odata.id"
            $response = Invoke-WebRequest -Uri $nic_adapter_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_nic_object = $response.Content | ConvertFrom-Json
            $nic_count =$converted_nic_object."Members@odata.count"
            for($i = 0;$i -lt $nic_count;$i ++)
            {
                $network = @{}
                $nic_adapter_x_url = "https://$ip" +  $converted_nic_object.Members[$i]."@odata.id"
                $response_nic_x_device = Invoke-WebRequest -Uri $nic_adapter_x_url -Headers $JsonHeader -Method Get -UseBasicParsing 
                $converted_nic_x_object = $response_nic_x_device.Content | ConvertFrom-Json
                $response_members_url = @{}
                $converted_nic_x_object.psobject.properties | Foreach { $response_members_url[$_.Name] = $_.Value }
                $properties = @('Id', 'Name', 'Status', 'Manufacturer', 'Model', 'PartNumber', 'SKU', 'SerialNumber')

                foreach ($property in $properties) 
                {
                    if($response_members_url.Keys -contains $property)
                    {
                        $network[$property] = $converted_nic_x_object.$property
                    }
                }
                if($response_members_url.Keys -notcontains 'Controllers')
                {
                    continue
                }
                
                # get Controller info including NetworkDeviceFunctions and assigned port in Controller
                # $response_members_url | ConvertTo-Json -Depth 10
                $controller_list = @()
                foreach ($controller in $response_members_url.Controllers)
                {
                    $respomse = @{}
                    $controller.psobject.properties | Foreach { $respomse[$_.Name] = $_.Value }
                    $devices_nic = @()
                    $controller_data = @{}
                    $propertys = @('FirmwarePackageVersion', 'ControllerCapabilities')
                    foreach($property in $propertys)
                    {
                        if($respomse.Keys -contains $property)
                        {
                            $controller_data[$property] = $converted_nic_x_object.$property
                        }
                    }
                    # get the NetworkDeviceFunction resources
                    # $response_controllers = @{}
                    # $response_members_url.Controllers.psobject.properties | Foreach { $response_controllers[$_.Name] = $_.Value }
    
                    
                    $respomse_links = @{}
                    $controller.Links.psobject.properties | Foreach { $respomse_links[$_.Name] = $_.Value }
                    # Write-Host $respomse.Keys
                    if(($respomse.Keys -notcontains 'Links') -or ($respomse_links.Keys -notcontains 'NetworkDeviceFunctions'))
                    {
                        continue
                    }
                    
                    foreach($devfun in $respomse_links.NetworkDeviceFunctions)
                    {
                        $respomse_network = @{}
                        $devfun.psobject.properties | Foreach { $respomse_network[$_.Name] = $_.Value }
                        $NIC_Devices = @{}
                        $nic_dev_x_url = "https://$ip" + $respomse_network.'@odata.id'
                        $response_nic_dev_x_url = Invoke-WebRequest -Uri $nic_dev_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                        $converted_nic_x_dev = $response_nic_dev_x_url.Content | ConvertFrom-Json
                        $respomse_network = @{}
                        $converted_nic_x_dev.psobject.properties | Foreach { $respomse_network[$_.Name] = $_.Value }
                        $propertys = @('Id', 'Name', 'NetDevFuncType', 'DeviceEnabled', 'Ethernet', 'Status')
                        foreach($property in $propertys)
                        {
                            if($respomse_network.Keys -contains $property)
                            {
                                $NIC_Devices[$property] = $converted_nic_x_dev.$property
                            }
                        }
                        # GET the associated NetworkPort resource
                        if($respomse_network.Keys -contains "PhysicalPortAssignment")
                        {
                            $nic_port_x_url = "https://$ip" + $converted_nic_x_dev.PhysicalPortAssignment."@odata.id"
                            $response_nic = Invoke-WebRequest -Uri $nic_port_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                            $converted_port_nic_x = $response_nic.Content | ConvertFrom-Json
                            $respomse_network = @{}
                            $converted_port_nic_x.psobject.properties | Foreach { $respomse_network[$_.Name] = $_.Value }
                            $Physical_Ports = @{}
                            $propertys = @('PhysicalPortNumber', 'Name', 'ActiveLinkTechnology', 'PortMaximumMTU', 'Status', 'LinkStatus')
                            foreach($property in $propertys)
                            {
                                if ($respomse_network.Keys -contains $property)
                                {
                                    $Physical_Ports[$property] = $converted_port_nic_x.$property
                                }
                            }
                            $NIC_Devices['physical_port'] = $Physical_Ports

                        }
                        $devices_nic += $NIC_Devices
                    }
                    $controller_data['NetworkDeviceFunctions'] = $devices_nic
                    $controller_list += $controller_data
                }
                $network['Controllers'] = $controller_list
                $nic_details += $network
            }
        }
        
        if($nic_details.Length -eq 0)
        {
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

                # Get EthernetInterfaces resource 
                $nic_adapter_url = "https://$ip" + $converted_object.EthernetInterfaces."@odata.id"
                $response = Invoke-WebRequest -Uri $nic_adapter_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_nic_object = $response.Content | ConvertFrom-Json

                # Get nic count
                $nic_x_count =$converted_nic_object."Members@odata.count"

                # Loop all nic resource instance in EthernetInterfaces resource
                for($i = 0;$i -lt $nic_x_count;$i ++)
                {
                    $ht_network = @{}

                    # Get nic resource
                    $nic_adapter_x_url ="https://$ip" +  $converted_nic_object.Members[$i]."@odata.id"
                    $response_nic_x_adapter = Invoke-WebRequest -Uri $nic_adapter_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_nic_x_object = $response_nic_x_adapter.Content | ConvertFrom-Json
                    $respomse_nic_object = @{}
                    $converted_nic_x_object.psobject.properties | Foreach { $respomse_nic_object[$_.Name] = $_.Value }
                    $propertys = @('Id', 'Name', 'MACAddress', 'MTUSize', 'FQDN', 'AutoNeg', 'Status')
                    foreach($property in $propertys)
                    {
                        if($respomse_nic_object.Keys -contains $property)
                        {
                            $ht_network[$property] = $converted_nic_x_object.$property
                        }
                    }
                    $nic_details += $ht_network
                    continue
                    # Output result
                }
            }  
        }
        $nic_details | ConvertTo-Json -Depth 10

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
