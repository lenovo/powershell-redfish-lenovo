###
#
# Lenovo Redfish examples - Get storage inventory
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
###get
Import-module $PSScriptRoot\lenovo_utils.psm1

function get_storage_inventory
{
    <#
   .Synopsis
    Cmdlet used to Get storage inventory
   .DESCRIPTION
    Cmdlet used to Get storage inventory from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id: Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_storage_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD
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
            # Hash table of boot mode information 
            $reset_types = @{}

            # Get system resource
            $url_address_system = "https://$ip"+$system_url_string
            $response = Invoke-WebRequest -Uri $url_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            # Get the storage url from the computer system resource
            if($hash_table.keys -contains "Storage")
            {
                $uri_storage = "https://$ip" + $converted_object.Storage.'@odata.id'
            }
            else
            {
                $uri_storage = "https://$ip" + $converted_object.SimpleStorage.'@odata.id'
            }

            # Get the storage information form the storage resource
            $response = Invoke-WebRequest -Uri $uri_storage -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            foreach($storage_url in $converted_object.Members)
            {
                $storage_x_url = "https://$ip" + $storage_url.'@odata.id'
                $response = Invoke-WebRequest -Uri $storage_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            
                # Build a empty hashtable store storage information
                $storage_info = @{}
                $storage_info["Storage_id"] = $hash_table.Id
                $storage_info["Name"] = $hash_table.Name
                $storage_list = @()
                
                # Get the storage controllers instances resources from each of the storage resources
                foreach($controller in $hash_table.StorageControllers)
                {
                    $hash_table1 = @{}
                    $controller.psobject.properties | Foreach { $hash_table1[$_.Name] = $_.Value }
                    foreach($key in $hash_table1.Keys)
                        {
                            $storage_controller = @{}
                            if('@odata.id', 'Links' -notcontains $key)
                            {
                                $storage_controller[$key] = $controller.$key
                            }
                        }
                    $storage_list += $storage_controller 
                }

                # Get the disk inventory from each of the disk resources
                $drive_list = @()
                if($hash_table.keys -contains "Drives")
                {
                    foreach($disk in $hash_table.Drives)
                    {
                        $hash_table2 = @{}
                        $controller.psobject.properties | Foreach { $hash_table2[$_.Name] = $_.Value }
                        $disk_inventory = @{}
                        $disk_url = "https://$ip" + $hash_table2.'@odata.id'
                        $response = Invoke-WebRequest -Uri $disk_url -Headers $JsonHeader -Method Get -UseBasicParsing
                        $converted_object = $response.Content | ConvertFrom-Json
                        $hash_table3 = @{}
                        $converted_object.psobject.properties | Foreach { $hash_table3[$_.Name] = $_.Value }
                        foreach($key in $hash_table3.Keys)
                        {
                            if('Description','@odata.context','@odata.id','@odata.type','@odata.etag', 'Links' -notcontains $key)
                            {
                                $disk_inventory[$key] = $hash_table3.$key
                            }
                        }
                        $drive_list += $disk_inventory
                    }
                    $storage_info["Drives"] = $drive_list
                }
                
                $storage_info["StorageControllers"] = $storage_list              
                $storage_info
                Write-Host
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