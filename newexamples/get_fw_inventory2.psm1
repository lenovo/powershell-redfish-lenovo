###
#
# Lenovo Redfish examples - Get firmware inventory
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


function get_fw_inventory
{
   <#
   .Synopsis
    Cmdlet used to get firmware inventory
   .DESCRIPTION
    Cmdlet used to get firmware inventory from BMC using Redfish API. Get result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_fw_inventory -ip 10.10.10.10 -username USERID -password PASSW0RD -config_file config.ini
   #>
   
    param(
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
        
        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        $JsonHeader = @{ "X-Auth-Token" = $session_key}
    
        # Get the update server url via Invoke-WebRequest
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        
        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $update_service_url_string = "https://$ip" + $hash_table.UpdateService.'@odata.id'

        # Get the firmware inventory url via Invoke-WebRequest
        $response_update_service = Invoke-WebRequest -Uri $update_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
       
        # Convert $response_update_service content to hash table
        $converted_object = $response_update_service.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $firmware_inventory_url_string = "https://$ip"+$hash_table.FirmwareInventory.'@odata.id'

        # Get the firmware_x_url via Invoke-WebRequest
        $response_firmware_inventory_url = Invoke-WebRequest -Uri $firmware_inventory_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
       
        # Convert $response_firmware_inventory_url content to hash table
        $converted_object = $response_firmware_inventory_url.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        foreach ($i in $hash_table.Members)
        {
            $firmware_x_url = "https://$ip" + $i.'@odata.id'
            # Get account information if account is valid (UserName not blank)
            $response_firmware_x_url = Invoke-WebRequest -Uri $firmware_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
            # Convert response_firmware_x_url content to hash table
            $converted_object = $response_firmware_x_url.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            # Create an null hash table for firmware inventory return
            $fw = @{}
            $fw["Name"] = $hash_table.Name
            $fw["Version"] = $hash_table.Version
            $fw["Description"] = $hash_table.Description
            if($hash_table.Keys -contains "SoftwareId")
            {
                $fw["SoftwareId"] = $hash_table.SoftwareId
            }
            if($hash_table.Keys -contains "Status")
            {
                $fw["State"] = $hash_table.Status
            }


            $firmware = @{}
            $fw_name = $firmware_x_url -split "/"
            $firmware[$fw_name[7]] = $fw
            # Output result
            ConvertOutputHashTableToObject $firmware | ConvertTo-Json -Depth 5
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