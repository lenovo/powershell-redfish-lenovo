###
#
# Lenovo Redfish examples - Set bios bootmode legacy
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


function set_bios_bootmode_legacy
{
    <#
    .Synopsis
     Cmdlet user to set bios bootmode legacy
    .DESCRIPTION
     Cmdlet used to set bios bootmode legacy form BMC using Redfish API. Set result will be printed to the screen.
     Connection information can be specified via command parameter of configuration file
     - ip: Pass in BMC IP address
     - username: Pass in BMC username
     - password: Pass in BMC username password
     - system_id: Pass in System resource instance id(None: first instance, all: all instances)
     - config_file: Pass in configuration file path, default configuration file is config.ini
    .EXAMPLE
     set_bios_bootmode_legacy -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        $system_id = [string]($ht_config_ini_info['ManagerId'])
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
        foreach ($system_url_string in $system_url_collection)
        {
            # Get system resource
            $url_address_system = "https://$ip"+$system_url_string
            $response = Invoke-WebRequest -Uri $url_address_system -Headers $JsonHeader -Method Get -UseBasicParsing

            # Get Bios resource
            $converted_object = $response.Content | ConvertFrom-Json
            $Bios_url = $converted_object.Bios."@odata.id"
            $uri_address_Bios = "https://$ip" + $Bios_url
            $response_bios_url = Invoke-WebRequest -Uri $uri_address_Bios -Headers $JsonHeader -Method Get -UseBasicParsing

            # Get boot mode from bios attributes
            $converted_object = $response_bios_url.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            if($hash_table.Attributes."BootMode")
            {
                $attribute_name = "BootMode"
            }
            elseif($hash_table.Attributes."SystemBootMode")
            {
                $attribute_name = "SystemBootMode"
            }
            else
            {
                $attribute_name = "BootModes_SystemBootMode"
            }

            # Get boot mode setting guide from bios registry
            $WarningText = ""
            $ValueName = "LegacyMode"
            $bios_registry_url = "https://$ip/redfish/v1/Registries/" +$hash_table."AttributeRegistry"
            $response = Invoke-WebRequest -Uri $bios_registry_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object_reg = $response.Content | ConvertFrom-Json
            foreach($location in $converted_object_reg.Location)
            {
                $isfind = $True
                if($location.Language -eq "en")
                {
                    # Get schema uri
                    $url ="https://$ip" +  $location.Uri
                    $response = Invoke-WebRequest -Uri $url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response.Content | ConvertFrom-Json
                    foreach($entry in $converted_object.RegistryEntries.Attributes)
                    {
                        if($entry.AttributeName -eq $attribute_name)
                        {
                            if($entry.WarningText)
                            {
                                $WarningText = $entry.WarningText
                            }
                            foreach($value in $entry.Value)
                            {
                                if($value.ValueName -like "legacy*")
                                {
                                    $ValueName = $value.ValueName
                                }
                            }
                            break
                        }
                    }
                    break
                }
            }

            # Build request body and send requests to set BIOS bootmode
            $pending_url = "https://$ip"+$hash_table."@Redfish.Settings"."SettingsObject"."@odata.id"
            $JsonBody = @{ Attributes = @{
                "$attribute_name"=$ValueName
                }} | ConvertTo-Json -Compress

            try
            {
                $response = Invoke-WebRequest -Uri $pending_url -Headers $JsonHeader -Method Patch  -Body $JsonBody -ContentType 'application/json'
            }
            catch
            {
                # Handle http exception response for Patch request
                if ($_.Exception.Response)
                {
                    Write-Host "Error occured, status code:" $_.Exception.Response.StatusCode.Value__
                    if($_.ErrorDetails.Message)
                    {
                        $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                        $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                        Write-Host "Error message:" $response_j.Resolution
                    }
                }
                # Handle system exception response for Post request
                elseif($_.Exception)
                {
                    Write-Host "Error message:" $_.Exception.Message
                    Write-Host "Please check arguments or server status."
                }
                return $False
            }

            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to set bios bootmode legacy. WarningText: {1}",$response.StatusCode, $WarningText)
            return $True 
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