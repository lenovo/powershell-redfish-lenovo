###
#
# Lenovo Redfish examples - Set server boot once
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


function set_server_boot_once
{
   <#
   .Synopsis
    Cmdlet used to set server boot once
   .DESCRIPTION
    Cmdlet used to get set server boot once from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id: Pass in ComputerSystem instance id(None: first instance, all: all instaces)
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - boot_source: Input the set server boot order("None", "Pxe", "Cd", "Usb", "Hdd", "BiosSetup", "Diags", "UefiTarget")
   .EXAMPLE
    set_server_boot_once -ip 10.10.10.10 -username USERID -password PASSW0RD -boot_source Cd
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string] $ip = '',
        [Parameter(Mandatory=$False)]
        [string] $username = '',
        [Parameter(Mandatory=$False)]
        [string] $password = '',
        [Parameter(Mandatory=$False)]
        [string] $system_id = 'None',
        [Parameter(Mandatory=$False)]
        [string] $config_file = 'config.ini',
        [Parameter(Mandatory=$True, HelpMessage='Input the set server boot("None", "Pxe", "Cd", "Usb", "Hdd", "BiosSetup", "Diags", "UefiTarget")')]
        [ValidateSet('None', 'Pxe', 'Cd', 'Usb', 'Hdd', 'BiosSetup', 'Diags', 'UefiTarget')]
        [string] $boot_source
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
        $session_key = $session_location = ''

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with sesison key for authentication
        $JsonHeader = @{ 'X-Auth-Token' = $session_key}

        # Get the system url collection
        $system_url_collection = @(get_system_urls -bmcip $ip -session $session -system_id $system_id)

        # Loop all System resource instance in $system_url_collection
        foreach ($system_url_string in $system_url_collection)
        {
            # Get system url from the system url collection
            $uri_address_system = "https://$ip"+$system_url_string

            # Build headers with sesison key for authentication
            $JsonHeader = @{ "X-Auth-Token" = $session_key
            }

            # get etag to set If-Match precondition
            $response = Invoke-WebRequest -Uri $uri_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            if($converted_object."@odata.etag" -ne $null)
            {
                $JsonHeader = @{ "If-Match" = $converted_object."@odata.etag"
                            "X-Auth-Token" = $session_key
                }
            }
            else
            {
                $JsonHeader = @{ "If-Match" = ""
                            "X-Auth-Token" = $session_key
                }
            }

            # Prepare PATCH Body to set Boot once to the user specified target
            $patch_body = @{"BootSourceOverrideEnabled"="Once"; "BootSourceOverrideTarget"=$boot_source}
            $body = @{"Boot"=$patch_body}
            $json_body = $body | convertto-json
            try
            {
                $response = Invoke-WebRequest -Uri $uri_address_system -Headers $JsonHeader -Method Patch -Body $json_body -ContentType 'application/json'
            }
            catch
            {
                # Handle http exception response for Post request
                if ($_.Exception.Response)
                {
                    Write-Host "Error occured, status code:" $_.Exception.Response.StatusCode.Value__
                    if($_.ErrorDetails.Message)
                    {
                        $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                        $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                        Write-Host "Error message:" $response_j.Resolution
                    }
                    $response = Invoke-WebRequest -Uri $uri_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response.Content | ConvertFrom-Json
                    $hash_table = @{}
                    $converted_object.psobject.properties | ForEach-Object { $hash_table[$_.Name] = $_.Value }
                    $allowable_values_list = $hash_table.Boot.'BootSourceOverrideTarget@Redfish.AllowableValues'
                    $allowable_values_string = [string]$allowable_values_list
                    $boot_source_string = ($allowable_values_string.Replace(" ",","))
                    Write-Warning ("checking the boot_source parameter, only allow input ($boot_source_string)")
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
            [String]::Format("- PASS, statuscode {0} returned successfully to set bios boot once {1}",$response.StatusCode, $boot_source)  
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
        if (-not [string]::IsNullOrWhiteSpace($session_key))
        {
            delete_session -ip $ip -session $session
        }
    }
}