###
#
# Lenovo Redfish examples - Set chassis indicator led
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


function set_chassis_indicator_led
{
   <#
   .Synopsis
    Cmdlet used to set chassis indicator led
   .DESCRIPTION
    Cmdlet used to set chassis indicator led status from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - led_status: Pass in led status specified by user(Off, Lit, Blinking)
   .EXAMPLE
    set_chassis_indicator_led -ip 10.10.10.10 -username USERID -password PASSW0RD -led_status Off
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$true, HelpMessage='Input the set led status("Off", "Lit", "Blinking")')]
        [string]$led_status="",
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
        
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with sesison key for authentication
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }
        
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        # Create an null array for result return
        $chassis_url_collection = @()
        # Get the chassis url collection via Invoke-WebRequest
        $chassis_url = $converted_object.Chassis."@odata.id"
        $chassis_url_string = "https://$ip" + $chassis_url
        $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing 

        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
    
        # Set the $chassis_url_collection by checking $chassis_id value
        foreach ($i in $hash_table.Members)
        {
            $i = [string]$i
            $chassis_url_string = ($i.Split("=")[1].Replace("}",""))
            $chassis_url_collection += $chassis_url_string
        }

        # Loop all chassis resource instance in $chassis_url_collection
        foreach ($chassis_url_string in $chassis_url_collection)
        {
            # Get chassis url from the chassis url collection
            $uri_address_chassis = "https://$ip"+$chassis_url_string

            # Build request body and send requests to set LED status
            $body = @{"IndicatorLED"=$led_status}
            $json_body = $body | convertto-json
            try
            {
                $response = Invoke-WebRequest -Uri $uri_address_chassis -Headers $JsonHeader -Method Patch  -Body $json_body -ContentType 'application/json'
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
            [String]::Format("- PASS, statuscode {0} returned successfully to set led {1}",$response.StatusCode, $led_status)
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
    