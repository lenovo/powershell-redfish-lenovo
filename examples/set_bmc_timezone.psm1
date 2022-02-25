###
#
# Lenovo Redfish examples - Set bmc timezone
#
# Copyright Notice:
#
# Copyright 2022 Lenovo Corporation
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


function set_bmc_timezone
{
    <#
   .Synopsis
    Cmdlet used to set bmc timezone
   .DESCRIPTION
    Cmdlet used to set bmc timezone from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - timezone: Pass in timezone by user specified
   .EXAMPLE
    set_bmc_timezone -ip 10.10.10.10 -username USERID -password PASSW0RD -timezone timezone
   #>
    param
    (
       [Parameter(Mandatory=$False)]
       [string]$ip="",
       [Parameter(Mandatory=$False)]
       [string]$username="",
       [Parameter(Mandatory=$False)]
       [string]$password="",
       [Parameter(Mandatory=$False)]
       [string]$config_file="config.ini",
       [Parameter(Mandatory=$True, HelpMessage="Specify the time offset from UTC, format should be +HH:MM or -HH:MM, such as '+08:00', ' -05:00'.")]
       [string]$timezone=""
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

        $JsonHeader = @{"X-Auth-Token" = $session_key}
        
        # Get the manager url collection
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        
        $managers_url = $converted_object.Managers."@odata.id"
        $managers_url_string = "https://$ip" + $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing        
        $converted_object = $response.Content | ConvertFrom-Json

        foreach($i in $converted_object.Members)
        {
            $manager_url_string = "https://$ip" + $i."@odata.id"
            $response = Invoke-WebRequest -Uri $manager_url_string -Headers $JsonHeader -Method Get -UseBasicParsing        
            $converted_object = $response.Content | ConvertFrom-Json
        }
        #Get etag to set If-Match precondition
        if ($converted_object.Keys -contains '@odata.etag') 
        {
            $etag = $converted_object.'@odata.etag'
        }
        else 
        {
            $etag = '*'
        }
        $headers = @{"X-Auth-Token" = $session_key; "If-Match" = "*"}
        #Build patch body for request to set timezone
        $body = @{"DateTimeLocalOffset"=$timezone}
        $json_body = $body | convertto-json
            
        try
        {
            $response = Invoke-WebRequest -Uri $manager_url_string -Headers $headers -Method Patch  -Body $json_body -ContentType 'application/json'     
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
        [String]::Format("- PASS, statuscode {0} returned successfully to set bmc timezone",$response.StatusCode) 
            
        return $True
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

            