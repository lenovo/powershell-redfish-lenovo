###
#
# Lenovo Redfish examples - Set power limit
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

function set_power_limit
{
    <#
   .Synopsis
    Cmdlet used to Set power limit
   .DESCRIPTION
    Cmdlet used to Set power limit from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id: Pass in ComputerSystem instance id (None: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - isenable: It is used to set power capping enabled or disabled(0:disabled,1:enabled). When power capping is enabled, the system may be throttled in order to maintain the power limit, you can set powerlimit using parameter powerlimit. Note: Even when power capping is disabled, the system may be throttled under certain fault conditions, such as when there is a power supply failure or a cooling issue, etc.
    - powerlimit: Input the power limit you want to set. (When isnable is 1,you must set powerlimit. When isnable is 0, your setting is meaningless). Note:The manual setting of maximum power limit can be over the actual power capacity. (1-32766).
   .EXAMPLE
    set_power_limit -ip 10.10.10.10 -username USERID -password PASSW0RD -isenable 1 -powerlimit 400
   #>
   
    param(
        [ValidateSet(0,1)]
        [Parameter(Mandatory=$True)]
        [int]$isenable,
        [Parameter(Mandatory=$False)]
        [int]$powerlimit = 0,
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

        # Build headers with session key for authentication
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
        
        # Loop all chassis resource instance in $chassis_url_collection
        foreach($chassis_url_string in $chassis_url_collection)
        {
            #get chassis resource
            $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $links_info = $converted_object.Links
            $ht_links = @{}
            $links_info.psobject.properties | Foreach { $ht_links[$_.Name] = $_.Value }
            if($ht_links.Keys -notcontains "ComputerSystems")
            {
                continue
            }

            #Get powerl_url resource
            $power_url = "https://$ip" + $converted_object.Power."@odata.id"
            $response = Invoke-WebRequest -Uri $power_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            #get power limit info
            $list_control_info = @()
            $list_control_info = $converted_object.PowerControl
            if(($list_control_info.length -eq 0) -or ($list_control_info[0].PowerLimit.length -eq 0))
            {
                Write-Host "Not Supporting this function"
                return $False
            }

           $str_isenable = ""
           if($isenable -eq 1)
           {
                $str_isenable = "true"
           }
           else
           {
                $str_isenable = "false"
           }

           if($isenable -eq 1)
           {
                $JsonBody = '{"PowerControl": [{"PowerLimit":{"LimitInWatts":' + $powerlimit.ToString() + '}}]}'
           }
           else
           {
                $JsonBody = '{"PowerControl": [{"PowerLimit":{"LimitInWatts":' + "null" + '}}]}'
           }
           $response = Invoke-WebRequest -Uri $power_url -Method Patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
           Write-Host
                [String]::Format("- PASS, statuscode {0} returned successfully to set powerlimit",$response.StatusCode)
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
            #delete_session -ip $ip -session $session
        }
    }
}