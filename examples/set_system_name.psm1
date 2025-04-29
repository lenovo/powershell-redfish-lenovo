###
#
# Lenovo Redfish examples - Set system name
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

function set_system_name
{
    <#
   .Synopsis
    Cmdlet used to set system name
   .DESCRIPTION
    Cmdlet used to set system name. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - system_name: Pass in system name specified by user
   .EXAMPLE
    set_system_name -ip 10.10.10.10 -username USERID -password PASSW0RD -system_name SYSTEMNAME
   #>
   param(
        [parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$system_name,
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
    try {
        $session_key = ""
        $session_location = ""

        # Create session 
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with session key for authentication
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

        # Get ServiceBase resource
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        # Get response base url
        $chassis_url = $converted_object.Chassis."@odata.id"
        $chassis_url_string = "https://$ip"+ $chassis_url
        $response = Invoke-WebRequest -Uri $chassis_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $response_chassis_url = $response.Content | ConvertFrom-Json

        #get system name
        foreach ($request in $response_chassis_url.Members)
        {
            $response_managers_url = "https://$ip" + $request.'@odata.id'
            $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }
            $response_url = Invoke-WebRequest -Uri $response_managers_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $links_info = $response_url.Content | ConvertFrom-Json
            $ht_links = @{}
            $links_info.psobject.properties | Foreach { $ht_links[$_.Name] = $_.Value }
            $data = $response_chassis_url.Members

            $tmp_links = @{}
            $ht_links.Links.psobject.properties | Foreach { $tmp_links[$_.Name] = $_.Value }
            # if chassis is not normal skip it
            if(($data.length -gt 1) -and ($ht_links.Keys -notcontains "Links" -or $tmp_links.Keys -notcontains 'ComputerSystems'))
            {
                continue
            }
            # if no Location property, skip it
            if($ht_links.keys -notcontains 'Location')
            {
                continue
            }
            
            # Send Patch Request to Modify System Name
            $JsonHeader = @{"X-Auth-Token" = $session_key; "If-Match" = "*" }
            $name = @{"Name" = $system_name}
            $pAddr = @{"PostalAddress"= $name}
            $body = @{"Location" = $pAddr}
            $JsonBody = $body | ConvertTo-Json
            $response = Invoke-WebRequest -Uri $response_managers_url -Method Patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
            [String]::Format("- PASS, Set system name {0} successfully",$system_name)
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