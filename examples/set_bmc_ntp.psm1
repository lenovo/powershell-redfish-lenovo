###
#
# Lenovo Redfish examples - Set bmc ntp
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


function set_bmc_ntp
{
    <#
   .Synopsis
    Cmdlet used to set bmc ntp
   .DESCRIPTION
    Cmdlet used to set bmc ntp from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - ntp_server: Specify the names of  NTP servers, up to 4 NTP servers can be used
    - enabled: Indicates if the NTP protocol is enabled or disabled. (0:false, 1:true)
   .EXAMPLE
    set_bmc_ntp -ip 10.10.10.10 -username USERID -password PASSW0RD -ntp_server 10.10.10.2 -enabled 0
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
        [Parameter(Mandatory=$True, HelpMessage="Input the ntp server(array  Items: string,Item count: 4)")]
        [array]$ntp_server,
        [Parameter(Mandatory=$True, HelpMessage="Input the ProtocolEnabled (0:false, 1:true)")]
        [int]$enabled
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
    
        # Get the manager url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        
        $managers_url = $converted_object.Managers."@odata.id"
        $managers_url_string = "https://$ip" + $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing 
       
        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        # Set the $manager_url_collection
        foreach ($i in $hash_table.Members)
        {
            $i = [string]$i
            $manager_url_string = ($i.Split("=")[1].Replace("}",""))
            $manager_url_collection += $manager_url_string
        }

        # Loop all Manager resource instance in $manager_url_collection
        foreach ($manager_url_string in $manager_url_collection)
        {
        
            # Get LogServices from the Manager resource instance
            $uri_address_manager = "https://$ip"+$manager_url_string
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object = $response.Content | ConvertFrom-Json
            $uri_network ="https://$ip"+$converted_object.NetworkProtocol.'@odata.id'
            $parameter = @{"NTPServers"=$ntp_server; "ProtocolEnabled"=[bool]$enabled}
            
            # Build request body and send requests to set bmc ntp
            $body = @{"NTP"=$parameter}
            $json_body = $body | convertto-json
            try
            {
                $response = Invoke-WebRequest -Uri $uri_network -Headers $JsonHeader -Method Patch  -Body $json_body -ContentType 'application/json'
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
            [String]::Format("- PASS, statuscode {0} returned successfully to set bmc ntp successful",$response.StatusCode) 
        }
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
