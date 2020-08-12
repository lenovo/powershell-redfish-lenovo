###
#
# Lenovo Redfish examples - Set network protocol
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
function set_network_protocol
{
   <#
   .Synopsis
    Cmdlet used to set network protocol
   .DESCRIPTION
    Cmdlet used to set network protocol using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - service: Specify service information supported by BMC. Support:["HTTPS","SSDP","SSH","SNMP","IPMI","VirtualMedia"]')
    - enabled: Disable(0) or enable(1) the BMC service. Support:[0, 1]. default is 1
    - port: The value of this property shall contain the port assigned for the protocol. These ports "IPMI:623","SLP:427" and "SSDP:1900" are reserved and can only be used for the corresponding services
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    set_networkprotocol -ip 10.10.10.10 -username USERID -password PASSW0RD -service SERVICE -port PORT
   #>
   
    param
    (
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$service="",
        [Parameter(Mandatory=$False)]
        [int]$enabled=1,
        [Parameter(Mandatory=$False)]
        [int]$port="",
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

        $JsonHeader = @{"X-Auth-Token" = $session_key}
    
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
        
            # Get service data uri from the Manager resource instance
            $uri_address_manager = "https://$ip" + $manager_url_string

            # Get the network protocol url
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $uri_network_protocol ="https://$ip" + $converted_object.NetworkProtocol."@odata.id"

            if($enabled -eq 1)
            {
                $enable= "true"
            }
            elseif($enabled -eq 0)
            {
                $enable = "false"
            }
            else
            {
                Write-Host "The parameter enabled only supported disable(0) or enable(1) the BMC service."
            }
            # Build request body for modify network protocol
            if("IPMI", "SSDP" -contains $service)
            {
                $json_body = '{"' + $service +'":{"ProtocolEnabled":' + $enable + '}}'
                
            }
            elseif("SSH", "HTTPS", "SNMP", "VirtualMedia" -contains $service)
            {
                $json_body = '{"' + $service + '":{"ProtocolEnabled":' + $enable + ',"Port":' + $port + '}}'
            }
            else
            {
               Write-Host "Please check the BMC service name is in the [HTTPS,SSDP,SSH,SNMP,IPMI,VirtualMedia]"
               return $False
            }

            # Send Patch Request to Modify Network Port
            $response = Invoke-WebRequest -Uri $uri_network_protocol -Headers $JsonHeader -Method Patch -Body $json_body -ContentType 'application/json' -UseBasicParsing
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to set BMC server {1}",$response.StatusCode, $service)
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