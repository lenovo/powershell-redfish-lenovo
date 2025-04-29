###
#
# Lenovo Redfish examples - Get hostinterface inventory
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

function get_hostinterface

{
    <#
   .Synopsis
    Cmdlet used to get hostinterface
   .DESCRIPTION
    Cmdlet used to get hostinterface from BMC using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_hostinterface -ip 10.10.10.10 -username USERID -password PASSW0RD
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
    # Write-Host $ip
    try
    {
        $session_key = ""
        $session_location = ""
        
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }
    
        # Get ServiceRoot resource
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $response_base_url = $response.Content | ConvertFrom-Json

        # Get Managers colletion resource
        $managers_url = $response_base_url.Managers."@odata.id"
        $managers_url_string = "https://$ip" + $managers_url
        $response_url = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $response_managers_url = $response_url.Content | ConvertFrom-Json
        $hash_table = @{}
        $response_managers_url.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        # Get each Manager resource
        $hostinterfaces = @{}
        
        foreach ($request in $hash_table.Members)
        {
            
            $request_url = "https://$ip" + $request.'@odata.id'
            $each_Manager_response = Invoke-WebRequest -Uri $request_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $each_Manager_converted_object = $each_Manager_response.Content | ConvertFrom-Json
            $each_Manager_hash_table = @{}
            $each_Manager_converted_object.psobject.properties | Foreach { $each_Manager_hash_table[$_.Name] = $_.Value }
            
            # Get HostInterfaces collection resource
            if ($each_Manager_hash_table.keys -notcontains 'HostInterfaces')
            {
                continue
            }
            $uri_host_protocol ="https://$ip" + $each_Manager_hash_table.HostInterfaces."@odata.id"
            $response_hostinterfaces = Invoke-WebRequest -Uri $uri_host_protocol -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object_hostinterfaces = $response_hostinterfaces.Content | ConvertFrom-Json
            $hostinterfaces_hash_table = @{}
            $converted_object_hostinterfaces.psobject.properties | Foreach { $hostinterfaces_hash_table[$_.Name] = $_.Value }

            # Get each HostInterface resource
            foreach ($interface in $hostinterfaces_hash_table.Members)
            {
                $uri_address_members = "https://$ip" + $interface.'@odata.id'
                $response_each_hostInterface = Invoke-WebRequest -Uri $uri_address_members -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object_each_hostInterface = $response_each_hostInterface.Content | ConvertFrom-Json
                $converted_object_hash_table = @{}
                $converted_object_each_hostInterface.psobject.properties | Foreach { $converted_object_hash_table[$_.Name] = $_.Value }   

                $hostinterface_dict = @{}
                foreach ($key in $converted_object_hash_table.Keys)
                {
                    if ("Description", "@odata.context", "@odata.id", "@odata.type", "@odata.etag", "Links", "Actions", "RelatedItem", "HostEthernetInterfaces", "ManagerEthernetInterface", "NetworkProtocol" -notcontains $key)
                    {
                         $hostinterface_dict[$key] = $converted_object_hash_table.$key
                    }                        
                }

                # Get HostEthernetInterfaces resource
                if ($converted_object_hash_table.Keys -notcontains "HostEthernetInterfaces")
                {
                    $hostinterfaces += $hostinterface_dict
                    continue
                }

                # Get HostEthernetInterfaces resource
                $hostethernets_url ="https://$ip" + $converted_object_hash_table.HostEthernetInterfaces."@odata.id"
                $response_HostEthernetInterfaces = Invoke-WebRequest -Uri $hostethernets_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $HostEthernetInterfaces_converted_object = $response_HostEthernetInterfaces.Content | ConvertFrom-Json
                $HostEthernetInterfaces_hash_table = @{}
                $HostEthernetInterfaces_converted_object.psobject.properties | Foreach { $HostEthernetInterfaces_hash_table[$_.Name] = $_.Value }

                # Get each HostEthernetInterface resource
                $HostEthernetInterfaces = @()
                foreach ($ethernet in $HostEthernetInterfaces_hash_table.Members)
                {
                    $uri_address_member = "https://$ip" + $ethernet.'@odata.id'
                    $each_HostEthernetInterface_response = Invoke-WebRequest -Uri $uri_address_member -Headers $JsonHeader -Method Get -UseBasicParsing
                    $each_HostEthernetInterface_converted_object = $each_HostEthernetInterface_response.Content | ConvertFrom-Json
                    $each_HostEthernetInterface_hash_table = @{}
                    $each_HostEthernetInterface_converted_object.psobject.properties | Foreach { $each_HostEthernetInterface_hash_table[$_.Name] = $_.Value }

                    $hostethernetinterface_dict = @{}
                    foreach ($key in $each_HostEthernetInterface_hash_table.Keys)
                    {
                        if ("Description", "@odata.context", "@odata.id", "@odata.type", "@odata.etag", "Links", "Actions", "RelatedItem" -notcontains $key)
                        {
                            $hostethernetinterface_dict[$key] = $each_HostEthernetInterface_hash_table.$key
                        }
                    }
                    $HostEthernetInterfaces += $hostethernetinterface_dict
                }

                $hostinterface_dict["HostEthernetInterfaces"] = $HostEthernetInterfaces
                $hostinterfaces += $hostinterface_dict
                # Output result
                ConvertOutputHashTableToObject $hostinterfaces | ConvertTo-Json

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