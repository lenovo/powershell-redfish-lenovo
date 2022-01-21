###
#
# Lenovo Redfish examples - Set manager ip
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


function set_bmc_ipv4
{
    <#
   .Synopsis
    Cmdlet used to set manager ip
   .DESCRIPTION
    Cmdlet used to set manager ip using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - dhcp_enabled: Pass in dhcp enabled or not for BMC nic
    - static_ip: Pass in static ip for BMC nic
    - static_gateway: Pass in static gateway for BMC nic
    - static_mask: Pass in static mask for BMC nic
   .EXAMPLE
    set_bmc_ipv4 -ip 10.10.10.10 -username USERID -password PASSW0RD -dhcp_enabled 0 -static_ip 10.10.10.11 -static_gateway 10.10.10.1 -static_mask 255.255.255.0
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
        [Parameter(Mandatory=$True, HelpMessage="Indicates if DHCP is enabled or disabled for the bmc nic. (0:false, 1:true)")]
        [string]$dhcp_enabled="",
        [Parameter(Mandatory=$False, HelpMessage="Indicates static ip for the manager nic. It will be ignored when dhcpenabled is set to 1")]
        [string]$static_ip="",
        [Parameter(Mandatory=$False, HelpMessage="Indicates static gateway for the manager nic. It will be ignored when dhcpenabled is set to 1")]
        [string]$static_gateway="",
        [Parameter(Mandatory=$False, HelpMessage="Indicates static subnetmask for the manager nic. It will be ignored when dhcpenabled is set to 1")]
        [string]$static_mask=""
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key }
    
        # Get the manager url collection
        $manager_url_collection = @()
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
            $manager_url_collection += $manager_url_string
        }    

        $target_ethernet_uri = $null
        $target_ethernet_current_setting = @{}
        $nic_addr = $ip.split(':')[0]  # split port if existing
        # Loop all Manager resource instance in $manager_url_collection
        foreach ($manager_url_string in $manager_url_collection)
        {
            $response = Invoke-WebRequest -Uri $manager_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $ht_managers = @{}
            $converted_object.psobject.properties | Foreach { $ht_managers[$_.Name] = $_.Value }
            if($ht_managers.Keys -notcontains "EthernetInterfaces")
            {
                continue
            }
            
            # Check whether server is SR635/SR655 or not
            $flag_SR635_SR655 = $False
            if ($manager_url_string.contains("Managers/Self") -and $ht_managers.Keys -contains "Oem" -and $ht_managers.Oem.psobject.properties.name -contains "Ami")
            {   
                $flag_SR635_SR655 = $True
            }          

            $uri_ethernet ="https://$ip"+$converted_object.EthernetInterfaces.'@odata.id'
            $response = Invoke-WebRequest -Uri $uri_ethernet -Headers $JsonHeader -Method Get -UseBasicParsing  
            $converted_object = $response.Content | ConvertFrom-Json
            
            foreach($i in $converted_object.Members)
            {
                $ethernet_url_string = "https://$ip" + $i."@odata.id"
                $response = Invoke-WebRequest -Uri $ethernet_url_string -Headers $JsonHeader -Method Get -UseBasicParsing  
                $converted_object = $response.Content | ConvertFrom-Json
                $tmp_converted_object = $converted_object | Out-String
                if($tmp_converted_object.contains($nic_addr))
                {
                    $target_ethernet_uri = $ethernet_url_string
                    $converted_object.psobject.properties | Foreach { $target_ethernet_current_setting[$_.Name] = $_.Value }
                    break
                }        
            }
            if($target_ethernet_uri -ne $null)
            {
                break
            }
        }

        if($target_ethernet_uri -eq $null)
        {
            Write-Host "No matched EthernetInterface found under Manager"
            return $False
        }
        # convert input to payload and check validity
        $payload = @{}
        $payload["DHCPv4"] = @{} 
        if($dhcp_enabled -eq "1")
        {
            $payload["DHCPv4"]["DHCPEnabled"] = $True
            $static_ip = ""
            $static_gateway = ""
            $static_mask = ""
        }
        else
        {
            $payload["DHCPv4"]["DHCPEnabled"] = $False 
        }

        if($static_ip -ne "" -or $static_gateway -ne "" -or $static_mask -ne "")
        {
            $config = @{}
            if($static_ip -ne "")
            {
                $config["Address"] = $static_ip
            }
            if($static_gateway -ne "")
            {
                $config["Gateway"] = $static_gateway
            }
            if($static_mask -ne "")
            {
                $config["SubnetMask"] = $static_mask
            }
            if($flag_SR635_SR655)
            {
                $payload["IPv4Addresses"] = @()
                $payload["IPv4Addresses"] += $config
            }
            else
            {
                $payload["IPv4StaticAddresses"] = @()
                $payload["IPv4StaticAddresses"] += $config
            }
        }
        # If no need change, nothing to do. If error detected, report it
        $need_change = $False
        foreach($property in $payload.keys)
        {
            $set_value = $payload[$property]
            $obj_cur_value = $target_ethernet_current_setting[$property]
            # type is simple(not dict/list)
            if($set_value -isnot [array] -and $set_value -isnot [hashtable])
            {
                if($set_value -ne $obj_cur_value)
                {
                    $need_change = $True
                }
            }
            # type is dict
            if($set_value -is [hashtable])
            {
                if($obj_cur_value -is [object])
                {
                    $cur_value = @{}
                    $obj_cur_value.psobject.properties | Foreach { $cur_value[$_.Name] = $_.Value }
                }
                else
                {
                    $cur_value = $obj_cur_value
                }
                foreach($subprop in $set_value.keys)
                {
                    if($subprop -notin $cur_value.keys)
                    {
                        Write-Host 
                        [String]::Format("Sub-property {0} is invalid.",$subprop) 
                        return $False
                    }
                    $sub_set_value = $set_value[$subprop]
                    $sub_cur_value = $cur_value[$subprop]
                    if($sub_set_value -ne $sub_cur_value)
                    {
                        $need_change = $True
                    }
                }
            }
            # type is list
            if($set_value -is [array])
            { 
                $len = $set_value.Length 
                for($i=0; $i -le $len; $i++)
                {                   
                    foreach($subprop in $set_value[$i].keys)
                    {
                        if($obj_cur_value[$i] -is [object])
                        {
                            $cur_value = @{}
                            $obj_cur_value[$i].psobject.properties | Foreach { $cur_value[$_.Name] = $_.Value }
                        }
                        else
                        {
                            $cur_value = $obj_cur_value[$i]
                        }
                        if($subprop -notin $cur_value.keys)
                        {
                            Write-Host 
                            [String]::Format("Sub-property {0} is invalid.",$subprop) 
                            return $False
                        }
                        $sub_set_value = $set_value[$i][$subprop]
                        $sub_cur_value = $cur_value[$subprop]
                        if($sub_set_value -ne $sub_cur_value)
                        {
                            $need_change = $True
                        }
                    }
                }
            }
        }
        if(! $need_change)
        {
            Write-Host "Manager NIC already set"
            return $True
        }

                           
        # Build request body and send request to set bmc ip
        $headers = @{"X-Auth-Token" = $session_key; "If-Match" = "*"}
        $json_body = $payload | convertto-json
        try
        {           
            $response = Invoke-WebRequest -Uri $target_ethernet_uri -Headers $headers -Method Patch  -Body $json_body -ContentType 'application/json'
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
        [String]::Format("- PASS, statuscode {0} returned successfully to set bmc ip",$response.StatusCode) 
        
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
