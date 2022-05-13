###
#
# Lenovo Redfish examples - Set manager dns
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

Import-module $PSScriptRoot\lenovo_utils.psm1

function lenovo_set_bmc_dns
{
    <#
   .Synopsis
    Cmdlet used to set bmc dns
   .DESCRIPTION
    Cmdlet used to set bmc dns from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - enabled: Indicates if DNS is enabled or disabled for the bmc nic. (0:false, 1:true)
    - dnsserver: Specify the names of DNS servers, up to 3 DNS servers can be used.
    - domainname: Specify the domain name, which will be changed along with domain DHCP is set to "static", the domain name should contain dot(.) and no other special characters,such as ":".
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_set_bmc_dns -ip 10.10.10.10 -username USERID -password PASSW0RD -enabled (0,1) -dnsserver 0.0.0.0,1.1.1.1,2.2.2.2 -domainname DOMAIN NAME
   #>
   param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)][ValidateSet(0, 1)]
        [string]$enabled=1,
        [Parameter(Mandatory=$False)]
        [array]$dnsserver="",
        [Parameter(Mandatory=$False)]
        [string]$domainname="",
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

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key }

        # Get ServiceBase resource
        $response_base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $response_base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        $managers_url = $hash_table.Managers.'@odata.id'
        $managers_url_string = "https://$ip"+ $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        foreach($member in $hash_table.Members)
        {
            $response_member = "https://$ip" + $member.'@odata.id'
            $response = Invoke-WebRequest -Uri $response_member -Headers $JsonHeader -Method Get -UseBasicParsing
            $member_object = $response.Content | ConvertFrom-Json
            $member_hash = @{}
            $member_object.psobject.properties | Foreach { $member_hash[$_.Name] = $_.Value }
            
            if($member_hash.keys -notcontains "NetworkProtocol")
            {
                continue
            }
            $dns_url = $response_member + '/NetworkProtocol/Oem/Lenovo/DNS'
            $response = Invoke-WebRequest -Uri $dns_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $dns_object = $response.Content | ConvertFrom-Json
            $dns_hash = @{}
            $dns_object.psobject.properties | Foreach { $dns_hash[$_.Name] = $_.Value }      
            
            if ($enabled -eq '1')
            {
                $payload = @{"DNSEnable" = $True}
            }
            else
            {
                $payload = @{"DNSEnable" = $False}
            }
            if ($enabled -eq '1' -and $dnsserver -eq $null -and $domainname -eq $null)
            {
                Write-Host 'Please specify the DNS servers or the domain name'
                return $False
            }
            if ($dnsserver -ne $null)
            {
                $len_dns = $dnsserver.Length
                if($len_dns -gt 3)
                {
                    Write-Host 'User can only specify the name of up to 3 DNS servers'
                    return $False
                }
            }
            if($dns_hash.keys -contains 'Actions')
            {
                $hash_actions = @{}
                $dns_hash.Actions.psobject.properties | Foreach { $hash_actions[$_.Name] = $_.Value } 
                if($hash_actions.keys -contains '#DNS.Reset')
                {
                    # SR635 / SR655
                    if($enabled -eq '1')
                    {
                        $payload = @{'DNSStatus'= 'enable'}
                    }
                    else
                    {
                        $payload = @{'DNSStatus'= 'disable'}
                    }
                    if ($dnsserver -ne $null)
                    {
                        $payload['DNSDHCP'] = 'static'
                        $payload['DNSIndex'] = 'none'
                        $payload['IPPriority'] = 'none'
                        for ($index = 0; $index -lt $dnsserver.Length; $index++)
                        {
                            $DNSServerIP = [String]::Format("DNSServerIP{0}", $index+1)
                            $payload[$DNSServerIP] = $dnsserver[$index]
                        }
                    }
                    if($domainname -ne $null)
                    {
                        $payload['DomainDHCP'] = 'static'
                        $payload['DomainName'] = $domainname
                    }
                }
            }
            else
            {
                # XCC
                if ($dnsserver -ne $null)
                {
                    $payload['PreferredAddresstype'] = 'IPv4'
                    for ($index = 0; $index -lt $dnsserver.Length; $index++)
                    {
                        $IPv4Address = [String]::Format("IPv4Address{0}", $index+1)
                        $payload[$IPv4Address] = $dnsserver[$index]
                    }
                }
                if ($domainname -ne $null)
                {
                    $payload['DDNS'] = @()
                    $DDNS_body = @{}
                    $DDNS_body['DDNSEnable'] = $True
                    $DDNS_body['DomainNameSource'] = 'Custom'
                    $DDNS_body['DomainName'] = $domainname
                    $payload['DDNS'] += $DDNS_body     
                }
            }
            $JsonBody = $payload | ConvertTo-Json -Depth 10
            $JsonHeader = @{"X-Auth-Token" = $session_key; 'If-Match'= '*'}
            $response_url_patch = Invoke-WebRequest -Uri $dns_url -Headers $JsonHeader -Method patch -Body $JsonBody -ContentType 'application/json'
            $url_list = @('200', '204')
            if($url_list -contains $response_url_patch.StatusCode)
            {
                if($dns_hash.keys -contains 'Actions')
                {
                    if ($hash_actions.keys -contains '#DNS.Reset')
                    {
                        # For SR635 / SR655 products, need reset the DNS
                        $reset_url = $dns_url + '/' + 'Actions' + '/' + 'DNS.reset'
                        $body = @{'ResetType'= 'restart'}
                        $Json_body = $body | ConvertTo-Json
                        $response_reset_url = Invoke-WebRequest -Uri $reset_url -Method Post -Body $Json_body -Headers $JsonHeader -ContentType 'application/json' 
                        if($response_reset_url.StatusCode -eq 200)
                        {
                            Write-Host 'Set BMC DNS config successfully.'
                            Write-Host 'Start to reset the DNS, may take about 1 minute...'
                            return $True
                        }
                        else
                        {
                            [String]::Format("Url '{0}' response Error code '{1}'",$reset_url, $response_reset_url.StatusCode)
                            return $False
                        }
                    }
                }
                else
                {
                    # XCC
                    Write-Host 'Set BMC DNS config successfully'
                    return $True
                }
            }
            else
            {
                [String]::Format("Url '{0}' response Error code '{1}'",$dns_url, $response_url_patch.StatusCode)
                return $False
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