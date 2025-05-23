###
#
# Lenovo Redfish examples - Set bmc hostname
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


function set_bmc_hostname
{
    <#
   .Synopsis
    Cmdlet used to set bmc hostname
   .DESCRIPTION
    Cmdlet used to set bmc hostname using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - hostname: Specify the BMC hostname  
   .EXAMPLE
    set_bmc_hostname -ip 10.10.10.10 -username USERID -password PASSW0RD -hostname hostname
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
        [Parameter(Mandatory=$True, HelpMessage="Input the hostname")]
        [string]$hostname=""
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
        $converted_object = $response.Content | ConvertFrom-Json
        foreach($i in $converted_object.Members)
        {
            $manager_url_string = "https://$ip" + $i."@odata.id"
            $manager_url_collection += $manager_url_string
        }    

        $target_ethernet_uri = $null
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

        #Check that the hostname you want to set is the same as it is now
        if ($converted_object.HostName -eq $hostname)
        {
            Write-Host "The hostname to be set is the same as the current"
            return $False
        }
            
        # Build request body and send request to set bmc hostname
        $headers = @{"X-Auth-Token" = $session_key; "If-Match" = "*"}
        $body = @{ "HostName" = $hostname }
        $json_body = $body | convertto-json
        
        $response = Invoke-WebRequest -Uri $target_ethernet_uri -Headers $headers -Method Patch  -Body $json_body -ContentType 'application/json'
       
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 204)
        {
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to set bmc hostname to {1}",$response.StatusCode, $hostname) 
            return $True
        }
        elseif ($response.StatusCode -eq 202)
        {
            $converted_object = $response.Content | ConvertFrom-Json
            $task_uri = "https://$ip" + $converted_object.'@odata.id'
            while($True)
            {
                try
                {
                    $result = task_monitor $session_key $task_uri
                    break
                }
                catch
                {
                    if($_.Exception.Response -and $_.Exception.Response.StatusCode.Value__ -eq 401)
                    {
                        while($True)
                        {
                            # Get the base url
                            $response_base_url = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
                            if ($response_base_url.StatusCode -eq 200)
                            {
                                # Create session
                                $session = create_session -ip $ip -username $username -password $password
                                $session_key = $session.'X-Auth-Token'

                                # Build headers with sesison key for authentication
                        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }
                                break
                            }
                            Start-Sleep -m 1000
                        }
                    }
                    Start-Sleep -m 1000
                    continue
                }
            }
            # Delete the task when the task state is completed without any warning
            $severity = ''
            if ($result.ret -eq $True -and $result.task_state -eq "Completed" -and $result.msg -ne '')
            {
                if ($null -ne $result.msg.'Severity')
                {
                    $severity = $result.msg.'Severity'
                }
            }
            if ($result.ret -eq $True -and $result.task_state -eq "Completed"-and ($result.msg -eq '' -or $severity -eq "OK"))
            {
                $response_deltask = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Delete -UseBasicParsing
            }
            if ($result.ret -eq $True)
            {
                $task_state = $result.task_state
                if ($task_state -eq "Completed")
                {
                    Write-Host
                    [String]::Format("- PASS, Set BMC host name {0} successfully. Messages: {1}", $hostname, $result.msg.Message) 
                    return $True
                }
                else
                {
                    Write-Host
                    [String]::Format("Failed to set BMC host name {0}. Messages: {1}", $hostname, $result.msg.Message) 
                    return $False
                }
            }
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
