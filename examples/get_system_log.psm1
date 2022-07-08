###
#
# Lenovo Redfish examples - Get the system log information
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


function get_system_log
{
   <#
   .Synopsis
    Cmdlet used to get system logs
   .DESCRIPTION
    Cmdlet used to get system logs from BMC using Redfish API. Logs will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_system_log -ip 10.10.10.10 -username USERID -password PASSW0RD 
   #>
   
    param(
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
    
    try
    {
        $session_key = ""
        $session_location = ""

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location
        $JsonHeader = @{ "X-Auth-Token" = $session_key}
        
        # Get the manager url collection
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
            $manager_url_string = $i."@odata.id"
            $manager_url_collection += $manager_url_string
        }

        # Loop all Manager resource instance in $manager_url_collection
        foreach ($manager_url_string in $manager_url_collection)
        {
        
            # Get LogServices from the Manager resource instance
            $uri_address_manager = "https://$ip"+$manager_url_string
            
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            
            $temp = [string]$hash_table.LogServices
            $uri_address_LogServices = "https://$ip"+($temp.Split("=")[1].Replace("}",""))
            
            # Get log collections from LogServices
            $response = Invoke-WebRequest -Uri $uri_address_LogServices -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }       
            # Loop all log services in collections
            foreach ($i in $hash_table.Members)
            {
                # Get Entries uri address about the log service
                $i=[string]$i
                $uri_address_log_service = "https://$ip"+($i.Split("=")[1].Replace("}",""))
                
                $sub_response = Invoke-WebRequest -Uri $uri_address_log_service -Headers $JsonHeader -Method Get -UseBasicParsing 
                $converted_object = $sub_response.Content | ConvertFrom-Json
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                if ($hash_table.Keys -notcontains "Entries") 
                {
                    continue
                }
                $temp = [string]$hash_table.Entries
                $uri_address_log_service_entries = "https://$ip"+($temp.Split("=")[1].Replace("}",""))
                # Get detail log information from log service's Entries uri
                $sub_response = Invoke-WebRequest -Uri $uri_address_log_service_entries -Headers $JsonHeader -Method Get -UseBasicParsing
                # Converting PS Custom Object to hashtable, print logs to the screen
                $converted_object = $sub_response.Content | ConvertFrom-Json
                $hash_table2 = @{}
                $converted_object.psobject.properties | Foreach { $hash_table2[$_.Name] = $_.Value }
                if ($hash_table2.'Members@odata.count' -eq 0) 
                {
                    continue
                }
                # Output result
                $hash_table2.Members | ConvertTo-Json
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