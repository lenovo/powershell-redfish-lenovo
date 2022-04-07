###
#
# Lenovo Redfish examples - Bmc license delete
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

function lenovo_bmc_license_delete
{
   <#
   .Synopsis
    Cmdlet used to delete bmc license 
   .DESCRIPTION
    Cmdlet used to delete bmc license from BMC using Redfish API. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - key_id: The Id of the license you want to delete, default is 1
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_Bmc_license_delete -ip 10.10.10.10 -username USERID -password PASSW0RD --key_id KEYID
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
        [Parameter(Mandatory=$False,HelpMessage='license key id by user specified')]
        [string]$key_id="1"
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

        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location
        $JsonHeader = @{"X-Auth-Token" = $session_key}
        # Get the base url collection
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json

        # Get the manager url collection
        $manager_url = "https://$ip" + $converted_object.Managers."@odata.id"
        $response = Invoke-WebRequest -Uri $manager_url -Header $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        # Get Manager resource
        foreach($request in $converted_object.Members)
        {
            $request_url = $request.'@odata.id'
            $response_url = "https://$ip"+$request_url
            $response = Invoke-WebRequest -Uri $response_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            $hash_table_oem = @{}
            $hash_table.Oem.psobject.properties | Foreach { $hash_table_oem[$_.Name] = $_.Value }

            $hash_table_lenovo = @{}
            $hash_table_oem.Lenovo.psobject.properties | Foreach { $hash_table_lenovo[$_.Name] = $_.Value }
            # Get bmc license url
            if ($hash_table.Keys -contains 'Oem' -and $hash_table_oem.Keys -contains 'Lenovo' -and $hash_table_lenovo.Keys -contains 'FoD') 
            {
                $request_url = $hash_table_lenovo.FoD.'@odata.id'
            }
            else 
            {
                break
            }
            $bmc_license_request_url = "https://$ip"+$request_url
            $response = Invoke-WebRequest -Uri $bmc_license_request_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            if ($converted_object.Keys -contains '@odata.id' -and '@odata.id' -notcontains 'Keys') 
            {
                break
            }
            # Get license key collection to check key id validity
            $request_url = $converted_object.Keys.'@odata.id'
            $response_bmc_url = "https://$ip" + $request_url
            $response = Invoke-WebRequest -Uri $response_bmc_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json  

            $request_delete_url = $request_url + '/' + $key_id
            $found = $False
            $list = @()
            $IdList = $list
            $hash_table_key = @{}
            $converted_object.psobject.properties | Foreach { $hash_table_key[$_.Name] = $_.Value }
            if ($hash_table_key.Keys -contains 'Members') 
            {
                $keylink_collection = $hash_table_key.Members
                
                foreach ($keylink in $keylink_collection)
                {
                    $key_url = $keylink.'@odata.id'
                    if ($request_delete_url -eq $key_url) 
                    {
                        $found = $True
                        break
                    }
                    $IdList += $key_url.split('/')[-1]
                }
            }
            if ($found -eq $False -and $IdList.Length -gt 0) 
            {
                Write-Host
                [String]::Format("The key id {0} is not valid. Valid key id list: [{1}].",$key_id,[String]$IdList)
                return $False
            }
            if ($found -eq  $False -and $IdList.Length -eq 0) 
            {
                Write-Host "No license key present, no need to delete."
                return $False
            }
            # Perform delete to delete license key
            $response = "https://$ip" + $request_delete_url
            $response = Invoke-WebRequest -Uri $response -Headers $JsonHeader -Method Delete -UseBasicParsing 
            $converted_object =$response.Content | ConvertFrom-Json
           
            [String]::Format(" BMC license delete successfully.")
            return $True
        }
        Write-Host "No license resource found, not support."
        return $False
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