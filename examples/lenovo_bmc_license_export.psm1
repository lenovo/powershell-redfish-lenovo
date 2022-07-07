###
#
# Lenovo Redfish examples - Bmc license export
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

function lenovo_bmc_license_export
{
   <#
   .Synopsis
    Cmdlet used to export bmc license
   .DESCRIPTION
    Cmdlet used to export bmc license from BMC using Redfish API. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - license file: Pass in user-specified license file
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_bmc_license_export -ip 10.10.10.10 -username USERID -password PASSW0RD -license_file exported_10.10.10.10_license_keyfile_1.key
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini",
        [Parameter(Mandatory=$False,HelpMessage="Input the file name that you want to save the exported license, default file: exported_10.10.10.10_license_keyfile_1.key")]
        [string]$license_file=""
        )
       
    if ($license_file -ne "" -and (Test-Path $license_file)) 
    {
        Write-Host "Specified file %s does not exist. Please check your license file path."
        return $False
    }
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
        #Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location
        $JsonHeader = @{"X-Auth-Token" = $session_key}

        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json

        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        if ($hash_table.Keys -contains 'LicenseService') 
        {
           Write-Host "Target server does not support exporting bmc license file."
           return $False
        }
        # Get Manager collection resource
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
                $request_url = "https://$ip" + $hash_table_lenovo.FoD.'@odata.id'
            }
            else 
            {
                break
            }
            $response = Invoke-WebRequest -Uri $request_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            if ($hash_table.Keys -cnotlike "*Keys*") 
            {
                break
            }
            # Get license key collection
            $request_url = $converted_object.Keys.'@odata.id'
            $response_bmc_url = "https://$ip" + $request_url
            $response = Invoke-WebRequest -Uri $response_bmc_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json   

            $hash_table_key = @{}
            $converted_object.psobject.properties | Foreach { $hash_table_key[$_.Name] = $_.Value }
            if ($hash_table_key.Keys -contains 'Members') 
            {
                $keylink_collection = $hash_table_key.Members
                foreach ($keylink in $keylink_collection) 
                {
                    $request_url = $keylink.'@odata.id'
                    $Members_url = "https://$ip"+$request_url
                    $Members_response = Invoke-WebRequest -Uri $Members_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $Members_response.Content | ConvertFrom-Json

                    $hash_table_members = @{}
                    $converted_object.psobject.properties | Foreach { $hash_table_members[$_.Name] = $_.Value }
                    if ($license_file -ne "")
                    {
                        $filename = $license_file
                    }
                    else 
                    {
                        $filename = 'exported_' +$ip+'_license_keyfile_' +$request_url.split('/')[-1] +'.key'
                    }
                    if (Test-Path($filename)) 
                    {
                        Remove-Item($filename)
                    }
                    New-Item $filename 
                    if ($hash_table_members.Keys -contains 'Bytes') 
                    {
                        $bytelist = $hash_table_members.'Bytes'
                        foreach($eachbyte in $bytelist)
                        {
                            $byte = [System.Convert]::ToByte($eachbyte)
                            add-content $filename $byte  -Encoding Byte -NoNewline
                        }
                    }
                    $license_keys += $filename
                }
            }
            if ($license_keys.length -eq 0)
            {
                Write-Host "No license key present."
                return $False
            }
            else 
            {
                Write-Host "Export license keys successfully."
                return $True
            }
        }
        Write-Host "Not support license via Redfish."
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
