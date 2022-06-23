###
#
# Lenovo Redfish examples - BMC license import
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

function lenovo_bmc_license_import
{
   <#
   .Synopsis
    Cmdlet used to import bmc license 
   .DESCRIPTION
    Cmdlet used to import bmc license from BMC using Redfish API. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - license_file: Pass in user-specified license file
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_bmc_license_import -ip 10.10.10.10 -username USERID -password PASSW0RD -license_file LICENSEFILE
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
        [Parameter(Mandatory=$True, HelpMessage="A file that contains the license key you want to import")]
        [string]$license_file=""
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
        if (-not (Test-Path $license_file))
        {
            [String]::Format("Specified file %s does not exist. Please check your license file path.",$license_file)
            return $False
        }
        $session_key = ""
        $session_location = ""

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location
        $JsonHeader = @{"X-Auth-Token" = $session_key}

        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json

        $hash_table_base = @{}
        $converted_object.psobject.properties | Foreach { $hash_table_base[$_.Name] = $_.Value }

        if ($hash_table_base.Keys -contains 'LicenseService') 
        {
            $licenseService_url = "https://$ip" + $hash_table_base.LicenseService.'@odata.id'
            $response_licenseService_url = Invoke-WebRequest -Uri $licenseService_url -Headers $JsonHeader -Method Get -UseBasicParsing 
            $converted_object =$response_licenseService_url.Content | ConvertFrom-Json

            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            if ($hash_table.Keys -contains 'Licenses') 
            {
                $license_url = "https://$ip" + $hash_table.Licenses."@odata.id"
                try 
                {
                    $content = Get-Content $license_file -Encoding byte 
                    $converted = [convert]::ToBase64String($content)
                }
                catch 
                {
                    [String]::Format("Failed to open file.")
                    return $False
                }
                $request_body = @{}
                $request_body["LicenseString"]= $converted
                $json_body = $request_body | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $license_url -Method Post -Headers $JsonHeader -Body $json_body -ContentType 'application/json'
                Write-Host
                [String]::Format("BMC license import successfully",$response.StatusCode)
                return $True
            }
        }      
        else
        {
            $manager_url = "https://$ip" + $hash_table_base.Managers.'@odata.id'
            $response = Invoke-WebRequest -Uri $manager_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            foreach($request in $converted_object.Members)
            {
                $request_url = "https://$ip" + $request.'@odata.id'
                $response = Invoke-WebRequest -Uri $request_url -Headers $JsonHeader -Method Get -UseBasicParsing 
                $converted_object = $response.Content | ConvertFrom-Json
            
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
    
                $hash_table_oem = @{}
                $hash_table.Oem.psobject.properties | Foreach { $hash_table_oem[$_.Name] = $_.Value }

                $hash_table_lenovo = @{}
                $hash_table_oem.Lenovo.psobject.properties | Foreach { $hash_table_lenovo[$_.Name] = $_.Value }

                if ($hash_table.Keys -contains 'Oem' -and $hash_table_oem.Keys -contains 'Lenovo' -and $hash_table_lenovo.Keys -contains 'FoD')
                {
                    $request_fod_url = "https://$ip" + $hash_table_lenovo.FoD.'@odata.id'
                }
                else 
                {
                    break
                }
                $response = Invoke-WebRequest -Uri $request_fod_url -Headers $JsonHeader -Method Get -UseBasicParsing 
                $converted_object = $response.Content | ConvertFrom-Json  
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                if ($hash_table.Keys -cnotlike "*Keys*")
                {
                    break
                }
                $list = @()
                try
                {
                    $content = Get-Content $license_file -Encoding Byte | ConvertFrom-Json
                    foreach($i in $content)
                    {
                        $list += $i
                    }
                }
                catch 
                {
                    $list = @()
                    if($_.Exception)
                    {
                        Write-Host "Error message:" $_.Exception.Message
                        Write-Host "Please check arguments."
                    }
                }
                $request_body = @{}
                $request_body['Bytes'] = $list
                $json_body = $request_body | ConvertTo-Json
                $request_url = "https://$ip" + $converted_object.Keys."@odata.id"
                $response = Invoke-WebRequest -Uri $request_url -Method Post -Headers $JsonHeader -Body $json_body -ContentType 'application/json'
                Write-Host
                [String]::Format("BMC license import successfully",$response.StatusCode)
                return $True
            }
        }
        Write-Host
        [String]::Format("Not support license via Redfish.")
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
