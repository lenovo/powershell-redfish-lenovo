###
#
# Lenovo Redfish examples - Disable security HTTPS to use certificate
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

function lenovo_httpfs_certificate_disable
{
   <#
   .Synopsis
    Cmdlet used to disable https certificate
   .DESCRIPTION
    Cmdlet used to disable https certificate from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_httpfs_certificate_disable -ip 10.10.10.10 -username USERID -password PASSW0RD
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

        # Get response_base_url
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json

        $update_service_url = "https://$ip" + $converted_object.UpdateService."@odata.id"
        $response_update_service_url = Invoke-WebRequest -Uri $update_service_url -Header $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response_update_service_url.Content | ConvertFrom-Json

        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        # Check /redfish/v1/UpdateService/VerifyRemoteServerCertificate existing
        if ($hash_table.Keys -contains 'VerifyRemoteServerCertificate')   
        {
            if ($hash_table.VerifyRemoteServerCertificate -eq $False) 
            {
                Write-Host "HTTPS certificate security is already disabled."
                return $True
            }
            $enable_body = @{"VerifyRemoteServerCertificate" = $False} | ConvertTo-Json
            $response_enable_verify = Invoke-WebRequest -Uri $update_service_url -Method Patch -Headers $JsonHeader -Body $enable_body -ContentType 'application/json' -UseBasicParsing
            if ($response_enable_verify.statuscode -eq 200) 
            {
                Write-Host "HTTPS certificate security is disabled."
                return $True
            }
        }
        # No HTTPS certificate resource found
        Write-Host "HTTPS certificate is not supported."
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
    finally
    {
        if ($session_key -ne "")
        {
            delete_session -ip $ip -session $session
        }
    }
}
