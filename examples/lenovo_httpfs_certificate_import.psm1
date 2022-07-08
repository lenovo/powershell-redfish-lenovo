###
#
# Lenovo Redfish examples - import HTTPS file server certificate to update firmware of BMC.
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

function lenovo_httpfs_certificate_import
{
   <#
   .Synopsis
    Cmdlet used to import HTTPS file server certificate to update firmware of BMC.
   .DESCRIPTION
    Cmdlet used to import HTTPS file server certificate to update firmware of BMC using Redfish API. 
    Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - certfile: certificate file by user specified.
   .EXAMPLE
    lenovo_httpfs_certificate_import -ip 10.10.10.10 -username USERID -password PASSW0RD -certfile CERTFILE_NAME
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
        [Parameter(Mandatory=$True, HelpMessage='An file that contains signed certificate in PEM format. Note: SR635/SR655 does not support uploading HTTPS file server certificate.')]
        [string]$certfile=""
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

         #check file path
        if (-not (Test-Path $certfile))
        {
            Write-Host
            [String]::Format("Specified file {0} does not exist or can't be accessed. Please check your certificate file path.", $certfile)
            return $False
        }

        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $JsonHeader = @{"X-Auth-Token" = $session_key}

        # Get the base url via Invoke-WebRequest
        $base_response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert base response content to hash table
        $base_converted_object = $base_response.Content | ConvertFrom-Json
        $base_hash_table = @{}
        $base_converted_object.psobject.properties | ForEach { $base_hash_table[$_.Name] = $_.Value }

        # Use standard API /redfish/v1/UpdateService/RemoteServerCertificates
        if ($base_hash_table.keys -contains "UpdateService")
        {
            $update_service_url = "https://$ip"+$base_hash_table.UpdateService.'@odata.id'
            # Get the UpdateService url via Invoke-WebRequest
            $response_update_service = Invoke-WebRequest -Uri $update_service_url -Headers $JsonHeader -Method Get -UseBasicParsing
            
            # Convert response_update_service content to hash table
            $converted_update_service_object = $response_update_service.Content | ConvertFrom-Json
            $update_service_hash_table = @{}
            $converted_update_service_object.psobject.properties | ForEach { $update_service_hash_table[$_.Name] = $_.Value }

            if ($update_service_hash_table.keys -contains "RemoteServerCertificates")
            {
                # Set request body
                $request_body = @{}
                $request_body['CertificateType'] = "PEM"
                
                $cert_content = read_cert_file_pem($certfile)
                if ($null -eq $cert_content)
                {
                    Write-Host
                    [String]::Format("Target server required certificate format should be PEM. Please specify correct certificate file.")
                    return $False
                }
                $str_cert = ""
                foreach($i in $cert_content)
                {
                    $str_cert += $i
                    $str_cert += "`n"
                }
                $request_body['CertificateString'] = $str_cert

                $request_upload_url = "https://$ip" + $update_service_hash_table.RemoteServerCertificates.'@odata.id'

                $request_json_body = $request_body | ConvertTo-json
                
                # Perform action #RemoteServerCertificates
                $request_response = Invoke-WebRequest -Uri $request_upload_url -Method Post -Headers $JsonHeader -Body $request_json_body -ContentType 'application/json'
                
                $converted_request_response_object = $request_response.Content | ConvertFrom-Json
                
                if ($request_response.StatusCode -eq 201)
                {
                    Write-Host
                    [String]::Format("- PASS, Upload certificate successfully. The file server certificate has been uploaded to {0}.", $converted_request_response_object.'@odata.id')
                    return $True
                }
            }
        }
        
        # No https file server certificate resource found
        return "Target server does not support uploading certificate file."
    }
    catch
    {
        # Handle http exception response
        if($_.Exception.Response)
        {
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            if ($_.Exception.Response.StatusCode.Value__ -eq 409)
            {
                Write-Host "Error message: The current number of certificates in the target certificate collection already reached the maximum number: 4."
            }
            elseif ($_.Exception.Response.StatusCode.Value__ -eq 401)
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
    
function read_cert_file_pem 
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$pem_certfile=""
    )
    
    try
    {
        $content = Get-Content $pem_certfile
    }
    catch
    {
        # Handle system exception response
        $content = ""
        if($_.Exception)
        {
            Write-Host "Error message:" $_.Exception.Message
            Write-Host "Please check arguments or server status."
        }
    }
    
    if ($content -contains '-----BEGIN CERTIFICATE-----')
    {
        return $content
    }
    else 
    {
        return $null
    }
}