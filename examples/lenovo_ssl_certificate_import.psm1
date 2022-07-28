###
#
# Lenovo Redfish examples - import ssl certificate that is signed via CA by CSR(certificate signing request)
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

function read_cert_file_pem {
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

function lenovo_ssl_certificate_import
{
   <#
   .Synopsis
    Cmdlet used to import ssl certificate that is signed via CA by CSR(certificate signing request). The type of the CSR only support PEM.
   .DESCRIPTION
    Cmdlet used to import ssl certificate that is signed via CA by CSR(certificate signing request) using Redfish API. 
    Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - certfile: certificate file by user specified.
   .EXAMPLE
    lenovo_ssl_certificate_import -ip 10.10.10.10 -username USERID -password PASSW0RD -certfile CERTFILE_NAME
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
        [Parameter(Mandatory=$True, HelpMessage='An file that contains signed certificate in PEM format. Note that the certificate being imported must have been created from the Certificate Signing Request most recently created.')]
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

        # Use standard API /redfish/v1/CertificateService/CertificateLocations
        if ($base_hash_table.keys -contains "CertificateService")
        {
            $certificate_service_url_string = "https://$ip"+$base_hash_table.CertificateService.'@odata.id'
            # Get the CertificateService url via Invoke-WebRequest
            $response_certificate_service = Invoke-WebRequest -Uri $certificate_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            
            # Convert response_certificate_service content to hash table
            $converted_certificate_service_object = $response_certificate_service.Content | ConvertFrom-Json
            $certificate_service_hash_table = @{}
            $converted_certificate_service_object.psobject.properties | ForEach { $certificate_service_hash_table[$_.Name] = $_.Value }

            if ($certificate_service_hash_table.keys -contains "Actions")
            {
                if ($null -ne $converted_certificate_service_object.Actions.'#CertificateService.ReplaceCertificate')
                {
                    $target_url = "https://$ip"+$converted_certificate_service_object.Actions.'#CertificateService.ReplaceCertificate'.'target'
                    
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

                    # Get https certificate uri to set request body
                    $https_cert_url = $null
                    if ($certificate_service_hash_table.keys -contains "CertificateLocations")
                    {
                        $certificate_locations_url_string = "https://$ip"+$certificate_service_hash_table.CertificateLocations.'@odata.id'
                        # Get the CertificateLocations url via Invoke-WebRequest
                        $response_certificate_locations = Invoke-WebRequest -Uri $certificate_locations_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
                        
                        # Convert response_certificate_locations content to hash table
                        $converted_certificate_locations_object = $response_certificate_locations.Content | ConvertFrom-Json
                        $certificate_locations_hash_table = @{}
                        $converted_certificate_locations_object.psobject.properties | ForEach { $certificate_locations_hash_table[$_.Name] = $_.Value }

                        if ($certificate_locations_hash_table.keys -contains "Links")
                        {
                            if ($null -ne $converted_certificate_locations_object.Links.'Certificates')
                            {
                                foreach ($i in $certificate_locations_hash_table.Links.'Certificates')
                                {
                                    # Get the single certificate url via Invoke-WebRequest
                                    $s_certificate_url = $i.'@odata.id'
                                    if (-not $s_certificate_url.contains('HTTPS'))
                                    {
                                        continue
                                    }
                                    $https_cert_url = $s_certificate_url
                                    break
                                }
                            }
                        }
                    }
                    if ($https_cert_url -eq $null)
                    {
                        $https_cert_url = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1'
                    }
                    $request_body['CertificateUri'] = @{}
                    $request_body['CertificateUri']['@odata.id'] = $https_cert_url

                    $request_json_body = $request_body | ConvertTo-json
                    
                    # Perform action #CertificateService.ReplaceCertificate
                    $request_response = Invoke-WebRequest -Uri $target_url -Method Post -Headers $JsonHeader -Body $request_json_body -ContentType 'application/json'
                    if (@(200, 201, 202, 204) -notcontains $request_response.StatusCode)
                    {
                        Write-Host
                        [String]::Format("- FAILED, statuscode {0} returned failed to import SSL certificate CSR.", $request_response.StatusCode)
                        return $False
                    }
                    
                    Write-Host
                    [String]::Format("- PASS, The SSL certificate has been imported successfully.")
                    return $True
                }
            }
        }
        
        # No SSL certificate resource found
        return "SSL certificate is not supported"
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
    
