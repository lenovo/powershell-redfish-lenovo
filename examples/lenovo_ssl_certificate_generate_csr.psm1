###
#
# Lenovo Redfish examples - generate ssl certificate CSR(certificate signing request)
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

function lenovo_ssl_certificate_generate_csr
{
   <#
   .Synopsis
    Cmdlet used to generate ssl certificate CSR(certificate signing request). The type of the CSR only support PEM.
   .DESCRIPTION
    Cmdlet used to generate ssl certificate CSR(certificate signing request) using Redfish API. 
    Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - Country: Country Name for CSR
    - StateOrProvince: State or Province Name for CSR
    - Locality: City or Locality Name for CSR
    - Organization: Organization Name for CSR
    - HostName: Host Name for CSR
   .EXAMPLE
    lenovo_ssl_certificate_generate_csr -ip 10.10.10.10 -username USERID -password PASSW0RD 
    -Country CN -StateOrProvince NC -Locality BeiJing -Organization Lenovo -HostName ThinkSystem_SR635_SR655
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
        [Parameter(Mandatory=$True, HelpMessage='The Country name for required SSL certificate information. (e.g. CN, US, JP, AU)')]
        [string]$Country="",
        [Parameter(Mandatory=$True, HelpMessage='The State or Province name for required SSL certificate information.')]
        [string]$StateOrProvince="",
        [Parameter(Mandatory=$True, HelpMessage='The City or Locality name for required SSL certificate information.')]
        [string]$Locality="",
        [Parameter(Mandatory=$True, HelpMessage='The Organization name for required SSL certificate information.')]
        [string]$Organization="",
        [Parameter(Mandatory=$True, HelpMessage='The BMC Host name or IP for required SSL certificate information.')]
        [string]$HostName=""
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

        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

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
                if ($null -ne $converted_certificate_service_object.Actions.'#CertificateService.GenerateCSR')
                {
                    $target_url = "https://$ip"+$converted_certificate_service_object.Actions.'#CertificateService.GenerateCSR'.'target'
                    $request_body = @{}
                    $request_body['CertificateCollection'] = @{}
                    $request_body['CertificateCollection']['@odata.id'] = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'
                    $request_body['KeyUsage'] = @('DigitalSignature')
                    $request_body['Country'] = $Country
                    $request_body['City'] = $Locality
                    $request_body['CommonName'] = $HostName
                    $request_body['State'] = $StateOrProvince
                    $request_body['Organization'] = $Organization

                    $request_json_body = $request_body | ConvertTo-Json

                    # Perform action #CertificateService.GenerateCSR
                    $request_response = Invoke-WebRequest -Uri $target_url -Method Post -Headers $JsonHeader -Body $request_json_body -ContentType 'application/json'
                    if (@(200, 201, 202, 204) -notcontains $request_response.StatusCode)
                    {
                        Write-Host
                        [String]::Format("- FAILED, statuscode {0} returned failed to generate ssl certificate CSR.", $request_response.StatusCode)
                        return $False
                    }
                    # Convert request_response content to hash table
                    $converted_request_response_object = $request_response.Content | ConvertFrom-Json
                    $request_response_hash_table = @{}
                    $converted_request_response_object.psobject.properties | ForEach { $request_response_hash_table[$_.Name] = $_.Value }

                    # Save received csr string
                    $filename = 'generated_' + $HostName + '_ssl_certificate' + '.csr'
                    if (Test-Path $filename)
                    {
                        Remove-Item -Path $filename
                    }
                    if ($request_response_hash_table.keys -contains 'CSRString')
                    {
                        Set-Content $filename $converted_request_response_object.CSRString
                    }
                    
                    Write-Host
                    [String]::Format("- PASS, The CSR for SSL certificate has been generated successfully. Format is PEM. ({0})", $filename)
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
    
