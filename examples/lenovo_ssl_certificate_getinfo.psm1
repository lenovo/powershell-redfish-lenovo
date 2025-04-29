###
#
# Lenovo Redfish examples - Get SSL certificate info
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

function lenovo_ssl_certificate_getinfo
{
   <#
   .Synopsis
    Cmdlet used to get SSL certificate info
   .DESCRIPTION
    Cmdlet used to get SSL certificate info from BMC using Redfish API. SSL certificate info will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_ssl_certificate_getinfo -ip 10.10.10.10 -username USERID -password PASSW0RD
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

        # Use standard API /redfish/v1/CertificateService/CertificateLocations first
        if ($base_hash_table.keys -contains "CertificateService")
        {
            $certificate_service_url_string = "https://$ip"+$base_hash_table.CertificateService.'@odata.id'
            # Get the CertificateService url via Invoke-WebRequest
            $response_certificate_service = Invoke-WebRequest -Uri $certificate_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            
            # Convert response_certificate_service content to hash table
            $converted_certificate_service_object = $response_certificate_service.Content | ConvertFrom-Json
            $certificate_service_hash_table = @{}
            $converted_certificate_service_object.psobject.properties | ForEach { $certificate_service_hash_table[$_.Name] = $_.Value }

            if ($certificate_service_hash_table.keys -contains "CertificateLocations")
            {
                $certificate_locations_url_string = "https://$ip"+$certificate_service_hash_table.CertificateLocations.'@odata.id'
                # Get the CertificateLocations url via Invoke-WebRequest
                $response_certificate_locations = Invoke-WebRequest -Uri $certificate_locations_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
                
                # Convert response_certificate_locations content to hash table
                $converted_certificate_locations_object = $response_certificate_locations.Content | ConvertFrom-Json
                $certificate_locations_hash_table = @{}
                $converted_certificate_locations_object.psobject.properties | ForEach { $certificate_locations_hash_table[$_.Name] = $_.Value }
            
                $ssl_cert_info = @{}

                if ($certificate_locations_hash_table.keys -contains "Links")
                {
                    if ($null -ne $converted_certificate_locations_object.Links.'Certificates')
                    {
                        foreach ($i in $certificate_locations_hash_table.Links.'Certificates')
                        {
                            # Get the single certificate url via Invoke-WebRequest
                            $s_certificate_url = "https://$ip" + $i.'@odata.id'
                            if (-not $s_certificate_url.contains('HTTPS'))
                            {
                                continue
                            }
                            # Get the http certificate url via Invoke-WebRequest
                            $response_http_certificate = Invoke-WebRequest -Uri $s_certificate_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    
                            # Convert response_http_certificate content to hash table
                            $converted_http_certificate_object = $response_http_certificate.Content | ConvertFrom-Json
                            $http_certificate_hash_table = @{}
                            $converted_http_certificate_object.psobject.properties | Foreach { $http_certificate_hash_table[$_.Name] = $_.Value }
                            
                            $properties = @('ValidNotAfter', 'ValidNotBefore', 'KeyUsage', 'CertificateType', 'Subject', 'CertificateString', 'Issuer')
                            foreach($item_name in $properties)
                            {
                                if ($http_certificate_hash_table.keys -contains $item_name)
                                {
                                    $ssl_cert_info[$item_name] = $converted_http_certificate_object.$item_name
                                }
                            }
                            break
                        }
                    }
                }
                $ssl_cert_info | ConvertTo-Json -Depth 10
                return $True
            }
        }

        # Use Oem API /redfish/v1/Managers/1/Oem/Lenovo/Security
        $managers_url = "https://$ip"+$base_hash_table.Managers.'@odata.id'

        # Get the managers url(/redfish/v1/Managers) via Invoke-WebRequest
        $response_managers_url = Invoke-WebRequest -Uri $managers_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_managers_url content to hash table
        $converted_managers_object = $response_managers_url.Content | ConvertFrom-Json
        $managers_hash_table = @{}
        $converted_managers_object.psobject.properties | Foreach { $managers_hash_table[$_.Name] = $_.Value }

        foreach ($i in $managers_hash_table.Members)
        {
            # Access /redfish/v1/Managers/1
            $s_manager_url = "https://$ip" + $i.'@odata.id'

            # Get the single manager url(/redfish/v1/Managers/1) via Invoke-WebRequest
            $response_s_manager_url = Invoke-WebRequest -Uri $s_manager_url -Headers $JsonHeader -Method Get -UseBasicParsing

            # Convert response_s_manager_url content to hash table
            $converted_s_manager_object = $response_s_manager_url.Content | ConvertFrom-Json
            $s_manager_hash_table = @{}
            $converted_s_manager_object.psobject.properties | Foreach { $s_manager_hash_table[$_.Name] = $_.Value }

            # Check /redfish/v1/Managers/1/Oem/Lenovo/Security existing
            if ($s_manager_hash_table.keys -notcontains "Oem")
            {
                continue
            }
            if ($null -eq $converted_s_manager_object.Oem.'Lenovo')
            {
                continue
            }
            if ($null -eq $converted_s_manager_object.Oem.'Lenovo'.'Security')
            {
                continue
            }
            if ($null -eq $converted_s_manager_object.Oem.'Lenovo'.'Security'.'@odata.id')
            {
                continue
            }

            # Access /redfish/v1/Managers/1/Oem/Lenovo/Security
            $security_url = "https://$ip"+$s_manager_hash_table.Oem.'Lenovo'.'Security'.'@odata.id'

            # Get the security_url via Invoke-WebRequest
            $response_security_url = Invoke-WebRequest -Uri $security_url -Headers $JsonHeader -Method Get -UseBasicParsing
    
            # Convert response_security_url content to hash table
            $converted_security_object = $response_security_url.Content | ConvertFrom-Json
            $security_hash_table = @{}
            $converted_security_object.psobject.properties | Foreach { $security_hash_table[$_.Name] = $_.Value }
            if ($security_hash_table.keys -notcontains "PublicKeyCertificates")
            {
                continue
            }
            $ssl_cert_info = @{}
            $ssl_cert_info["EnableHttps"] = $True
            $ssl_cert_info["PublicKeyCertificates"] = @{}
            $ssl_cert_info["CertificateSigningRequests"] = @{}
            if ($security_hash_table.keys -contains "SSLSettings")
            {
                if ($null -ne $security_hash_table.SSLSettings.'EnableHttps')
                {
                    $ssl_cert_info["EnableHttps"] = $converted_security_object.SSLSettings.'EnableHttps'
                }
            }
            if ($security_hash_table.keys -contains "PublicKeyCertificates")
            {
                if ($null -ne $converted_security_object.PublicKeyCertificates)
                {
                    foreach ($cert in $security_hash_table.'PublicKeyCertificates')
                    {
                        if ($cert.keys -contains "Subject")
                        {
                            if ($cert['Subject'] -eq 'Server_Cert')
                            {
                                $propertys = @('Subject', 'AltSubject', 'Expire', 'PublicKey')
                                foreach ($property in $propertys)
                                {
                                    if ($cert.keys -contains $property)
                                    {
                                        $ssl_cert_info["PublicKeyCertificates"][$property] = $cert[$property]
                                    }
                                    else
                                    {
                                        $ssl_cert_info["PublicKeyCertificates"][$property] = $null
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ($security_hash_table.keys -contains "CertificateSigningRequests")
            {
                if ($null -ne $converted_security_object.CertificateSigningRequests)
                {
                    foreach ($certcsr in $security_hash_table.'CertificateSigningRequests')
                    {          
                        $propertys = @('Subject', 'AltSubject', 'UnstructuredName', 'ChallengePassword')
                        foreach ($property in $propertys)
                        {
                            if ($certcsr.keys -contains $property)
                            {
                                $ssl_cert_info["CertificateSigningRequests"][$property] = $certcsr[$property]
                            }
                            else
                            {
                                $ssl_cert_info["CertificateSigningRequests"][$property] = $null
                            }
                        }                           
                    }
                }
            }
            
            $ssl_cert_info | ConvertTo-Json -Depth 10
            return $True
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
    
