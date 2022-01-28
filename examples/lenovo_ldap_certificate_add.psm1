###
#
# Lenovo Redfish examples - add/import LDAP certificate to BMC (Note: Need to restart BMC to activate it)
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

function read_cert_file_der{
    param (
        [Parameter(Mandatory=$true)]
        [string]$der_certfile=""
    )
    
    try
    {
        $list = @()
        $content = Get-Content $der_certfile -Encoding byte
        foreach($i in $content)
        {
            $list += $i
        }
    }
    catch
    {
        # Handle system exception response
        $list = @()
        if($_.Exception)
        {
            Write-Host "Error message:" $_.Exception.Message
            Write-Host "Please check arguments or server status."
        }
    }
    return $list
}

function lenovo_ldap_certificate_add
{
   <#
   .Synopsis
    Cmdlet used to add/import LDAP certificate to BMC (Note: Need to restart BMC to activate it)
   .DESCRIPTION
    Cmdlet used to add/import LDAP certificate to BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - certfile: certificate file by user specified. Format should be DER or PEM depending on target server's requirement
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_ldap_certificate_add -ip 10.10.10.10 -username USERID -password PASSW0RD -certfile xxx.pem
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$certfile="",
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
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert base response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $base_hash_table = @{}
        $converted_object.psobject.properties | ForEach { $base_hash_table[$_.Name] = $_.Value }

        $flag_SR635_SR655 = $False

        # Use standard API /redfish/v1/AccountService/LDAP/Certificates first

        # Get the AccountService url via Invoke-WebRequest
        $account_service_url_string = "https://$ip"+$base_hash_table.AccountService.'@odata.id'
        $response_account_service = Invoke-WebRequest -Uri $account_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_service content to hash table
        $converted_account_service_object = $response_account_service.Content | ConvertFrom-Json
        
        if ($null -ne $converted_account_service_object.LDAP)
        {
            if ($null -ne $converted_account_service_object.LDAP.'Certificates')
            {
                if ($null -ne $converted_account_service_object.LDAP.'Certificates'.'@odata.id')
                {
                    $request_url = "https://$ip" + $converted_account_service_object.LDAP.'Certificates'.'@odata.id'
                    $request_body = @{}
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
                    $request_body['CertificateType'] = 'PEM'
                    $json_body = $request_body | ConvertTo-Json

                    # Perform post to add the certificate
                    $response = Invoke-WebRequest -Uri $request_url -Method Post -Headers $JsonHeader -Body $json_body -ContentType 'application/json'
                    Write-Host
                    [String]::Format("- PASS, statuscode {0} returned successfully to add certificate.",$response.StatusCode)
                    return $True
                }
            }
        }
        if ($null -ne $converted_account_service_object.Oem)
        {
            if ($null -ne $converted_account_service_object.Oem.'Ami')
            {
                $flag_SR635_SR655 = $True
            }
        }

        # Add(import) certificate for SR635/SR655 using standard API with some oem properties
        if ($flag_SR635_SR655)
        {
            $request_url = "https://$ip" + '/redfish/v1/Managers/Self/RemoteAccountService/LDAP/Certificates'
            $request_body = @{}
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
            $request_body['CertificateType'] = 'PEM'
            $request_body['Oem'] = @{}
            $request_body['Oem']['Ami'] = @{}
            $request_body['Oem']['Ami']['CACert'] = $True
            $json_body = $request_body | ConvertTo-Json

            # Perform post to add the certificate
            try
            {
                $response = Invoke-WebRequest -Uri $request_url -Method Post -Headers $JsonHeader -Body $json_body -ContentType 'application/json'
            }
            catch
            {
                # Handle http exception response
                if($_.Exception.Response)
                {
                    if ($_.Exception.Response.StatusCode.Value__ -eq 401)
                    {
                        Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
                        Write-Host "Error message: You are required to log on Web Server with valid credentials first."
                    }
                    elseif ($_.ErrorDetails.Message)
                    {
                        $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                        $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                        
                        # Use ReplaceCertificate action URI
                        $replace_url = '/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate'
                        if (-not $response_j.Resolution.Contains($replace_url))
                        {
                            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
                            Write-Host "Error message:" $response_j.Resolution
                            return $False
                        }

                        # Get the Certificates url via Invoke-WebRequest
                        $certificates_response = Invoke-WebRequest -Uri $request_url -Headers $JsonHeader -Method Get -UseBasicParsing

                        # Convert certificates_response content to hash table
                        $converted_certificates_object = $certificates_response.Content | ConvertFrom-Json
                        $certificates_hash_table = @{}
                        $converted_certificates_object.psobject.properties | ForEach { $certificates_hash_table[$_.Name] = $_.Value }
                        $CertificateUri = ""
                        if ($null -ne $converted_certificates_object.Members)
                        {
                            foreach ($i in $certificates_hash_table.Members)
                            {
                                $CertificateUri = $i.'@odata.id'
                                break
                            }
                        }
                        $replace_request_url = "https://$ip" + $replace_url
                        $replace_request_body = @{}
                        $replace_request_body['CertificateString'] = $str_cert
                        $replace_request_body['CertificateType'] = 'PEM'
                        $replace_request_body['CertificateUri'] = @{}
                        $replace_request_body['CertificateUri']['@odata.id'] = $CertificateUri

                        $replace_json_body = $replace_request_body | ConvertTo-Json

                        $replace_response = Invoke-WebRequest -Uri $replace_request_url -Method Post -Headers $JsonHeader -Body $replace_json_body -ContentType 'application/json'
                        Write-Host
                        [String]::Format("- PASS, statuscode {0} returned successfully to add certificate.",$replace_response.StatusCode)
                        return $True
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
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to add certificate.",$response.StatusCode)
            return $True
        }

        # No LDAP certificate resource found
        return "LDAP certificate is not supported"
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
    
