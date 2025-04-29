###
#
# Lenovo Redfish examples - delete HTTPS file server certificate
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

function lenovo_httpfs_certificate_delete
{
   <#
   .Synopsis
    Cmdlet used to delete HTTPS file server certificate.
   .DESCRIPTION
    Cmdlet used to delete HTTPS file server certificate using Redfish API. 
    Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - cert_id: The certificate ID by user specified
   .EXAMPLE
    lenovo_httpfs_certificate_delete -ip 10.10.10.10 -username USERID -password PASSW0RD -cert_id ID
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
        [Parameter(Mandatory=$True)]
        [string]$cert_id=""
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
                $remote_cert_url = "https://$ip" + $update_service_hash_table.RemoteServerCertificates.'@odata.id'
                # Get the remote_cert_url via Invoke-WebRequest
                $response_remote_cert = Invoke-WebRequest -Uri $remote_cert_url -Headers $JsonHeader -Method Get -UseBasicParsing
                
                # Convert response_remote_cert content to hash table
                $converted_remote_cert_object = $response_remote_cert.Content | ConvertFrom-Json
                $remote_cert_hash_table = @{}
                $converted_remote_cert_object.psobject.properties | ForEach { $remote_cert_hash_table[$_.Name] = $_.Value }

                $request_delete_url = $remote_cert_url + "/" + $cert_id
                if ($remote_cert_hash_table.keys -contains "Members" -and $remote_cert_hash_table.keys -contains "Members@odata.count")
                {
                    if ($remote_cert_hash_table.'Members@odata.count' -le 0)
                    {
                        return "No HTTP file server certificates present, no need to delete."
                    }
                    ForEach ($mem in $remote_cert_hash_table.Members)
                    {
                        $mem_url = "https://$ip" + $mem.'@odata.id'
                        if ($request_delete_url -eq $mem_url)
                        {
                            # Perform action delete
                            $request_response = Invoke-WebRequest -Uri $request_delete_url -Method Delete -Headers $JsonHeader -ContentType 'application/json'
                            if ($request_response.StatusCode -eq 204)
                            {
                                Write-Host
                                [String]::Format("- PASS, Delete certificate {0} successfully.", $mem.'@odata.id')
                                return $True
                            }
                        }
                    }
                    return "Failed to delete the certificate. The specified certificate does not exist."
                }
            }
        }
        # No https file server certificate resource found
        return "HTTPS file server certificate is not supported"
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
    
