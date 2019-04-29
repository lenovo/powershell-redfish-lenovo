###
#
# Lenovo Redfish examples - Export FFDC data
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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
function lenovo_export_ffdc_data
{
   <#
   .Synopsis
    Cmdlet used to export ffdc data
   .DESCRIPTION
    Cmdlet used to export ffdc data using Redfish API, If no file server is specified, it will be downloaded current directory
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - exporturi: The format of ExportURI must be "sftp://…" or "tftp://… ".(If the user needs to download the FFDC data to the local, these parameters are not required
    - sftpuser: Specify sftp username if you specify sftp uri
    - sftppwd: Specify sftp password if you sprcify sftp uri
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_export_ffdc_data -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        [Parameter(Mandatory=$False, HelpMessage='The format of ExportURI must be "sftp://…" or "tftp://… ".(If the user needs to download the FFDC data to the local, these parameters are not required.)')]
        [string]$exporturi="",
        [Parameter(Mandatory=$False, HelpMessage='Specify sftp username if you specify sftp uri.')]
        [string]$sftpuser="",
        [Parameter(Mandatory=$False, HelpMessage='Specify sftp password if you sprcify sftp uri.')]
        [string]$sftppwd=""
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

        $JsonHeader = @{"X-Auth-Token" = $session_key}
    
        # Get the manager url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        
        $managers_url = $converted_object.Managers."@odata.id"
        $managers_url_string = "https://$ip" + $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing 
    
        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        # Set the $manager_url_collection
        foreach ($i in $hash_table.Members)
        {
            $i = [string]$i
            $manager_url_string = ($i.Split("=")[1].Replace("}",""))
            $manager_url_collection += $manager_url_string
        }

        # Loop all Manager resource instance in $manager_url_collection
        foreach ($manager_url_string in $manager_url_collection)
        {
        
            # Get servicedata uri from the Manager resource instance
            $uri_address_manager = "https://$ip"+$manager_url_string
            # $uri_address_manager
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $uri_service_data ="https://$ip"+$converted_object.Oem.Lenovo.ServiceData.'@odata.id'
            # Get servicedata uri response
            $response = Invoke-WebRequest -Uri $uri_service_data -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $uri_ffdc_data = "https://$ip" + $converted_object.'Actions'.'#LenovoServiceData.ExportFFDCData'.'target'

            $body = @{}
            # Build request body and send requests to get ffdc data
            $body."InitializationNeeded" = $true
            $body."DataCollectionType" = "ProcessorDump"
            
            # Resolve user-specified parameters
            if($exporturi -ne "")
            {
                $body.ExportURI = $exporturi
                $protocol = $body.ExportURI.Split(":")[0]
                
                # Get the user specified sftp username and password when the protocol is sftp
                if(("sftp", "tftp") -contains $protocol)
                {
                    if("sftp" -eq $protocol)
                    {
                        if(($sftpuser -eq "") -or ($sftppwd -eq ""))
                        {
                            Write-Host "When the protocol is sftp, must be specify the sftp username and password."
                            return $false
                        }
                        else
                        {
                            $body."Username" = $sftpuser
                            $body."Password" = $sftppwd
                        }
                    }
                }
                else
                {
                    Write-Host "Please check the parameter ExportURI, the format of ExportURI must be 'sftp://...' or 'tftp://...'"
                    return $False
                }
            }
           
            $start = Get-Date
            $json_body = $body | convertto-json
            try
            {
                $response = Invoke-WebRequest -Uri $uri_ffdc_data -Headers $JsonHeader -Method Post  -Body $json_body -ContentType 'application/json' -UseBasicParsing
                # The system will create a task to let user know the transfer progress and return a download URI
                if ($response.StatusCode -eq 202)
                {
                    $converted_object = $response.Content | ConvertFrom-Json
                    $task_uri = "https://$ip" + $converted_object.'@odata.id'
                    $task_state = ""
                    while($task_state -ne "Completed")
                    {
                        $response = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Get -UseBasicParsing
                        $converted_object = $response.Content | ConvertFrom-Json
                        $task_state = $converted_object.TaskState
                        Start-Sleep -Seconds 10
                    }

                    $response = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response.Content | ConvertFrom-Json
                    $hash_table = @{}
                    $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

                    # Download the FFDC data to locally
                    if($hash_table.keys -contains "Oem")
                    {
                        $download_uri = "https://$ip" + $converted_object.Oem.Lenovo.FFDCForDownloading.Path
                        $ffdc_file_name = $download_uri.Split('/')[-1]
                        $response = Invoke-WebRequest -Uri $download_uri -Headers $JsonHeader -UseBasicParsing -OutFile $ffdc_file_name
                        $end = Get-Date
                        $run_time = "{0:0.00}" -f ($end - $start).TotalSeconds
                        Write-Host -ForegroundColor Red ('Total Runtime: ' + $run_time)
                        [String]::Format("-PASS, statuscode {0}, The export ffdc data is saved as {1}", $response.StatusCode, $ffdc_file_name)
                    }
                    else
                    {
                        $end = Get-Date
                        $run_time = "{0:0.00}" -f ($end - $start).TotalSeconds
                        Write-Host -ForegroundColor Red ('Total Runtime: ' + $run_time)
                        [String]::Format("-PASS, statuscode {0}, The export ffdc data is saved as {1}", $response.StatusCode, $exporturi)
                    }
                    # Delete the task when the taskstate is completed
                    $response = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Delete -UseBasicParsing
                    return $true
                }
            }
        
        catch
        {
            # Handle http exception response for Post request
            if ($_.Exception.Response)
            {
                Write-Host "Error occured, status code:" $_.Exception.Response.StatusCode.Value__
                if($_.ErrorDetails.Message)
                {
                    $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                    $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                    Write-Host "Error message:" $response_j.Resolution
                }
            }
            # Handle system exception response for Post request
            elseif($_.Exception)
            {
                Write-Host "Error message:" $_.Exception.Message
                Write-Host "Please check arguments or server status."
            }
            return $False
        }
        }
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