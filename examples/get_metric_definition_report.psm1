###
#
# Lenovo Redfish examples - Get metric inventory
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

function get_metric_definition_report
{
    <#
   .Synopsis
    Cmdlet used to get metric definition report
   .DESCRIPTION
    Cmdlet used to get metric definition report from BMC using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_metric_definition_report -ip 10.10.10.10 -username USERID -password PASSW0RD
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
    # Write-Host $ip
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
    
        # Get ServiceRoot resource
        $base_url = "https://$ip/redfish/v1/"
        $response1 = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response1.Content | ConvertFrom-Json
        $response_base_url = @{}
        $converted_object.psobject.properties | Foreach { $response_base_url[$_.Name] = $_.Value }
        
        # Get response_telemetry_service_url
        if ($response_base_url.keys -contains 'TelemetryService')
        {
            $telemetry_service_url = $response_base_url.TelemetryService.'@odata.id'
        }
        $response_telemetry_service_url = "https://$ip" + $telemetry_service_url
        $response = Invoke-WebRequest -Uri $response_telemetry_service_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
       
        # Get MetricDefinition collection
        $metric_collection_url = $hash_table.MetricDefinitions."@odata.id"
        $response_metric_collection_url = "https://$ip" + $metric_collection_url
        $response = Invoke-WebRequest -Uri $response_metric_collection_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        # Get each MetricDefinition 
        foreach ($metric_member in $hash_table.Members)
        {  
            $metric_url = $metric_member.'@odata.id'
            $metric_list = $metric_url -Split"/"

            $response_metric_url = "https://$ip" + $metric_url
            $temporary_response = Invoke-WebRequest -Uri $response_metric_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $temporary_converted_object = $temporary_response.Content | ConvertFrom-Json
            $temporary_hash_table = @{}
            $temporary_converted_object.psobject.properties | Foreach { $temporary_hash_table[$_.Name] = $_.Value }
        
            $metric_detail = @{}
           
            foreach ($property in $temporary_hash_table.Keys)
            {
                
                if ("Description","@odata.context","@odata.id","@odata.type","@odata.etag", "Links", "Actions", "RelatedItem" -notcontains $property)
                    {
                        $metric_detail[$property] = $temporary_hash_table.$property
                       
                    }
            }
            $metric_definitions=@{$metric_list[-1]=$metric_detail}
            # The output MetricDefinitions
            ConvertOutputHashTableToObject $metric_definitions | ConvertTo-Json
        }

        # Get MetricReports collection
        $response_telemetry_service_url = "https://$ip" + $telemetry_service_url
        $response_thre = Invoke-WebRequest -Uri $response_telemetry_service_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response_thre.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $metric_collection_url = $hash_table.MetricReports.'@odata.id'
        $response_metric_collection_url = "https://$ip" + $metric_collection_url

        $responset = Invoke-WebRequest -Uri $response_metric_collection_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $responset.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        # Get each MetricReport
        foreach ($metric_member in $hash_table.Members)
        {
            $metric_url = $metric_member.'@odata.id'
            $metric_list = $metric_url -Split"/"

            $response_metric_url = "https://$ip" + $metric_url
            $temporary_response = Invoke-WebRequest -Uri $response_metric_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $temporary_converted_object = $temporary_response.Content | ConvertFrom-Json
            $temporary_hash_table = @{}
            $temporary_converted_object.psobject.properties | Foreach { $temporary_hash_table[$_.Name] = $_.Value }
        
            $metric_detail = @{}
            foreach ($property in $temporary_hash_table.keys)
            {
                if ("Description","@odata.context","@odata.id","@odata.type","@odata.etag", "Links", "Actions", "RelatedItem" -notcontains $property)
                    {
                        $metric_detail[$property] = $temporary_hash_table.$property
                    }
            }
            $metric_reports=@{$metric_list[-1]=$metric_detail}
            # The output MetricReports
            ConvertOutputHashTableToObject $metric_reports | ConvertTo-Json
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