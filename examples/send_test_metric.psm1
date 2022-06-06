###
#
# Lenovo Redfish examples - Send Test Metric Report
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


function send_test_metric
{
    <#
   .Synopsis
    Cmdlet used to send test metric report
   .DESCRIPTION
    Cmdlet used to send test metric report using Redfish API. Send result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - reportname: The MetricReportName you want to send
   .EXAMPLE
    send_test_metric -ip 10.10.10.10 -username USERID -password PASSW0RD -reportname CPUTemp
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
        [string]$config_file="config.ini",
        [Parameter(Mandatory=$True, HelpMessage="The MetricReportName you want to send, such as CPUTemp,InletAirTemp,PowerMetrics,PowerSupplyStats")]
        [string]$reportname="CPUTemp"
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

        # Build headers with sesison key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key }
    
        # Get the TelemetryService resource
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        
        $telemetry_service_url = $converted_object.TelemetryService."@odata.id"
        $telemetry_service_uri = "https://$ip" + $telemetry_service_url
        $response = Invoke-WebRequest -Uri $telemetry_service_uri -Headers $JsonHeader -Method Get -UseBasicParsing        
        $converted_object = $response.Content | ConvertFrom-Json

        # Get SummitTestMetricReport URI
        $summit_test_metric_url = $converted_object.Actions.'#TelemetryService.SubmitTestMetricReport'.'target'
        $summit_test_metric_uri = "https://$ip" + $summit_test_metric_url

        # Get MetricReports collection
        $metric_collection_url = $converted_object.MetricReports.'@odata.id'
        $metric_collection_uri = "https://$ip" + $metric_collection_url
        $response = Invoke-WebRequest -Uri $metric_collection_uri -Headers $JsonHeader -Method Get -UseBasicParsing        
        $converted_object = $response.Content | ConvertFrom-Json

        # Get each MetricReport
        $flag_found = $False
        $metric_reportname_list = @()
        $GeneratedMetricReportValues = @()
        foreach($metric_member in $converted_object.Members)
        {
            $metric_name = $metric_member."@odata.id".split('/')[-1]
            $metric_reportname_list += $metric_name
            if($reportname -eq $metric_name)
            {
                $flag_found = $True
                break
            }
        } 

        if($flag_found -eq $False)
        {
            Write-Host "Invalid reportname. Allowable reportname list:[" $metric_reportname_list "]"
            return $False
        }  

        # Set default MetricReportValues
        $metric_value_obj = @{}
        $metric_value_obj["MetricProperty"] = ""
        $metric_value_obj["Timestamp"] = Get-Date -Format 'yyyy-M-dTH:m:s+00:00'
        $metric_value_obj["MetricValue"] = "0"
        $GeneratedMetricReportValues += $metric_value_obj
        
        # POST the metric test report 
        $JsonHeader["If-match"] = "*"
        $JsonBody = @{ 
                "MetricReportName" = $reportname
                "GeneratedMetricReportValues" = $GeneratedMetricReportValues
                } | ConvertTo-Json -Compress
            
        $response = Invoke-WebRequest -Uri $summit_test_metric_uri -Headers $JsonHeader -Method Post -Body $JsonBody -ContentType 'application/json' 
        if($response.StatusCode -in @(200,204))
        {
            Write-Host "Send Test Metric successsfully, Metric data: " $JsonBody
            return $True
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
