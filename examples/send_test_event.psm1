###
#
# Lenovo Redfish examples - Send test event
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


function send_test_event
{
    <#
   .Synopsis
    Cmdlet used to Send test event
   .DESCRIPTION
    Cmdlet used to Send test event from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    
    optional parameter: you can only use one option [destination/all/id] 
    - destination: Pass in the destination ip/servername you want to delete
    - all: Delete all subscriptions
    - id: Pass in the subscription id you want to delete
   .EXAMPLE
    send_test_event -ip 10.10.10.10 -username USERID -password PASSW0RD -eventid 40000001 -message 'test event' -severity OK
   #>
   
    param
    (
    [Parameter(Mandatory=$False)]
    [string]$eventid = "40000001",
    [Parameter(Mandatory=$False)]
    [string]$message = "test event",
    [ValidateSet("OK","Warning","Critical")]
    [Parameter(Mandatory=$False)]
    [string]$severity = "OK",
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

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key}
    
        # Get the base url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json
        $event_service_url = $converted_object.EventService."@odata.id"
        $registries_url = "https://$ip" + $converted_object.Registries."@odata.id"
        $response = Invoke-WebRequest -Uri $registries_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $response_registries_url =$response.Content | ConvertFrom-Json
        $messageid_name = $response_registries_url."Members@odata.count"
        
        #Get event url resource
        $event_url = "https://$ip" + $converted_object.EventService."@odata.id"
        $response = Invoke-WebRequest -Uri $event_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json
        $EventService_Version = 130
        $EventService_Type = $converted_object."@odata.type" -split "\."
        $EventService_Type = $EventService_Type[-2]

        if($EventService_Type.StartsWith("v")){
            $EventService_Version = $EventService_Type -replace 'v|_', ''
        }
        #Get send test action url
        $send_event_url = "https://$ip" + $converted_object.Actions."#EventService.SubmitTestEvent".target
        $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss+08:00'

        if($converted_object.Actions."#EventService.SubmitTestEvent" -contains "@Redfish.ActionInfo"){
            $actioninfo_url = "https://$ip" + $converted_object.Actions."#EventService.SubmitTestEvent"."@Redfish.ActionInfo"
            $response = Invoke-WebRequest -Uri $actioninfo_url -Headers $JsonHeader -Method Get -UseBasicParsing 
            $converted_object =$response.Content | ConvertFrom-Json
            if($converted_object -contains "Parameters")
            {
                foreach($parameter in $converted_object.Parameters)
                {
                    if($parameter.Name -eq "EventId"){
                        $JsonBody = @{"EventId"=$eventid}
                    }elseif($parameter.Name -eq "EventType"){
                        $JsonBody = @{"EventId"="Alert"}
                    }elseif($parameter.Name -eq "EventTimestamp"){
                        $JsonBody = @{"EventTimestamp"=$timestamp}
                    }elseif($parameter.Name -eq "Message"){
                        $JsonBody = @{"EventTimestamp"=$message}
                    }elseif($parameter.Name -eq "MessageArgs"){
                        $JsonBody = @{"EventTimestamp"=@()}
                    }elseif($parameter.Name -eq "MessageId"){
                        $JsonBody = @{"EventTimestamp"="Base.1.1.GeneralError"}
                    }elseif($parameter.Name -eq "Severity"){
                        $JsonBody = @{"Severity"=$severity}
                    }elseif($parameter.Name -eq "OriginOfCondition"){
                        $JsonBody = @{"OriginOfCondition"=$event_service_url}
                    }
                }
            }
        }
        elseif($EventService_Version -ge 160){
            $JsonBody = @{"EventId"=$eventid
                      "EventTimestamp" = $timestamp
                      "Message" = $message
                      "MessageArgs" = @()
                      "MessageId"="Base.1.1.GeneralError"
                      "OriginOfCondition"=$event_service_url}|ConvertTo-Json -Compress
        }
        elseif($EventService_Version -ge 130){
            $JsonBody = @{"EventId"=$eventid
                      "EventTimestamp" = $timestamp
                      "Message" = $message
                      "MessageArgs" = @()
                      "MessageId"="Base.1.1.GeneralError"
                      "Severity"= $severity
                      "OriginOfCondition"=$event_service_url}|ConvertTo-Json -Compress
        }
        elseif($EventService_Version -ge 106){
            $JsonBody = @{"EventId"=$eventid
                      "EventType" = "Alert"
                      "EventTimestamp" = $timestamp
                      "Message" = $message
                      "MessageArgs" = @()
                      "MessageId"="Base.1.1.GeneralError"
                      "Severity"= $severity
                      "OriginOfCondition"=$event_service_url}|ConvertTo-Json -Compress
        }
        else{
            $JsonBody = @{"EventId"=$eventid
                      "EventType" = "Alert"
                      "EventTimestamp" = $timestamp
                      "Message" = $message
                      "MessageArgs" = @()
                      "MessageId"="Base.1.1.GeneralError"
                      "Severity"= $severity}|ConvertTo-Json -Compress
        }
        for($i=0; $i -lt $messageid_name;$i++){
            $message_id = "https://$ip" + $response_registries_url.Members[$i]."@odata.id"
            $response = Invoke-WebRequest -Uri $message_id -Headers $JsonHeader -Method Get -UseBasicParsing 
            $response_message_id = $response.Content | ConvertFrom-Json
            if($response_message_id.id -contains "Base"){
                $messageid_prefix = $response_message_id."id".Substring(0, $response_message_id.Length - 1) + "Created"
                $JsonBody = @{"MessageId" = $messageid_prefix}
            }
        }
       $response = Invoke-WebRequest -Uri $send_event_url -Method Post -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
       Write-Host
                [String]::Format("- PASS, statuscode {0} returned successfully to send test event
                                   event id is{1},EventType:Alert,EventTimestamp:{2},
                                   Message:{3},MessageArgs:[],MessageId:Base.1.1.GeneralError,Severity:{4},OriginOfCondition:$event_service_url",
                                   $response.StatusCode,$eventid,$timestamp,$message,$severity)
        return $True
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
