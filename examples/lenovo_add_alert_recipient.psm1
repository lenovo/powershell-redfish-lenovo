###
#
# Lenovo Redfish examples - Add one alert recipient (Email/Syslog Recipients)
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
Import-module $PSScriptRoot\lenovo_utils.psm1

function lenovo_add_alert_recipient
{
    <#
   .Synopsis
    Cmdlet used to add alert recipient
   .DESCRIPTION
    Cmdlet used to add alert recipient from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - RecipientName: Pass in Recipient Name 
    - Address: For Syslog, IP:Port, e.g. 10.10.10.10:514. For Email, email address.
    - Enabledstate: Specify if enable to send syslog or email.
    - AlertType: Specify Syslog or Email.
    - CriticalEvents: Specify critical events you want to receive. all' means all events, or you can specify multiple events, use space to seperate them. example: event1 event2.Available events list: ['CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', 'CriticalPowerFailure', 'HardDiskDriveFailure', 'FanFailure', 'CPUFailure', 'MemoryFailure', 'HardwareIncompatibility', 'PowerRedundancyFailure', 'AllOtherCriticalEvents']
    - WarningEvents: Similar with option CriticalEvents, Available events list: ['PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', 'WarningVoltageThresholdExceeded', 'WarningPowerThresholdExceeded', 'NoncriticalFanevents','CPUinDegradedState', 'MemoryWarning', 'AllOtherWarningEvents']
    - SystemEvents: Similar with option CriticalEvents, Available events list: ['SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', 'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', 'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange', 'AllAuditEvents']
    - IncludeEventLog: Specify if need to include Event Log contents in the email body, only avaliable for AlertType Email. Default is 1.
    - Id: Pass in user Id(1~13)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_add_alert_recipient -ip 10.10.10.10 -username USERID -password PASSW0RD \
                -RecipientName example -Address 10.10.10.10:514 -Enabledstate 1 -AlertType Syslog \
                -CriticalEvents All -WarningEvents All -SystemEvents SuccessfulRemoteLogin SystemPowerSwitch
   #>

   param
    (
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True)]
        [string]$RecipientName="",
        [Parameter(Mandatory=$True)]
        [string]$Address="",
        [Parameter(Mandatory=$False)][ValidateSet(0, 1)]
        [int]$Enabledstate=1,
        [Parameter(Mandatory=$True)][ValidateSet('Syslog', 'Email')]
        [string]$AlertType="",
        [Parameter(Mandatory=$False)]
        [string]$CriticalEvents="",
        [Parameter(Mandatory=$False)]
        [string]$WarningEvents="",
        [Parameter(Mandatory=$False)]
        [string]$SystemEvents="",
        [Parameter(Mandatory=$False)][ValidateRange(1,13)]
        [int]$Id="",
        [Parameter(Mandatory=$False)][ValidateSet(0, 1)]
        [int]$IncludeEventLog=1,
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key }

        # Get ServiceBase resource
        $response_base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $response_base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        $managers_url = $hash_table.Managers.'@odata.id'
        $managers_url_string = "https://$ip"+ $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        $manager_url = $hash_table.Members[0].'@odata.id'
        $response_manager_url = "https://$ip" + $manager_url
        $response = Invoke-WebRequest -Uri $response_manager_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $Oem_hash_table = @{}
        $converted_object.psobject.properties | Foreach { $Oem_hash_table[$_.Name] = $_.Value }

        $lenovo_hash_table = @{}
        $Oem_hash_table.Oem.psobject.properties | Foreach { $lenovo_hash_table[$_.Name] = $_.Value }
        
        $recipients_hash_table = @{}
        $lenovo_hash_table.Lenovo.psobject.properties | Foreach { $recipients_hash_table[$_.Name] = $_.Value }

        # Get bmc recipients url
        if($Oem_hash_table.Keys -contains 'Oem' -and $lenovo_hash_table.keys -contains 'Lenovo' -and $recipients_hash_table.keys -contains 'Recipients')
        {
            $recipients_url = $recipients_hash_table.Recipients.'@odata.id'
        }
        else {
            Write-Host 'No support to add alert recipient.'
            return $False
        }
        $response_recipients_url = "https://$ip" + $recipients_url
        $response = Invoke-WebRequest -Uri $response_recipients_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $id_used = @()
        foreach($member in $hash_table.Members)
        {   
            $used = $member.'@odata.id' -Split"/"
            $id_used += $used[-1]
        }
        $all_critical_events = @('CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', 'CriticalPowerFailure', 
        'HardDiskDriveFailure', 'FanFailure','CPUFailure', 'MemoryFailure', 'HardwareIncompatibility', 
        'PowerRedundancyFailure', 'AllOtherCriticalEvents')
        $all_warning_events = @('PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', 'WarningVoltageThresholdExceeded', 
        'WarningPowerThresholdExceeded', 'NoncriticalFanevents','CPUinDegradedState', 'MemoryWarning', 'AllOtherWarningEvents')
        $all_system_events = @('SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', 
        'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', 
        'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange', 'AllAuditEvents')

        $setting_dict = @{}
        $setting_dict['RecipientSettings'] = @{}
        $setting_dict['RecipientSettings']['EnabledAlerts'] = @{}
        $setting_dict['RecipientSettings']['EnabledAlerts']['CriticalEvents'] = @{}
        $setting_dict['RecipientSettings']['EnabledAlerts']['WarningEvents'] = @{}
        $setting_dict['RecipientSettings']['EnabledAlerts']['SystemEvents'] = @{}

        $setting_dict["Id"] = ''
        if ($Id -ne $null)
        {
            $setting_dict["Id"] = $Id.ToString()
        }
        if ($RecipientName -ne $null) 
        {
            $setting_dict['RecipientSettings']['RecipientName'] = $RecipientName
        }
        if($Address -ne $null)
        {
            $setting_dict['RecipientSettings']['Address'] = $Address
        }
        $setting_dict["RecipientSettings"]["Enabledstate"] = $True
        if($Enabledstate -ne $null)
        {
            $setting_dict['RecipientSettings']['Enabledstate'] = [bool]$Enabledstate
        }
        $setting_dict["RecipientSettings"]["IncludeEventLog"] = $False
        if ($IncludeEventLog -ne $null -and $AlertType -eq "Email")
        {
            $setting_dict["RecipientSettings"]["IncludeEventLog"] = [bool]$IncludeEventLog
        }
        if($AlertType -ne $null)
        {
            $setting_dict['RecipientSettings']['AlertType'] = $AlertType
        }

        $setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["Enabled"] = $False
        $setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["AcceptedEvents"] = @()
        if ($CriticalEvents.Length -gt 0)
        {
            $setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["Enabled"] = $True
            if($CriticalEvents -contains 'all' -or $CriticalEvents -contains 'All')
            {
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["AcceptedEvents"] = $all_critical_events
            }
            else 
            {
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["CriticalEvents"]["AcceptedEvents"] = @($CriticalEvents)
            }
        }

        $setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["Enabled"] = $False
        $setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["AcceptedEvents"] = @()
        if ($WarningEvents.Length -gt 0)
        {
            $setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["Enabled"] = $True
            if($WarningEvents -contains 'all' -or $WarningEvents -contains 'All')
            {
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["AcceptedEvents"] = $all_warning_events
            }
            else 
            {
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["WarningEvents"]["AcceptedEvents"] = @($WarningEvents)
            }
        }

        $setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["Enabled"] = $False
        $setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = @()
        if ($SystemEvents.Length -gt 0)

        {
            $setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["Enabled"] = $True
            if($SystemEvents -contains 'all' -or $SystemEvents -contains 'All')
            {
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = $all_system_events
            }
            else 
            {
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = @($SystemEvents)
            }
        }
        
        $index_id = $setting_dict['Id']
        # if Id is not specified, find first available Id. Otherwise, check the Id specified is being used or not
        if ($index_id -eq 0)
        {
            foreach($i in 1..13)
            {
                if($id_used -notcontains $i.ToString())
                {
                    $index_id = $i.ToString()
                    break
                }
            }
            if ($index_id -eq 0)
            {
                Write-Host 'No available Id to add alert recipient.'
                return $False
            }
            $setting_dict['Id'] = $index_id 
        }
        else {
            if($id_used -contains $index_id)
            {
                [String]::Format("Id {0} has been used.",$index_id)
                return $False
            }
        }
        # POST setting info body to add one new recipient
        trap 
        {
            if($SystemEvents -contains 'all' -or $SystemEvents -contains 'All')
            {
                $all_system_events[-1] = 'AllOtherAuditEvents'
                $setting_dict["RecipientSettings"]["EnabledAlerts"]["SystemEvents"]["AcceptedEvents"] = $all_system_events
            }
            
            $JsonBody = $setting_dict | ConvertTo-Json -Depth 10
            $response = Invoke-WebRequest -Uri $response_recipients_url -Method Post -Headers $JsonHeader -Body $JsonBody
            [String]::Format("Add alert recipientsuccessfully, id is {0}.",$setting_dict['Id'])
            return $True
        }
        $JsonHeader = @{ "X-Auth-Token" = $session_key; "Content-Type"= "application/json"}
        $JsonBody = $setting_dict | ConvertTo-Json -Depth 10
        $response = Invoke-WebRequest -Uri $response_recipients_url -Method Post -Headers $JsonHeader -Body $JsonBody
        [String]::Format("Add alert recipientsuccessfully, id is {0}.",$setting_dict['Id'])
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