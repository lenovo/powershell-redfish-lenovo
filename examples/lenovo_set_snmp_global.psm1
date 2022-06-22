###
#
# Lenovo Redfish examples - Set SNMP global information
#
# Follow below steps to configure SNMP Alert Recipients
# Step 1: Get SNMP engineid from target server as below (Ex. target server ip is 10.245.39.101)
#         lenovo_generate_snmp_engineid -ip 10.245.39.101 -username USERID -password PASSW0RD
#         "80 00 1F 88 04 58 43 43 2D 37 58 30 35 2D 4A 33 30 30 43 4B 56 4E"
# Step 2: Setup and configure your SNMP trap receiver (Ex. receiver ip is 10.245.52.18)
#         Ex. Configure your community for SNMPv1 trap as below in net-snmp's /etc/snmp/snmptrapd.conf
#         authCommunity   log,execute,net mypublic
#         Ex. Configure user info for SNMPv3 trap as below in net-snmp's /etc/snmp/snmptrapd.conf
#         createUser -e 0x80001F88045843432D375830352D4A333030434B564E USERID SHA "PASSW0RD" AES "Aa12345678"
#         Ex. Start the trap receiver after configuration as below for snmptrapd
#         #sudo snmptrapd -c /etc/snmp/snmptrapd.conf -Lo -f
# Step 3: Set SNMP global settings to enable SNMPv1/SNMPv3 traps on target server as below
#         lenovo_set_snmp_global -ip 10.245.39.101 -username USERID -password PASSW0RD -CriticalEvents all -WarningEvents all -SystemEvents all -snmpv1_community mypublic -snmpv1_trap enable -location mylocation -contact_person myperson -snmpv3_trap enable
# Step 4: Set SNMPv3 user settings on target server as below (skip this for SNMPv1 only)
#         update_bmc_user_snmpinfo -ip 10.245.39.101 -username USERID -password PASSW0RD -username USERID -authentication_protocol HMAC_SHA96 -privacy_protocol CFB128_AES128 -privacy_password Aa12345678
# Step 5: Add SNMPv1 or SNMPv3 protocol subscription on target server as below
#         Ex. Add SNMPv1 subscription
#         add_event_subscriptions -ip 10.245.39.101 -username USERID -password PASSW0RD -protocol SNMPv1 -destination 10.245.52.18
#         Ex. Add SNMPv3 subscription
#         add_event_subscriptions -ip 10.245.39.101 -username USERID -password PASSW0RD -protocol SNMPv3 -destination USERID@10.245.52.18
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

function lenovo_set_snmp_global
{
    <#
   .Synopsis
    Cmdlet used to set bios boot order
   .DESCRIPTION
    Cmdlet used to set bios boot order from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - snmpv3_agent: Enable or disable SNMPv3 agent. Note that snmpv3_agent can only be enabled with contact_person and location being set.
    - port_agent: Specify the port of SNMPv3 agent.
    - contact_person: Specify the contact person of BMC.
    - location: Specify the location of BMC.
    - snmpv1_trap: Enable or disable SNMPv1 trap. Note that snmpv1_trap can only be enabled with snmpv1_community being set.
    - snmpv3_trap: Enable or disable SNMPv3 trap.
    - port_trap: Specify the port of SNMP trap.'
    - snmpv1_community: Specify the community of SNMPv1 trap.
    - snmpv1_address: Specify the address of SNMPv1 trap.
    - CriticalEvents: Specify critical events you want to receive. 'all' means all events, 'none' means disable this, or you can specify multiple events, use space to seperate them. example: "event1 event2".
        Available events list: "['CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', 'CriticalPowerFailure', \
                 'HardDiskDriveFailure', 'FanFailure','CPUFailure', 'MemoryFailure', 'HardwareIncompatibility', \
                 'PowerRedundancyFailure', 'AllOtherCriticalEvents']"
    - WarningEvents: Similar with option CriticalEvents, 
        Available events list: "['PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', 'WarningVoltageThresholdExceeded', \
                 'WarningPowerThresholdExceeded', 'NoncriticalFanevents','CPUinDegradedState', 'MemoryWarning', \
                 'AllOtherWarningEvents']"
    - SystemEvents: Similar with option CriticalEvents, 
        Available events list: "['SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', \
                 'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', \
                 'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange']"
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_set_snmp_global -ip 10.245.39.101 -username USERID -password PASSW0RD -CriticalEvents all -WarningEvents all -SystemEvents all -snmpv1_community mypublic -snmpv1_trap enable -location mylocation -contact_person myperson -snmpv3_trap enable 
   #>
   param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)][ValidateSet('enable', 'disable')]
        [string]$snmpv3_agent="",
        [Parameter(Mandatory=$False)]
        [int]$port_agent="",
        [Parameter(Mandatory=$False)]
        [string]$contact_person="",
        [Parameter(Mandatory=$False)]
        [string]$location="",
        [Parameter(Mandatory=$False)][ValidateSet('enable', 'disable')]
        [string]$snmpv1_trap="",
        [Parameter(Mandatory=$False)][ValidateSet('enable', 'disable')]
        [string]$snmpv3_trap="",
        [Parameter(Mandatory=$False)]
        [int]$port_trap="",
        [Parameter(Mandatory=$False)]
        [string]$snmpv1_community="",
        [Parameter(Mandatory=$False)]
        [string]$snmpv1_address="",
        [Parameter(Mandatory=$False)]
        [string]$CriticalEvents="",
        [Parameter(Mandatory=$False)]
        [string]$WarningEvents="",
        [Parameter(Mandatory=$False)]
        [string]$SystemEvents="",
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

    $setting_dict = @{}
    if ($snmpv3_agent -ne "")
    {
        $setting_dict['snmpv3_agent'] = $snmpv3_agent
    }
    if($port_agent -ne "")
    {
        $setting_dict['port_agent'] = [int]$port_agent
    }
    if($contact_person -ne "")
    {
        $setting_dict['contact_person'] = $contact_person
    }
    if($location -ne "")
    {
        $setting_dict['location'] = $location
    }
    if($snmpv1_trap -ne "")
    {
        $setting_dict['snmpv1_trap'] = $snmpv1_trap
    }
    if($snmpv3_trap -ne "")
    {
        $setting_dict['snmpv3_trap'] = $snmpv3_trap
    }
    if($port_trap -ne "")
    {
        $setting_dict['port_trap'] = [int]$port_trap
    }
    if($snmpv1_community -ne "")
    {
        $setting_dict['snmpv1_community'] = $snmpv1_community
    }
    if($snmpv1_address -ne "")
    {
        $setting_dict['snmpv1_address'] = $snmpv1_address
    }
    if($CriticalEvents -ne "")
    {
        $setting_dict['CriticalEvents'] = $CriticalEvents
    }
    if($WarningEvents -ne "")
    {
        $setting_dict['WarningEvents'] = $WarningEvents
    }
    if($SystemEvents -ne '')
    {
        $setting_dict['SystemEvents'] = $SystemEvents
    }
    
    if($setting_dict.keys.Count -eq 0)
    {
        Write-Host 'No setting option is specified.'
        return $False
    }
    $alert_recipient = $null
    if ($setting_dict.keys -contains 'CriticalEvents' -or $setting_dict.keys -contains 'WarningEvents' -or $setting_dict.keys -contains 'SystemEvents')
    {
        $alert_recipient = @{}
        $all_critical_events = @('CriticalTemperatureThresholdExceeded', 'CriticalVoltageThresholdExceeded', 
        'CriticalPowerFailure', 'HardDiskDriveFailure', 'FanFailure','CPUFailure', 'MemoryFailure', 
        'HardwareIncompatibility', 'PowerRedundancyFailure', 'AllOtherCriticalEvents')
        $all_warning_events = @('PowerRedundancyWarning', 'WarningTemperatureThresholdExceeded', 
        'WarningVoltageThresholdExceeded', 'WarningPowerThresholdExceeded', 'NoncriticalFanevents',
        'CPUinDegradedState', 'MemoryWarning', 'AllOtherWarningEvents')
        $all_system_events = @('SuccessfulRemoteLogin', 'OperatingSystemTimeout', 'AllOtherEvents', 
        'SystemPowerSwitch', 'OperatingSystemBootFailure','OperatingSystemLoaderWatchdogTimeout', 
        'PredictedFailure', 'EventLog75PercentFull', 'NetworkChange')

        if($setting_dict.keys -contains 'CriticalEvents' -and ($setting_dict['CriticalEvents'] -contains 'all'))
        {
            $alert_recipient['CriticalEvents'] = @{'AcceptedEvents' = $all_critical_events; 'Enabled' = $True}
        }
        elseif($setting_dict.keys -contains 'CriticalEvents' -and ($setting_dict['CriticalEvents'] -contains 'none'))
        {
            $alert_recipient['CriticalEvents'] = @{'AcceptedEvents' = @(); 'Enabled' = $False}
        }
        elseif($setting_dict.keys -contains 'CriticalEvents')
        {
            $setting_list = @()
            $criticalevents_list = $setting_dict['CriticalEvents'].Split(' ')
            foreach($event in $criticalevents_list)
            {
                $setting_list += $event
                if($all_critical_events -notcontains $event)
                {
                    $all_critical_events_list = $all_critical_events | ConvertTo-Json
                    [String]::Format("Unknown event {0} found. Specify 'all' or 'none' or specify one or more events from AcceptedEvents list: {1}'",$event, $all_critical_events_list)
                    return $False
                }
            }
            $alert_recipient['CriticalEvents'] = @{'AcceptedEvents' = $setting_list; 'Enabled' = $True}
        }

        if($setting_dict.keys -contains 'WarningEvents' -and ($setting_dict['WarningEvents'] -contains 'all'))
        {
            $alert_recipient['WarningEvents'] = @{'AcceptedEvents' = $all_warning_events; 'Enabled' = $True}
        }
        elseif($setting_dict.keys -contains 'WarningEvents' -and ($setting_dict['WarningEvents'] -contains 'none' -or $setting_dict['WarningEvents'] -contains 'None'))
        {
            $alert_recipient['WarningEvents'] = @{'AcceptedEvents' = @(); 'Enabled' = $False}
        } 
        elseif($setting_dict.keys -contains 'WarningEvents')
        {
            $setting_list = @()
            $warningevents_list = $setting_dict['WarningEvents'].Split(' ')
            foreach($event in $warningevents_list)
            {
                $setting_list += $event
                if ($all_warning_events -notcontains $event)
                {
                    $all_warning_events_list = $all_warning_events | ConvertTo-Json
                    [String]::Format("Unknown event {0} found. Specify 'all' or 'none' or specify one or more events from AcceptedEvents list: {1}",$event, $all_warning_events_list)
                    return $False
                }
            }
            $alert_recipient['WarningEvents'] = @{'AcceptedEvents' = $setting_list; 'Enabled' = $True}
        }

        if($setting_dict.keys -contains 'SystemEvents' -and ($setting_dict['SystemEvents'] -contains 'all'))
        {
            $alert_recipient['SystemEvents'] = @{'AcceptedEvents' = $all_system_events; 'Enabled' = $True}
        }
        elseif($setting_dict.keys -contains 'SystemEvents' -and ($setting_dict['SystemEvents'] -contains 'none' -or $setting_dict['SystemEvents'] -contains 'None'))
        {
            $alert_recipient['SystemEvents'] = @{'AcceptedEvents' = @(); 'Enabled' = $False}
        } 
        elseif($setting_dict.keys -contains 'SystemEvents')
        {
            $setting_list = @()
            $systemevents_list = $setting_dict['SystemEvents'].Split(' ')
            foreach($event in $systemevents_list)
            {
                $setting_list += $event
                if ($all_system_events -notcontains $event)
                {
                    $all_system_events_list = $all_system_events | ConvertTo-Json
                    [String]::Format("Unknown event {0} found. Specify 'all' or 'none' or specify one or more events from AcceptedEvents list: {1}",$event, $all_system_events_list)
                    return $False
                }
            }
            $alert_recipient['SystemEvents'] = @{'AcceptedEvents' = $setting_list; 'Enabled' = $True}
        }
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

        # Get SNMP
        $request_url = "https://$ip/redfish/v1/Managers/1/NetworkProtocol/Oem/Lenovo/SNMP"
        $response = Invoke-WebRequest -Uri $request_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $response_url = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $response_url.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        if($response.StatusCode -eq 400)
        {
            Write-Host 'Target server does not support Oem SNMP resource'
            return $False
        }
        if($response.StatusCode -ne 200)
        {
            [String]::Format("Url '{0}' response Error code {1}", $request_url, $hash_table.StatusCode)
            return $False
        }
        if($hash_table.keys -contains '@odata.etag')
        {
            $etag = $hash_table['@odata.etag']
        }
        else
        {
            $etag = "*"
        }
        $hash_table_SNMPv3Agent = @{}
        $hash_table.SNMPv3Agent.psobject.properties | Foreach { $hash_table_SNMPv3Agent[$_.Name] = $_.Value }
        if($setting_dict.keys -contains 'snmpv3_agent' -and $setting_dict['snmpv3_agent'] -eq 'enable')
        {
            $flag_missing = $False
            if($setting_dict.keys -contains 'contact_person' -and $setting_dict['contact_person'] -eq "")
            {
                $flag_missing = $True
            }
            if(($setting_dict.keys -notcontains 'contact_person') -and ($hash_table_SNMPv3Agent['ContactPerson'] -eq $null -or $hash_table_SNMPv3Agent['ContactPerson'] -eq ""))
            {
                $flag_missing = $True
            }
            if($setting_dict.keys -contains 'location' -and $setting_dict['location'] -eq "")
            {
                $flag_missing = $True
            }
            if(($setting_dict.keys -notcontains 'location') -and ($hash_table_SNMPv3Agent['Location'] -eq $null -or $hash_table_SNMPv3Agent['Location'] -eq ""))
            {
                $flag_missing = $True
            }
            if($flag_missing -eq $True)
            {
                Write-Host 'Input parameter checking failed. Note that snmpv3_agent can only be enabled with contact_person and location being set.'
                return $False
            }
        }
        if ($setting_dict.keys -contains 'snmpv1_trap' -and $setting_dict['snmpv1_trap'] -eq "enable")
        {
            $flag_missing = $False
            if($setting_dict.keys -contains 'snmpv1_community' -and $setting_dict['snmpv1_community'] -eq "")
            {
                $flag_missing = $True
            }
            if($setting_dict.keys -notcontains 'snmpv1_community' -and $hash_table['CommunityNames'].Length -eq 0 -or $hash_table['CommunityNames'][0] -eq "")
            {
                $flag_missing = $True
            }
            if($flag_missing -eq $True)
            {
                Write-Host 'Input parameter checking failed. Note that snmpv1_trap can only be enabled with snmpv1_community being set.'
                return $False
            }
        }

        # Build patch body
        $patch_body = @{}
        if ($setting_dict.keys -contains 'snmpv3_agent' -or $setting_dict.keys -contains 'port_agent' -or $setting_dict.keys -contains 'contact_person' -or $setting_dict.keys -contains 'location')
        {
            $patch_body['SNMPv3Agent'] = @{}
            if($setting_dict.keys -contains 'snmpv3_agent' -and $setting_dict['snmpv3_agent'] -eq "enable")
            {
                $patch_body['SNMPv3Agent']['ProtocolEnabled'] = $True
            }
            elseif($setting_dict.keys -contains 'snmpv3_agent' -and $setting_dict['snmpv3_agent'] -ne 'enable')
            {
                $patch_body['SNMPv3Agent']['ProtocolEnabled'] = $False
            }
            if($setting_dict.keys -contains 'port_agent')
            {
                $patch_body['SNMPv3Agent']['Port'] = $setting_dict['port_agent']
            }
            if($setting_dict.keys -contains 'contact_person')
            {
                $patch_body['SNMPv3Agent']['ContactPerson'] = $setting_dict['contact_person']
            }
            if($setting_dict.keys -contains 'location')
            {
                $patch_body['SNMPv3Agent']['Location'] = $setting_dict['location']
            }
        }
        if($setting_dict.keys -contains 'snmpv1_trap' -or $setting_dict.keys -contains 'snmpv3_trap' -or $setting_dict.keys -contains 'port_trap')
        {
            $patch_body['SNMPTraps'] = @{}
            if($setting_dict.keys -contains 'snmpv1_trap' -and $setting_dict['snmpv1_trap'] -eq 'enable')
            {
                $patch_body['SNMPTraps']['SNMPv1TrapEnabled'] = $True
            }
            elseif($setting_dict.keys -contains 'snmpv1_trap' -and $setting_dict['snmpv1_trap'] -ne 'enable')
            {
                $patch_body['SNMPTraps']['SNMPv1TrapEnabled'] = $False
            }
            if($setting_dict.keys -contains 'snmpv3_trap' -and $setting_dict['snmpv3_trap'] -eq 'enable')
            {
                $patch_body['SNMPTraps']['ProtocolEnabled'] = $True
            }
            elseif($setting_dict.keys -contains 'snmpv3_trap' -and $setting_dict['snmpv3_trap'] -ne 'enable')
            {
                $patch_body['SNMPTraps']['ProtocolEnabled'] = $False
            }
            if($setting_dict.keys -contains 'port_trap')
            {
                $patch_body['SNMPTraps']['Port'] = $setting_dict['port_trap']
            }
            if($setting_dict.keys -contains 'snmpv1_address')
            {
                $patch_body['SNMPTraps']['Targets'] = @()
                $addr = @{'Addresses'= @($setting_dict['snmpv1_address'])}
                $patch_body['SNMPTraps']['Targets'] += $addr
            }
        }
        if ($setting_dict.keys -contains 'snmpv1_community')
        {
            $patch_body['CommunityNames'] = @($setting_dict['snmpv1_community'])
        }
        if($alert_recipient -ne $null)
        {
            if($patch_body.keys -notcontains 'SNMPTraps')
            {
                $patch_body['SNMPTraps'] = @{}
            }
            $patch_body['SNMPTraps']['AlertRecipient'] = $alert_recipient
        }
        $JsonHeader = @{"X-Auth-Token" = $session_key; "If-Match"= $etag}
        $JsonBody = $patch_body | ConvertTo-Json -Depth 10
        Write-Host $JsonBody'---'
        $response = Invoke-WebRequest -Uri $request_url -Method patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
        $url_list = @(200, 204)
        if($url_list -contains $response.StatusCode)
        {
            Write-Host 'The global SNMP info is successfully updated.'
            return $True
        }
        else
        {
            [String]::Format("Update global SNMP info failed, url '{0}' response error code {1}", $request_url, $response.StatusCode)
            return $False
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