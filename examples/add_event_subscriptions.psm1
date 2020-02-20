###
#
# Lenovo Redfish examples - Add event subscriptions
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


function add_event_subscriptions
{
    <#
   .Synopsis
    Cmdlet used to add event subscriptions
   .DESCRIPTION
    Cmdlet used to add event subscriptions from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - destination: Pass in the new subscription's destination url you want to set
    - resourcetypes: Pass in the resource types you want to received.  
    - context: Specify a client-supplied string that is stored with the event destination subscription.
   .EXAMPLE
    add_event_subscriptions -ip 10.10.10.10 -username USERID -password PASSW0RD -destination "https://10.119.171.6" -resourcetypes @("LogService","Job") -context test
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
        [Parameter(Mandatory=$True)]
        [string]$destination,
        [Parameter(Mandatory=$True)]
        [String[]]$resourcetypes,
        [Parameter(Mandatory=$True)]
        [string]$context
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
    
    $list_resource_types = @(
        "AccountService",
        "ActionInfo",
        "Assembly",
        "AttributeRegistry",
        "Bios",
        "BootOption",
        "BootOptionCollection",
        "Chassis",
        "ChassisCollection",
        "CompositionService",
        "ComputerSystem",
        "ComputerSystemCollection",
        "Drive",
        "Endpoint",
        "EndpointCollection",
        "EthernetInterface",
        "EthernetInterfaceCollection",
        "Event",
        "EventDestination",
        "EventDestinationCollection",
        "EventService",
        "ExternalAccountProvider",
        "ExternalAccountProviderCollection",
        "FabricCollection",
        "HostInterface",
        "HostInterfaceCollection",
        "IPAddresses",
        "Job",
        "JobCollection",
        "JobService",
        "JsonSchemaFile",
        "JsonSchemaFileCollection",
        "LenovoAccountService",
        "LenovoAdapter",
        "LenovoAdapterCollection",
        "LenovoAlertRecipient",
        "LenovoAlertRecipientCollection",
        "LenovoAuthenticationAuthority",
        "LenovoBootManager",
        "LenovoBootManagerCollection",
        "LenovoChassis",
        "LenovoComputerSystem",
        "LenovoConfigurationService",
        "LenovoDNS",
        "LenovoDateTimeService",
        "LenovoDeviceInfo",
        "LenovoDrive",
        "LenovoEthernetInterface",
        "LenovoEvent",
        "LenovoFirmwareService",
        "LenovoFirmwareServiceCollection",
        "LenovoFoDKey",
        "LenovoFoDKeyCollection",
        "LenovoFoDService",
        "LenovoHistoryMetricValue",
        "LenovoHistoryMetricValueContainer",
        "LenovoHistoryMetricValueContainerCollection",
        "LenovoLDAPClient",
        "LenovoLED",
        "LenovoLEDCollection",
        "LenovoLogEntry",
        "LenovoLogService",
        "LenovoManager",
        "LenovoManagerAccount",
        "LenovoManagerGroup",
        "LenovoManagerGroupCollection",
        "LenovoManagerNetworkProtocol",
        "LenovoMemory",
        "LenovoMemoryCollectionExtension",
        "LenovoPortForwarding",
        "LenovoPortForwardingMap",
        "LenovoPortForwardingMapCollection",
        "LenovoPower",
        "LenovoProcessor",
        "LenovoRedundancy",
        "LenovoRemoteControlService",
        "LenovoRemoteControlSession",
        "LenovoRemoteControlSessionCollection",
        "LenovoRemoteMapMedia",
        "LenovoRemoteMapMediaCollection",
        "LenovoRemoteMapService",
        "LenovoRemoteMountMedia",
        "LenovoRemoteMountMediaCollection",
        "LenovoSMTPClient",
        "LenovoSNMPProtocol",
        "LenovoScheduledPowerAction",
        "LenovoScheduledPowerActionCollection",
        "LenovoSecurityService",
        "LenovoSensor",
        "LenovoSensorCollection",
        "LenovoSerialInterface",
        "LenovoServerProfileService",
        "LenovoServiceData",
        "LenovoServiceRoot",
        "LenovoSlot",
        "LenovoSlotCollection",
        "LenovoSoftwareInventory",
        "LenovoStorageVolume",
        "LenovoTask",
        "LenovoThermal",
        "LenovoUpdateService",
        "LenovoWatchdog",
        "LenovoWatchdogCollection",
        "LogEntry",
        "LogEntryCollection",
        "LogService",
        "LogServiceCollection",
        "Manager",
        "ManagerAccount",
        "ManagerAccountCollection",
        "ManagerCollection",
        "ManagerNetworkProtocol",
        "Memory",
        "MemoryCollection",
        "Message",
        "MessageRegistry",
        "MessageRegistryCollection",
        "MessageRegistryFile",
        "MessageRegistryFileCollection",
        "MetricDefinition",
        "MetricDefinitionCollection",
        "MetricReport",
        "MetricReportCollection",
        "MetricReportDefinition",
        "MetricReportDefinitionCollection",
        "NetworkAdapter",
        "NetworkAdapterCollection",
        "NetworkDeviceFunction",
        "NetworkDeviceFunctionCollection",
        "NetworkInterface",
        "NetworkInterfaceCollection",
        "NetworkPort",
        "NetworkPortCollection",
        "PCIeDevice",
        "PCIeDeviceCollection",
        "PCIeFunction",
        "PCIeFunctionCollection",
        "PCIeSlots",
        "PhysicalContext",
        "Port",
        "PortCollection",
        "Power",
        "PrivilegeRegistry",
        "Privileges",
        "Processor",
        "ProcessorCollection",
        "ProcessorMetrics",
        "Protocol",
        "Redundancy",
        "Resource",
        "Role",
        "RoleCollection",
        "Schedule",
        "SecureBoot",
        "SerialInterface",
        "SerialInterfaceCollection",
        "ServiceRoot",
        "Session",
        "SessionCollection",
        "SessionService",
        "Settings",
        "SoftwareInventory",
        "SoftwareInventoryCollection",
        "Storage",
        "StorageCollection",
        "Task",
        "TaskCollection",
        "TaskService",
        "TelemetryService",
        "Thermal",
        "Triggers",
        "TriggersCollection",
        "UpdateService",
        "VLanNetworkInterface",
        "VLanNetworkInterfaceCollection",
        "VirtualMedia",
        "VirtualMediaCollection",
        "Volume",
        "VolumeCollection"
    )

    foreach($type in $resourcetypes)
    {
        if($type  -in $list_resource_types)
        {
            continue
        }
        else
        {
            Write-Host "The value of event type outside the scope,please check your input"
            return $False
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key}
    
        # Get the base url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json

        #Get event url resource
        $event_url = "https://$ip" + $converted_object.EventService."@odata.id"
        $response = Invoke-WebRequest -Uri $event_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object =$response.Content | ConvertFrom-Json
        
        #Add event subscriptions
        $subscriptions_url = "https://$ip" + $converted_object.Subscriptions."@odata.id"
        $JsonBody = @{"Destination"=$destination
                             "ResourceTypes"=$resourcetypes
                             "Context"=$context
                             "Protocol"="Redfish"}|ConvertTo-Json -Compress
        $response = Invoke-WebRequest -Uri $subscriptions_url -Method Post -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
        $converted_object =$response.Content | ConvertFrom-Json
        $rt_link = "https://$ip" + $converted_object."@odata.id"
        $id = $rt_link.Split("/")[-1]
        Write-Host "Add event subscriptions successfully,subscription id is " $id  ",subscription's link is " $rt_link 
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
