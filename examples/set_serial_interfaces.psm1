###
#
# Lenovo Redfish examples - Set serial interfaces
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
function set_serial_interfaces
{
   <#
   .Synopsis
    Cmdlet used to set serial interfaces
   .DESCRIPTION
    Cmdlet used to set serial interfaces using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - interfaceid: serial interface instance id. (default instance id is 1)
    - bitrate: This property shall indicate the transmit and receive speed of the serial connection. Support: [9600, 19200, 38400, 57600, 115200]
    - stopbits: This property shall indicate the stop bits for the serial connection. Support:["1","2"]
    - parity: This property shall indicate parity information for a serial connection. Support: ["None", "Even", "Odd"]
    - enabled: The value of this property shall be a boolean indicating whether this interface is enabled. Support:(0:false,1:true)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    set_serial_interfaces -ip 10.10.10.10 -username USERID -password PASSW0RD -interfaceid INTERFACEID -bitrate BITRATE -stopbit -STOPBITS -parity PARITY -enabled ENABLED
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
        [int]$interfaceid=1,
        [Parameter(Mandatory=$False)]
        [string]$bitrate="",
        [Parameter(Mandatory=$False)]
        [string]$stopbits="",
        [Parameter(Mandatory=$False)]
        [string]$parity="",
        [Parameter(Mandatory=$False)]
        [int]$enabled="",
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

        $JsonHeader = @{"X-Auth-Token" = $session_key}
    
        # Get the manager url collection
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
        
            # Get service data uri from the Manager resource instance
            $uri_address_manager = "https://$ip" + $manager_url_string

            # Get the serial interfaces url
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $serial_interfaces_url ="https://$ip" + $converted_object.SerialInterfaces."@odata.id"

            #Get the serial interfaces url collection
            $response = Invoke-WebRequest -Uri $serial_interfaces_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $serial_interfaces_url_collection = $converted_object.Members
            $count = $serial_interfaces_url_collection.count

            # Get the serial interfaces url form serial interfaces url collection
            $index = $interfaceid - 1
            if(($index -lt 0) -or ($index -gt $count-1))
            {
                Write-Host "The specified Interface Id does not exist."
                return $False
            }
            $serial_interfaces = $serial_interfaces_url_collection[$index]
            $serial_interfaces_x_url = "https://$ip" + $serial_interfaces.'@odata.id'

            # get etag to set If-Match precondition
            $response = Invoke-WebRequest -Uri $serial_interfaces_x_url -Headers $JsonHeader -Method Get -UseBasicParsing 
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            if ($null -ne $hash_table."@odata.etag")
            {
                $etag = $hash_table."@odata.etag"
            }
            else
            {
                $etag = ""
            }
            $JsonHeader["If-Match"] = $etag

            if($null -eq $hash_table.BitRate)
            {
                Write-Host "The specified Interface Id {0} has no BitRate property, not valid.",$hash_table.Id
            }

            $hash_table."@odata.etag"
            $hash_table.BitRate

            $body = @{}
            # Build body for set serial interfaces properties value
            if($bitrate -ne "")
            {
                $body["BitRate"] = $bitrate
            }
            if($parity -ne "")
            {
                $body["Parity"] = $parity
            }
            if($stopbits -ne "")
            {
                $body["StopBits"] = $stopbits
            }
            if($enabled -ne '')
            {
                if(([bool]$enabled -eq $False -and $state -eq "Enabled") -or ([bool]$enabled -eq $True -and $state -eq "Offline"))
                {
                    write-Host 'InterfaceEnabled is "true" then SerialInterfaceState must be "Enabled".InterfaceEnabled is "false" then SerialInterfaceState must be "Offline".'
                    return $False
                }
                $body['InterfaceEnabled'] = [bool]$enabled
            }
            else
            {
                if($state -eq "Enabled")
                {
                    $body['InterfaceEnabled'] = $True
                }
                elseif($state -eq "Offline")
                {
                    $body['InterfaceEnabled'] = $False
                }
            }

            $json_body = $body | ConvertTo-Json -Compress 
            # Request set serial interface
            $response = Invoke-WebRequest -Uri $serial_interfaces_x_url -Headers $JsonHeader -Method Patch -Body $json_body -ContentType 'application/json' -UseBasicParsing
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to set serial interfaces", $response.statuscode)
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