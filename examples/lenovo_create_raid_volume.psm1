###
#
# Lenovo Redfish examples - Create RAID volume
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


function lenovo_create_raid_volume
{
    <#
   .Synopsis
    Cmdlet used to create RAID volume
   .DESCRIPTION
    Cmdlet used to create RAID volume from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - raidid: Specify the storage id when multi storage exist
    - volume_name: virtual drive(VD)'s name
    - raid_type: virtual drive(VD)'s raid type
    - volume_capacity: virtual drive(VD)'s capacity Mega bytes. If you want to use all space, please specify -1
    - read_policy: virtual drive(VD)'s read policy
    - write_policy: virtual drive(VD)'s write policy
    - io_policy: virtual drive(VD)'s io policy
    - access_policy: access policy of the volume
    - drive_cache_policy: virtual drive(VD)'s access policy
   .EXAMPLE
    lenovo_create_raid_volume -ip 10.10.10.10 -username admin -password admin -raidid RAID_Slot1 -volume_name test_volume1 -raid_type RAID0 -volume_capacity 500000
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
        [string]$raidid="",
        [Parameter(Mandatory=$False)]
        [string]$volume_name="",
        [Parameter(Mandatory=$False)][ValidateSet('RAID0', 'RAID1', 'RAID5', 'RAID6', 'RAID10', 'RAID50', 'RAID60')]
        [string]$raid_type="",
        [Parameter(Mandatory=$False)]
        [string]$volume_capacity="",
        [Parameter(Mandatory=$False)][ValidateSet('NoReadAhead', 'ReadAhead')]
        [string]$read_policy="",
        [Parameter(Mandatory=$False)][ValidateSet('WriteThrough', 'AlwaysWriteBack', 'WriteBackWithBBU')]
        [string]$write_policy="",
        [Parameter(Mandatory=$False)][ValidateSet('DirectIO', 'CachedIO')]
        [string]$io_policy="",
        [Parameter(Mandatory=$False)][ValidateSet('ReadWrite', 'ReadOnly', 'Blocked')]
        [string]$access_policy="",
        [Parameter(Mandatory=$False)][ValidateSet('Unchanged', 'Enable', 'Disable')]
        [string]$drive_cache_policy="",
        [Parameter(Mandatory=$False)]
        [string]$system_id="None",
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
    if ($system_id -eq "")
    {
        $system_id = [string]($ht_config_ini_info['SystemId'])
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
      
        # Get the system url collection
        $system_url_collection = @()
        $system_url_collection = get_system_urls -bmcip $ip -session $session -system_id $system_id

        foreach($system_url_string in $system_url_collection)
        {
            # Get system resource
            $system_url_string = "https://$ip" + $system_url_string
            $response = Invoke-WebRequest -Uri $system_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            # Set Storage url
            $storage_url = "https://$ip" +  $converted_object."Storage"."@odata.id"
            $response = Invoke-WebRequest -Uri $storage_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            $found = $False
            if($raidid -ne "")
            {
                $raidid_url = "https://$ip" +  $converted_object."@odata.id" + "/$raidid"
                foreach ($raid_controller in $converted_object.Members)
                {
                    $raid_controller_url = "https://$ip" + $raid_controller."@odata.id"
                    if($raid_controller_url -eq $raidid_url)
                    {
                        $found = $true
                    }
                }
                if($found -eq $False)
                {
                    Write-Host "Error: No RAID storage controller found with RAID ID $raidid"
                    return $False
                }

                $ret = raid_validation_check_by_id -ip $ip -JsonHeader $JsonHeader -raidid_url $raidid_url
                if($ret -eq $False){return $False}
            }
            else
            {
                foreach ($raid_controller in $converted_object.Members)
                {
                    $raid_controller_url = "https://$ip" + $raid_controller."@odata.id"
                    $ret = raid_validation_check_by_id -ip $ip -JsonHeader $JsonHeader -raidid_url $raid_controller_url
                    if($ret = $False)
                    {
                        continue
                    }
                    else
                    {
                        $found = $true    
                    }
                }
                if($found = $False)
                {
                    Write-Host "Error: No RAID storage controller available on server now"
                    return $False
                }
            }

            $volume_url = $ret

            $JsonBody = @{
                "Name" = $volume_name
                "RAIDType"= $raid_type
                "Oem" = @{"Lenovo" = @{}}
            }

            if ($volume_capacity -gt 0)
            {
                $JsonBody["CapacityBytes"] = [int]$volume_capacity*1024*1024
            }
            if ($read_policy -ne "")
            {
                $JsonBody["Oem"]["Lenovo"]["ReadPolicy"] =$read_policy
            }
            if ($write_policy -ne "")
            {
                $JsonBody["Oem"]["Lenovo"]["WritePolicy"] =$write_policy
            }
            if ($io_policy -ne "")
            {
                $JsonBody["Oem"]["Lenovo"]["IOPolicy"] =$io_policy
            }
            if ($access_policy -ne "")
            {
                $JsonBody["Oem"]["Lenovo"]["AccessPolicy"] =$access_policy
            }
            if ($drive_cache_policy -ne "")
            {
                $JsonBody["Oem"]["Lenovo"]["DriveCachePolicy"] =$drive_cache_policy
            }
        }

        $JsonBody = $JsonBody | ConvertTo-Json
       
        $response = Invoke-WebRequest -Uri $volume_url -Method Post -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
        Write-Host
        [String]::Format("- PASS, statuscode {0} returned successfully to create volume {1}",$response.StatusCode,$raidid)
    
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
                $sr = new-object System.IO.StreamReader $_.Exception.Response.GetResponseStream()
                $resobject = $sr.ReadToEnd() | ConvertFrom-Json
                $resobject.error.('@Message.ExtendedInfo')    
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

function raid_validation_check_by_id
{
    param
    (
        [Parameter(Mandatory=$True)]
        [string]$ip,
        [Parameter(Mandatory=$True)]
        [hashtable]$JsonHeader,
        [Parameter(Mandatory=$True)]
        [string]$raidid_url
    )
    
    $response = Invoke-WebRequest -Uri $raidid_url -Headers $JsonHeader -Method Get -UseBasicParsing
    $converted_object = $response.Content | ConvertFrom-Json
    if($converted_object."Drives@odata.count" -eq 0)
    {
        Write-Host "Error: No Drives found on specified RAID storage controller $raidid"
        return $False
    }

    $raidid_volume_url = "https://$ip" +  $converted_object.Volumes."@odata.id"
    $response = Invoke-WebRequest -Uri $raidid_volume_url -Headers $JsonHeader -Method Get -UseBasicParsing
    $converted_object = $response.Content | ConvertFrom-Json
    if($converted_object."Members@odata.count" -ne 0)
    {
        Write-Host "Error: Volume has already been created on specified storage contoller $raidid"
        return $False
    }

    return $raidid_volume_url

}