###
#
# Lenovo Redfish examples - Create new RAID volume
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
    Cmdlet used to create RAID volume using Redfish API. Configuration information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - raid_type: Possible options: ["RAID0","RAID1","RAID5","RAID6","RAID10","RAID50","RAID60"]
    - volume_capacity: Pass in new volume size in Bytes. If you want to use all space, please specify -1
    - raidid: Specify the storage id when multi storage exist
    - volume_name: virtual drive(VD)'s name
    - read_policy: Possible options: ["NoReadAhead", "ReadAhead"]
    - write_policy: Possible options: ["WriteThrough", "AlwaysWriteBack", "WriteBackWithBBU"]
    - io_policy: Possible options: ["DirectIO", "CachedIO"]
    - access_policy: Possible options: ["ReadWrite", "ReadOnly", "Blocked"]
    - drive_cache_policy: Possible options: ["Unchanged", "Enable", "Disable"]
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_create_raid_volume -ip 10.10.10.10 -username USERID -password PASSW0RD -raidid RAID_Slot4 -volume_name VD_1_vol -raid_type RAID5
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [string]$system_id="None",
        [Parameter(Mandatory=$False)]
        [string]$raidid="",
        [Parameter(Mandatory=$False)]
        [string]$volume_name="",
        [Parameter(Mandatory=$False)]
        [string]$raid_type="", 
        [Parameter(Mandatory=$False)]
        [int]$volume_capacity="",
        [Parameter(Mandatory=$False)]
        [string]$read_policy="",
        [Parameter(Mandatory=$False)]
        [string]$write_policy="",
        [Parameter(Mandatory=$False)]
        [string]$io_policy="",
        [Parameter(Mandatory=$False)]
        [string]$access_policy="",
        [Parameter(Mandatory=$False)]
        [string]$drive_cache_policy="",
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }

        # Get the system url collection
        $system_url_collection = @()
        $system_url_collection = get_system_urls -bmcip $ip -session $session -system_id $system_id

        # Loop all System resource instance in $system_url_collection
        foreach($system_url_string in $system_url_collection){
           
            # Get system resource
            $url_address_system = "https://$ip"+$system_url_string
            $response = Invoke-WebRequest -Uri $url_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            
            # Get the Storage url
            $storage_url = "https://$ip" + $converted_object.'Storage'.'@odata.id'
            $response = Invoke-WebRequest -Uri $storage_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $storage_url_response = $response.Content | ConvertFrom-Json

            $storage_count = $storage_url_response.'Members@odata.count'

            $list_raid_id = @()
            $list_raid_name = @()
            $list_raid_drive_num = @()
            $list_raid_volume_num = @()
            $list_raid_volume_urls = @()

            for ($raid_index=0; $raid_index -ilt $storage_count; $raid_index++){
                $storage_x_url = "https://$ip" + $storage_url_response.'Members'[$raid_index].'@odata.id'
                $response = Invoke-WebRequest -Uri $storage_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json

                $Storage_id = $converted_object.'Id'
                $Name = $converted_object.'Name'
                $drive_num = $converted_object.'Drives'.Count
                $volumes_url = $converted_object.'Volumes'."@odata.id"

                $volumes_num_url = "https://$ip" + $volumes_url
                $response = Invoke-WebRequest -Uri $volumes_num_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json
                $volume_num = $converted_object."Members".Count

                $list_raid_id += $Storage_id
                $list_raid_name += $Name
                $list_raid_drive_num += $drive_num
                $list_raid_volume_num += $volume_num
                $list_raid_volume_urls += $volumes_url
            }

            # Find the target storage when raidid is specified
            if ($raidid -ne "None"){                
                for ($raid_index=0; $raid_index -ilt $storage_count; $raid_index++){
                    if (($raidid -eq $list_raid_id[$raid_index]) -or ($raidid -eq $list_raid_name[$raid_index])){
                        if ($list_raid_drive_num[$raid_index] -eq 0){                            
                            return "There is no Drives on specified storage"
                        }
                        if ($list_raid_volume_num[$raid_index] -ne 0){                            
                            return "Volume has already been created on specified storage"
                        }
                    $target_raid_volumes_url = $list_raid_volume_urls[$raid_index]
                    break
                    }
                }
            }
            # Check whether only one raid storage can be configured when raidid is not specified. If multi-raid can be configured, raidid need to be specified
            else{
                for ($raid_index=0; $raid_index -ilt $storage_count; $raid_index++){
                    if ($list_raid_drive_num[$raid_index] -eq 0){
                        continue
                    }
                    if ($list_raid_volume_num[$raid_index] -ne 0){
                        continue
                    }
                    if ($target_raid_volumes_url -eq ""){
                        $target_raid_volumes_url = $list_raid_volume_urls[$raid_index]
                    }
                    else{
                        return "There are multi-storage which can be configured. Please specified the raidid."
                    }
                }
            }
            if ($target_raid_volumes_url -eq ""){
                return "Failed to found storage that can be configured"
            }
            
            # USE POST to create a volume                   
            $JsonBody = @{
                "Name"= $volume_name;`
                "RAIDType" = $raid_type;`
                "Oem" = @{"Lenovo" = @{}};`
                } 
            if ($volume_capacity -gt 0){
                $JsonBody["CapacityBytes"] = $volume_capacity # if you want to use all space, no need to specify CapacityBytes
                }
            if ($read_policy -ne ""){
                $jsonBody["Oem"]["Lenovo"]["ReadPolicy"] = $read_policy
                }
            if ($write_policy -ne ""){
                $JsonBody["Oem"]["Lenovo"]["WritePolicy"] = $write_policy
                }
            if ($io_policy -ne ""){
                $JsonBody["Oem"]["Lenovo"]["IOPolicy"] = $io_policy
                }
            if ($access_policy -ne ""){
                $JsonBody["Oem"]["Lenovo"]["AccessPolicy"] = $access_policy
                }
            if ($drive_cache_policy -ne ""){
                $JsonBody["Oem"]["Lenovo"]["DriveCachePolicy"] = $drive_cache_policy
                }
            
            $JsonBody = $JsonBody | ConvertTo-Json -Compress
            $target_URI = "https://$ip" + $target_raid_volumes_url
            $response = Invoke-WebRequest -Uri $target_URI -Headers $JsonHeader -Method Post -Body $JsonBody -ContentType 'application/json'
            if ($response.StatusCode -in @(200,201)){
                [String]::Format("RAID volume created successfully. statuscode {0}",$response.StatusCode)
            }
            
        } # end foreach
        
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
