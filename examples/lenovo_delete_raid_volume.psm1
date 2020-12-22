###
#
# Lenovo Redfish examples - Delete RAID volume
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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


function lenovo_delete_raid_volume
{
    <#
   .Synopsis
    Cmdlet used to delete RAID volume
   .DESCRIPTION
    Cmdlet used to delete RAID volume from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - raidid: Specify the storage id when multi storage exist
    - volume_name: virtual drive(VD)'s name
   .EXAMPLE
    lenovo_delete_raid_volume -ip 10.10.10.10 -username admin -password admin -raidid RAID_Slot1 -volume_name test_volume1
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
            $volume_url = ""
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

                $ret = volume_info_validation -ip $ip -JsonHeader $JsonHeader -raidid_url $raidid_url
                if($ret -eq $False){return $False}
                else
                {
                    foreach ($volume_info in $ret)
                    {
                        $volume_name_ret = $volume_info.split(";")[0]
                        $volume_url_ret = $volume_info.split(";")[1]
                        if($volume_name_ret -eq $volume_name)
                        {
                            $volume_url = $volume_url_ret
                        }
                    }    
                }
            }
            else
            {
                foreach ($raid_controller in $converted_object.Members)
                {
                    $raid_controller_url = "https://$ip" + $raid_controller."@odata.id"
                    $ret = volume_info_validation -ip $ip -JsonHeader $JsonHeader -raidid_url $raid_controller_url
                    if($ret -eq $False){continue}
                    else
                    {
                        foreach ($volume_info in $ret)
                        {
                            $volume_name_ret = $volume_info.split(";")[0]
                            $volume_url_ret = $volume_info.split(";")[1]
                            if($volume_name_ret -eq $volume_name)
                            {
                                if($volume_url -eq "")
                                {
                                    $volume_url = $volume_url_ret
                                }
                                else
                                {
                                    Write-Host "Error: There are multi-volume which can be configured. Please specified the raidid."
                                    return $False
                                }
                            }
                        }
                    }
                }
            }

            if($volume_url -eq "")
            {
                Write-Host "Error: Failed to found storage that can be configured"
                return $False
            }
        }

        $JsonBody = $JsonBody | ConvertTo-Json
       
        $response = Invoke-WebRequest -Uri $volume_url -Method Delete -Headers $JsonHeader -ContentType 'application/json'
        Write-Host
        [String]::Format("- PASS, statuscode {0} returned successfully to delete volume {1}",$response.StatusCode,$volume_name)
    
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

function volume_info_validation
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

    $volume_list = @()
    
    $response = Invoke-WebRequest -Uri $raidid_url -Headers $JsonHeader -Method Get -UseBasicParsing
    $converted_object = $response.Content | ConvertFrom-Json

    $raidid_volume_url = "https://$ip" +  $converted_object.Volumes."@odata.id"
    $response = Invoke-WebRequest -Uri $raidid_volume_url -Headers $JsonHeader -Method Get -UseBasicParsing
    $converted_object = $response.Content | ConvertFrom-Json
    if($converted_object."Members@odata.count" -eq 0)
    {
        Write-Host "Error: No Volume found on specified storage contoller $raidid"
        return $False
    }

    foreach($volume_member in $converted_object.Members)
    {
        $volume_url = "https://$ip" + $volume_member."@odata.id"
        $response = Invoke-WebRequest -Uri $volume_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        $volume_list += $converted_object.Name + ";" + $volume_url
    }

    return $volume_list

}