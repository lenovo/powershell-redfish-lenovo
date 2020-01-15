###
#
# Lenovo Redfish examples - Umount virtual media
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
function umount_virtual_media
{
   <#
   .Synopsis
    Cmdlet used to umount virtual media
   .DESCRIPTION
    Cmdlet used to umount virtual media information using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - image: Mount virtual media name
    - mounttype: Types of mount virtual media
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    Example of HTTP/NFS:
    "mount_virtual_media  -ip 10.10.10.10 -username USERID -password PASSW0RD --image isoname.img"
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
        [string]$image="",
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
        $manager_url_collection = @()
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
        
            # Get servicedata uri from the Manager resource instance
            $uri_address_manager = "https://$ip" + $manager_url_string

            # Get the virtual media url
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $uri_virtual_media ="https://$ip" + $converted_object."VirtualMedia"."@odata.id"

            $uri_remote_map ="https://$ip" + $converted_object."Oem"."Lenovo"."RemoteMap"."@odata.id"
            $uri_remote_control ="https://$ip" + $converted_object."Oem"."Lenovo"."RemoteControl"."@odata.id"

            # Get the virtual media response resource
            $response = Invoke-WebRequest -Uri $uri_virtual_media -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            $members_count = $hash_table."Members@odata.count"
            if($members_count -eq 0)
            {
                Write-Host "This server doesn't mount virtual media."
            }

            # umount_virtual_media
            foreach($i in $hash_table.Members)
            {
                $virtual_media_x_url = "https://$ip" + $i."@odata.id"
                # Get the virtual media response resource
                $response = Invoke-WebRequest -Uri $virtual_media_x_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

                if (!($hash_table.Id -match "Remote"))
                {
                    if($image -eq $hash_table.ImageName)
                    {

                        $body = @{}
                        $body["Image"] = $Null
                        $json_body = $body | convertto-json

                        $virtual_media_member_uri = "https://$ip" + $hash_table."@odata.id"
                        $response = Invoke-WebRequest -Uri $virtual_media_member_uri -Headers $JsonHeader -Method Patch -Body $json_body -ContentType 'application/json'

                        Write-Host
                        [String]::Format("- PASS, statuscode {0} returned to umount virtual media successful",$response.StatusCode) 
                        return $True
                    }
                    else
                    {
                        continue    
                    }
                }
            }
            $result = "Please check the image name is correct and has been mounted."
            $result
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