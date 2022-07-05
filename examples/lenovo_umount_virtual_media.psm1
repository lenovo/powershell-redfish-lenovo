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
function lenovo_umount_virtual_media
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
    "lenovo_mount_virtual_media  -ip 10.10.10.10 -username USERID -password PASSW0RD --fsprotocol HTTP --fsip 10.10.10.11 --fsdir /fspath/ --image isoname.img"
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
        [string]$mounttype="Network",
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
    
        # Get the manager/system url collection
        $root_urls = @()
        $root_urls_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json


        $managers_url = "https://$ip" + $converted_object.Managers."@odata.id"
        $systems_url = "https://$ip" + $converted_object.Systems."@odata.id"
        $root_urls += $managers_url
        $root_urls += $systems_url

        foreach ($root_url in $root_urls) {
            $response = Invoke-WebRequest -Uri $root_url -Headers $JsonHeader -Method Get -UseBasicParsing

            # Convert response content to hash table
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            # Set the $root_urls_collection
            foreach ($i in $hash_table.Members)
            {
                $i = [string]$i
                $url_string = ($i.Split("=")[1].Replace("}",""))
                $root_urls_collection += $url_string
            }
        }

        $uri_virtual_media = ""
        $response_manager_url = ""
        # Loop all Manager/System resource instance in $root_urls_collection
        foreach ($url_string in $root_urls_collection)
        {

            # Get servicedata uri from the Manager/System resource instance
            $uri_address_manager = "https://$ip" + $url_string

            # Get the virtual media url
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            # Get the virtual media url from the manager/system response
            if ($converted_object."VirtualMedia") {
                $uri_virtual_media ="https://$ip" + $converted_object."VirtualMedia"."@odata.id"
            }
            # Get manager response
            if ($converted_object."Oem") {
                if ($converted_object."Oem"."Lenovo") {
                    if ($converted_object."Oem"."Lenovo"."RemoteControl") {
                        $response_manager_url = $converted_object
                    }
                }
            }
            if ($uri_virtual_media -eq "" -or $response_manager_url -eq "") {
                continue
            }
        }

        $uri_remote_map ="https://$ip" + $response_manager_url."Oem"."Lenovo"."RemoteMap"."@odata.id"
        $uri_remote_control ="https://$ip" + $response_manager_url."Oem"."Lenovo"."RemoteControl"."@odata.id"

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

        if($mounttype -eq "Network")
        {
            if($members_count -eq 10)
            {
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
            else 
            {
                # umount_all_virtual_from_network
                $response = Invoke-WebRequest -Uri $uri_remote_map -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                $umount_images_uri = "https://$ip" + $hash_table."Actions"."#LenovoRemoteMapService.UMount"."target"

                $response = Invoke-WebRequest -Uri $umount_images_uri -Headers $JsonHeader -Method Post -ContentType 'application/json'

                Write-Host
                [String]::Format("- PASS, statuscode {0} returned to mount virtual media successful",$response.StatusCode)
                return $True
            }
        }
        else
        {
            # umount_virtual_media_from_rdoc
            $response = Invoke-WebRequest -Uri $uri_remote_control -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $mount_image_uri = "https://$ip" + $hash_table.MountImages."@odata.id"

            $response = Invoke-WebRequest -Uri $mount_image_uri -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $image_uri_list = $hash_table.Members

            if($image -eq "all")
            {
                foreach($image_uri in $image_uri_list)
                {
                    $image_uri = $image_uri."@odata.id"
                    if($image_uri -match "RDOC")
                    {
                        $response = Invoke-WebRequest -Uri $image_uri -Headers $JsonHeader -Method Delete
                    }
                }

                $result = "Umount all virtual media successfully."
                $result
                return $True
            }
            else
            {
                foreach($image_uri in $image_uri_list)
                {
                    $image_uri = "https://$ip" + $image_uri."@odata.id"
                    $response = Invoke-WebRequest -Uri $image_uri -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response.Content | ConvertFrom-Json
                    $hash_table = @{}
                    $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                    $image_iso_name = $hash_table.name

                    if($image_iso_name -eq $image)
                    {
                        $response = Invoke-WebRequest -Uri $image_uri -Headers $JsonHeader -Method Delete

                        $result = [String]::Format("- PASS, statuscode {0} returned to mount virtual media successful.",$response.StatusCode)
                        $result
                        return $True
                    }
                    else
                    {
                        continue
                    }
                }

                $result = "Please check the iso name is correct and has been mounted."
                $result
                return $False

            }
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