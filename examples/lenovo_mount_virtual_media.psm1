###
#
# Lenovo Redfish examples - Mount virtual media
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
function lenovo_mount_virtual_media
{
   <#
   .Synopsis
    Cmdlet used to mount virtual media
   .DESCRIPTION
    Cmdlet used to mount virtual media information using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - image: Mount virtual media name
    - mounttype: Types of mount virtual media
    - fsprotocol: Specify the protocol for uploading image or ISO
    - fsip: Specify the file server ip
    - fsport: 
    - fsusername: Username to access the file path, available for Samba, NFS, HTTP, SFTP/FTP
    - fspassword: Password to access the file path, password should be encrypted after object creation, available for Samba, NFS, HTTP, SFTP/FTP
    - fsdir: File path of the map image
    - readonly: It indicates the map image status is readonly or read/write
    - domain: Domain of the username to access the file path, available for Samba only
    - options: It indicates the mount options to map the image of the file path, available for Samba and NFS only
    - inserted: This value shall specify if the image is to be treated as inserted upon completion of the action. If this parameter is not provided by the client, the service shall default this value to be true
    - writeProtected: This value shall specify if the remote media is supposed to be treated as write protected. If this parameter is not provided by the client, the service shall default this value to be true
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    Example of HTTP/NFS:
    "lenovo_mount_virtual_media  -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol HTTP -fsip 10.10.10.11 -fsdir /fspath/ -image isoname.img"
    Example of SFTP/FTP/Samba:
    "lenovo_mount_virtual_media  -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol SFTP -fsip 10.10.10.11 -fsusername mysftp -fspassword mypass -fsdir /fspath/ -image isoname.img"
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
        [Parameter(Mandatory=$False, HelpMessage='Specify the protocol for uploading image or ISO. Support:["Samba", "NFS", "CIFS", "HTTP", "HTTPS", "SFTP", "FTP"].')]
        [string]$fsprotocol="",
        [Parameter(Mandatory=$False)]
        [string]$fsip="",
        [Parameter(Mandatory=$False)]
        [string]$fsport="",
        [Parameter(Mandatory=$False)]
        [string]$fsusername="",
        [Parameter(Mandatory=$False)]
        [string]$fspassword="",
        [Parameter(Mandatory=$False)]
        [string]$fsdir="",
        [Parameter(Mandatory=$False)]
        [string]$readonly="1",
        [Parameter(Mandatory=$False)]
        [string]$domain="",
        [Parameter(Mandatory=$False)]
        [string]$options="",
        [Parameter(Mandatory=$False)]
        [string]$inserted="1",
        [Parameter(Mandatory=$False)]
        [string]$writeprotected="1",
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
    if ($fsprotocol -eq "")
    {
        $fsprotocol = [string]($ht_config_ini_info['FSprotocol'])
    }
    if ($fsip -eq "")
    {
        $fsip = [string]($ht_config_ini_info['FSip '])
    }
    if ($fsport -eq "")
    {
        $fsport = [string]($ht_config_ini_info['FSport'])
    }
    if ($fsusername -eq "")
    {
        $fsusername = [string]($ht_config_ini_info['FSusername'])
    }
    if ($fspassword -eq "")
    {
        $fspassword = [string]($ht_config_ini_info['FSpassword'])
    }
    if ($fsdir -eq "")
    {
        $fsdir = [string]($ht_config_ini_info['FSdir'])
    }
    
    try
    {
        Ignore_SSLCertificates

        # Set BMC access credential
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
        $bmc_username = $username
        $bmc_password = $password
        $bmc_password_secure = ConvertTo-SecureString $bmc_password -AsPlainText -Force
        $bmc_credential = New-Object System.Management.Automation.PSCredential($bmc_username, $bmc_password_secure)

        # $session_key = ""
        # $session_location = ""
        
        # # Create session
        # $session = create_session -ip $ip -username $username -password $password
        # $session_key = $session.'X-Auth-Token'
        # $session_location = $session.Location

        # $JsonHeader = @{"X-Auth-Token" = $session_key}
    
        # Get the manager/system url collection
        $root_urls = @()
        $root_urls_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Credential $bmc_credential -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json


        $managers_url = "https://$ip" + $converted_object.Managers."@odata.id"
        $systems_url = "https://$ip" + $converted_object.Systems."@odata.id"
        $root_urls += $managers_url
        $root_urls += $systems_url

        foreach ($root_url in $root_urls) {
            $response = Invoke-WebRequest -Uri $root_url -Credential $bmc_credential -Method Get -UseBasicParsing
    
            # Convert response content to hash table
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            # Set the root_urls_collection
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
            $response = Invoke-WebRequest -Uri $uri_address_manager -Credential $bmc_credential -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            # Get the virtual media url from the manager/system response
            if ($converted_object."VirtualMedia")  {
                $uri_virtual_media ="https://$ip" + $converted_object."VirtualMedia"."@odata.id"
            }
            # Get manager response
            if ($converted_object."Oem")  {
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

        # Get mount media iso url
        # XCC Mount VirtualMedia
        $uri_remote_map ="https://$ip" + $response_manager_url."Oem"."Lenovo"."RemoteMap"."@odata.id"
        $uri_remote_control ="https://$ip" + $response_manager_url."Oem"."Lenovo"."RemoteControl"."@odata.id"

        # Get the virtual media response resource
        $response = Invoke-WebRequest -Uri $uri_virtual_media -Credential $bmc_credential -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        $members_count = $hash_table."Members@odata.count"
        if($members_count -eq 0)
        {
            Write-Host "This server doesn't mount virtual media."
        }

        if($fsport -ne "")
        {
            $fsport = ":" + $fsport
        }
        if($fsdir -ne "")
        {
            $fsdir = "/" + $fsdir.Trim("/")
        }
        $protocol = $fsprotocol.ToLower()
        $fsprotocol = $fsprotocol.ToLower()

        if($fsprotocol -eq "samba")
        {
            $source_url = "smb://" + $fsip + $fsport + $fsdir + "/" + $image
        }
        else
        {
            $source_url = $fsprotocol + "://" + $fsip + $fsport + $fsdir + "/" + $image
        }

        if($mounttype -eq "Network")
        {
            if($members_count -eq 10)
            {
                if(@("nfs", "http", "https", "cifs") -contains $fsprotocol)
                {
                    # mount_virtual_media
                    # Loop all the virtual media members and get all the virtual media informations
                    foreach($i in $hash_table.Members)
                    {
                        $virtual_media_x_url = "https://$ip" + $i."@odata.id"
                        # Get the virtual media response resource
                        $response = Invoke-WebRequest -Uri $virtual_media_x_url -Credential $bmc_credential -Method Get -UseBasicParsing
                        $converted_object = $response.Content | ConvertFrom-Json
                        $hash_table = @{}
                        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

                        if($hash_table.Id -match "EXT")
                        {
                            if($Null -eq $hash_table.ImageName)
                            {
                                if($fsprotocol -eq "nfs")
                                {
                                    $image_uri = $fsip + $fsport + ":" + $fsdir + "/" + $image
                                }
                                elseif ($fsprotocol -eq "cifs") {
                                    $image_uri = "//" + $fsip + $fsport + $fsdir + "/" + $image
                                }
                                else
                                {
                                    $image_uri = $fsprotocol + "://" + $fsip + $fsport + $fsdir + "/" + $image
                                }

                                $body = @{}
                                $body["Image"] = $image_uri
                                $body["WriteProtected"] = [bool]$writeprotected
                                $body["Inserted"] = [bool]$inserted
                                if ($fsprotocol -eq "cifs") {
                                    $body["TransferProtocolType"] = $fsprotocol.ToUpper()
                                    $body["UserName"] = $fsusername
                                    $body["Password"] = $fspassword
                                }
                                $json_body = $body | convertto-json

                                $virtual_media_member_uri = "https://$ip" + $hash_table."@odata.id"
                                $response = Invoke-WebRequest -Uri $virtual_media_member_uri -Credential $bmc_credential -Method Patch -Body $json_body -ContentType 'application/json'

                                Write-Host
                                [String]::Format("- PASS, statuscode {0} returned to mount virtual media successful",$response.StatusCode)
                                return $True
                            }
                            else
                            {
                                continue
                            }
                        }

                    }
                    $result = "Up to 4 files can be concurrently mounted to the server by the BMC."
                    $result
                    return $False
                }
                else
                {
                    $result = "For remote mounts, only HTTP, HTTPS, CIFS and NFS(no credential required) protocols are supported."
                    $result
                    return $False
                }
            }
            else
            {
                # mount_virtual_from_network
                # Get MountImages url from remote map resource instance
                $response = Invoke-WebRequest -Uri $uri_remote_map -Credential $bmc_credential -Method Get -UseBasicParsing
                $converted_object = $response.Content | ConvertFrom-Json
                $hash_table = @{}
                $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
                $images_member_uri = "https://$ip" + $hash_table.MountImages."@odata.id"

                $body = @{}

                if($fsprotocol -eq "nfs")
                {
                    $body["FilePath"] = $fsip + $fsport + ":" + $fsdir + "/" + $image
                }
                elseif($fsprotocol -eq "samba")
                {
                    $body["FilePath"] = "//" + $fsip + $fsport + $fsdir + "/" + $image
                }
                elseif(($fsprotocol -eq "sftp") -or ($fsprotocol -eq "ftp") -or ($fsprotocol -eq "http"))
                {
                    $body["FilePath"] = $fsprotocol + "://" + $fsip + $fsport + $fsdir + "/" + $image
                }
                else
                {
                    $result = "Mount media iso network only support protocol Samba, NFS, HTTP, SFTP/FTP."
                    $result
                    return $False
                }

                $body["Type"] = $fsprotocol
                $body["Username"] = $fsusername
                $body["Password"] = $fspassword
                $body["Domain"] = $domain
                $body["Readonly"] = [bool]$readonly
                $body["Options"] = $options
                $json_body = $body | convertto-json

                $response = Invoke-WebRequest -Uri $images_member_uri -Credential $bmc_credential -Method Post -Body $json_body -ContentType 'application/json'
                Write-Host
                [String]::Format("- PASS, statuscode {0} returned to add image member successful",$response.StatusCode)

                $mount_image_url = "https://$ip" + $hash_table.Actions."#LenovoRemoteMapService.Mount"."target"
                $response = Invoke-WebRequest -Uri $mount_image_url -Credential $bmc_credential -Method Post -ContentType 'application/json'
                Write-Host
                [String]::Format("- PASS, statuscode {0} returned to mount virtual media successful",$response.StatusCode)
            }
        }
        else
        {
            # mount_virtual_media_from_rdoc
            # Get MountImages url from remote map resource instance
            $response = Invoke-WebRequest -Uri $uri_remote_control -Credential $bmc_credential -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $upload_url = "https://$ip" + $hash_table.Actions."#LenovoRemoteControlService.UploadFromURL"."target"

            # Get AllowableValues of protocol
            $allow_protocols = $hash_table.Actions."#LenovoRemoteControlService.UploadFromURL"."Type@Redfish.AllowableValues"
            if ($allow_protocols -notcontains $protocol) {
                $allow_protocols = $allow_protocols | ConvertTo-Json
                Write-Host
                [String]::Format("For remote mounting of RDOC images, supported protocol list: {0}.",$allow_protocols)
                return $False
            }

            if($fsprotocol -eq "samba")
            {
                $fsprotocol = "smb"
            }

            $body = @{
                "sourceURL" = $source_url;
                "Username" = $fsusername;
                "Password" = $fspassword;
                "Type" = $fsprotocol.ToUpper();
                "Readonly" = [bool]$readonly;
                "Domain" = $domain;
                "Option" = $options
            }
            $json_body = $body | convertto-json

            $response = Invoke-WebRequest -Uri $upload_url -Credential $bmc_credential -Method Post -Body $json_body -ContentType 'application/json'
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned to upload media iso successful, next will mount media iso...",$response.StatusCode)

            # Get MountImages url from remote map resource instance
            $response = Invoke-WebRequest -Uri $uri_remote_map -Credential $bmc_credential -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            $mount_image_url = "https://$ip" + $hash_table.Actions."#LenovoRemoteMapService.Mount"."target"

            $body = @{""=""}
            $json_body = $body | convertto-json
            $response = Invoke-WebRequest -Uri $mount_image_url -Method Post -Credential $bmc_credential -Body $json_body -ContentType 'application/json'
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned to mount virtual media successful",$response.StatusCode)

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
    # finally
    # {
    #     if ($session_key -ne "")
    #     {
    #         delete_session -ip $ip -session $session
    #     }
    # }
}