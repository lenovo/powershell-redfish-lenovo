###
#
# Lenovo Redfish examples - Update firmware
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
###get
Import-module $PSScriptRoot\lenovo_utils.psm1

function update_firmware
{
    <#
   .Synopsis
    Cmdlet used to update firmware
   .DESCRIPTION
    Cmdlet used to update firmware from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - imageurl: Specify the firmware to be updated. Two formats of imageURl:
                    1. Specify a full file path, for example, sftp://USERID:PASSWORD@IP:PORT/PATH.
                    2. Specify the firmware name, but must be used with the following parameters: fsip, fsport, fsuserName, fspassword, fsdir.
    - fsprotocol: Specify the file server protocol. Support: ["SFTP". "TFTP", "HTTP", "HTTPS" ,"HTTPPUSH"]
    - fsip: Specify the file server ip.
    - fsport: Specify the file server port.
    - fsusername: Specify the file server username, only for SFTP.
    - fspassword: Specify the file server password, only for SFTP.
    - fsdir: Specify the file server dir to the firmware upload.
   .EXAMPLE
    SFTP:
        update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol SFTP -imageurl "sftp://USERID:PASSWORD@IP:PORT/PATH"
        update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol SFTP -fsip 10.10.10.11 -fsusername mysftp -fspassword mypass -fsdir /fspath/ -imageurl lnvgy_fw_xcc_cdi388g-7.80_anyos_noarch.uxz
    TFTP:
        update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol TFTP -imageurl "tftp://IP/PATH"
        update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol TFTP -fsip 10.10.10.11  -fsdir /fspath/ -imageurl lnvgy_fw_xcc_cdi388g-7.80_anyos_noarch.uxz
    HTTPPUSH:
        update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol HTTPPUSH -imageurl /fspath/lnvgy_fw_xcc_cdi388g-7.80_anyos_noarch.uxz
        update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -fsprotocol HTTPPUSH -fsdir /fspath/ -imageurl lnvgy_fw_xcc_cdi388g-7.80_anyos_noarch.uxz
   #>

    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True, HelpMessage='Specify the firmware to be updated. Two formats of imageURl:
                    1. Specify a full file path, for example, sftp://USERID:PASSWORD@IP:PORT/PATH.
                    2. Specify the firmware name, but must be used with the following parameters: fsip, fsport, fsuserName, fspassword, fsdir.')]
        [string]$imageurl="",
        [Parameter(Mandatory=$True, HelpMessage='Specify the file server protocol. Support:["SFTP", "TFTP", "HTTPPUSH", "HTTP", "HTTPS"]')]
        [string]$fsprotocol="",
        [Parameter(Mandatory=$False, HelpMessage='Specify the file server ip.')]
        [string]$fsip="",
        [Parameter(Mandatory=$False, HelpMessage='Specify the file server port.')]
        [string]$fsport="",
        [Parameter(Mandatory=$False, HelpMessage='Specify the file server username, only for SFTP.')]
        [string]$fsusername="",
        [Parameter(Mandatory=$False, HelpMessage='Specify the file server password, only for SFTP.')]
        [string]$fspassword="",
        [Parameter(Mandatory=$False, HelpMessage='Specify the file server dir to the firmware upload. ')]
        [string]$fsdir="",
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key}
        
        # Get the server root resource
        $root_url = "https://$ip" + "/redfish/v1/"
        $response = Invoke-WebRequest -Uri $root_url -Headers $JsonHeader -Method Get -UseBasicParsing 

        # Get the update service url from the root resource
        $converted_object = $response.Content | ConvertFrom-Json
        $update_service_url = "https://$ip" + $converted_object.UpdateService.'@odata.id'
        # Get the update service resource
        $response = Invoke-WebRequest -Uri $update_service_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Get the update firmware url from the update service resource
        $converted_object = $response.Content | ConvertFrom-Json
        if ($fsprotocol.ToLower() -eq "httppush") {
            if ($imageurl  -and $fsdir) {
                $file_path = [io.path]::Combine($fsdir, $imageurl)
            }else {
                $file_path = $imageurl
            }
            if ((Test-Path $file_path) -ne "True") {
                Write-Host "The path '$file_path' doesn't exist, please check the 'fsdir' or 'imageurl' is correct."
                return $False
            }
            $update_firmware_url = " https://$ip" + $converted_object."HttpPushUri"
            $files = [System.IO.File]::ReadAllBytes($file_path)

            $response = Invoke-WebRequest -Uri $update_firmware_url -Headers $JsonHeader -Method Post  -Body $files
        }else{
            $update_firmware_dict = $converted_object.Actions.'#UpdateService.SimpleUpdate'
            # Check whether the current protocol is allowed to update firmware
            if ($update_firmware_dict."TransferProtocol@Redfish.AllowableValues") {
                $support_list = $update_firmware_dict."TransferProtocol@Redfish.AllowableValues" | ConvertTo-Json
                if (!$support_list.Contains($fsprotocol.ToUpper())) {
                    Write-Host
                    [String]::Format("{0} isn't supported. Supported protocol list: {1}.", ($fsprotocol, $support_list))
                    return $False
                }
            }

            # The property VerifyRemoteServerCertificate exists
            if ($fsprotocol.ToLower() -eq "https" -and ($converted_object.VerifyRemoteServerCertificate -or $converted_object.RemoteServerCertificates)){
                if ($converted_object.VerifyRemoteServerCertificate -eq $True) {
                    $remote_url = "https://$ip" + $converted_object.RemoteServerCertificates."@odata.id"
                    $remote_response = Invoke-WebRequest -Uri $remote_url -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $remote_response | ConvertFrom-Json
                    if ($converted_object."Members@odata.count" -eq 0) {
                        Write-Host "Target server require certificate verification of HTTPS file server. Please go to 'lenovo_https_certificate_import.psm1' script to upload the certificate."
                        return $False
                    }
                }
            }

            $update_firmware_url = "https://$ip" + $update_firmware_dict.'target'
            # Update firmware via file server
            if ($imageurl -and $fsdir) {
                if ($fsport) {
                    $fsport = ":" + $fsport
                }
                if ($fsdir){
                    $fsdir = "/" + $fsdir.Trim("/")
                }
                if ($fsprotocol.ToLower() -eq "sftp") {
                    $file_path = $fsprotocol.ToLower() + "://" + $fsusername + ":" + $fspassword + "@" + $fsip + $fsport + $fsdir + "/" + $imageurl
                }else {
                    $file_path = $fsprotocol.ToLower() + "://" + $fsip + $fsport + $fsdir + "/" + $imageurl
                }
            }else{
                $file_path = $imageurl
            }
            $body = @{"ImageURI"=$file_path; "Targets"=@(); "TransferProtocol"=$fsprotocol}
            $json_body = $body | convertto-json
            $response = Invoke-WebRequest -Uri $update_firmware_url -Headers $JsonHeader -Method Post -Body $json_body -ContentType 'application/json'
        }
        try
        {
            # The system will create a task to let user know the update firmware status
            if ($response.StatusCode -eq 202) {
                $converted_object = $response.Content | ConvertFrom-Json
                $task_uri = "https://$ip" + $converted_object.'@odata.id'

                $result = task_monitor($task_uri)
                if ($result -ne $False) {
                    $message = $result.msg
                    if ($result.task_state -eq "Completed") {
                        Write-Host
                        [String]::Format("- PASS. Update firmware successfully. {0}", $message)
                        return $True
                    }else{
                        Write-Host
                        [String]::Format("Taskstate exception, firmware update failed. {0}", $message)
                        return $False
                    }
                }else{
                    return $False
                }
            }elseif($response.StatusCode -eq 200 -or $response.StatusCode -eq 204){
                Write-Host "- PASS. Update firmware successfully."
                return $True
            }
        }
        catch
        {
            # Handle http exception response for Post request
            if ($_.Exception.Response)
            {
                Write-Host "Error occured, status code:" $_.Exception.Response.StatusCode.Value__
                if($_.ErrorDetails.Message)
                {
                    $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                    $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                    Write-Host "Error message:" $response_j.Resolution
                }
            }
            # Handle system exception response for Post request
            elseif($_.Exception)
            {
                Write-Host "Error message:" $_.Exception.Message
                Write-Host "Please check arguments or server status."
            }
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

function task_monitor($task_uri) {
    # Monitor task status
    Write-Host $task_uri
    $RUNNING_TASK_STATE = "New", "Pending", "Service", "Starting", "Stopping", "Running", "Cancelling", "Verifying"
    $END_TASK_STATE = "Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended"

    $current_state = ""
    $task_state = ""
    $num_503 = 0
    while($True)
    {
        # Get the task uri response
        $response = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Get -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            $converted_object = $response.Content | ConvertFrom-Json
            $task_state = $converted_object.TaskState
            if ($converted_object.Messages) {
                $messages = $converted_object.Messages
            }
            if ($converted_object.PercentComplete) {
                $percent = $converted_object.PercentComplete
            }
            if ($RUNNING_TASK_STATE -contains $task_state) {
                if ($task_state -ne $current_state) {
                    $current_state = $task_state
                    Write-Host "Task state is $current_state, wait a minute."
                    continue
                }else{
                    flush($percent)
                }
            }elseif($task_state | Where-Object {$_.startswith("Downloading")}){
                Write-Host (" "*100),"`r"
                Write-Host $task_state,"`r" -NoNewline
                continue
            }elseif($task_state | Where-Object {$_.startswith("Update")}){
                Write-Host (" "*100),"`r"
                Write-Host $task_state,"`r" -NoNewline
                continue
            }elseif($END_TASK_STATE -contains $task_state){
                Write-Host (" "*100),"`r"
                Write-Host "End of the task."
                $result = @{"task_state"=$task_state; "msg"=[String]::Format("Message: {0}", $messages.Message)}
                return $result
            }else{
                if ($messages) {
                    Write-Host
                    [String]::Format("Unknown TaskState {0}. Task Not conforming to Schema Specification. Messages: {1}", ($task_state, $messages))
                }else{
                    Write-Host
                    [String]::Format("Unknown TaskState {0}. Task Not conforming to Schema Specification.", $task_state)
                }
                return $False
            }
        }elseif($response.StatusCode -eq 503 -and $num_503 -lt 3){
            $num_503 += 1
            continue
        }
    }
}

function flush($percent) {
    $list = "|", "\", "-", "/"
    foreach ($i in $list) {
        Write-Host $i, ((' '*10),"PercentComplete",$percent),"`r" -NoNewline
        Start-Sleep -m 500
    }
}