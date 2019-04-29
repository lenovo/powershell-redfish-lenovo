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
    - target: Specify the targets firmware to be updated. Support:["BMC-Primary", "BMC-Backup", "UEFI", "LXPM", "LXPMWindowsDriver1", "LXPMLinuxDriver1","Adapter"]
    - image_url: Specify the path of the firmware to be updated. The format of imageURl must be "sftp://..." or "tftp://...
    - fsprotocol: Specify the file server protocol. Support:["SFTP". "TFTP"]
   .EXAMPLE
    update_firmware -ip 10.10.10.10 -username USERID -password PASSW0RD -target "BMC-Primary" -imager_url "sftp://USERID:PASSWORD@IP/PATH" -fsprotocol SFTP
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$True, HelpMessage='Specify the target list firmware to be updated. ')]
        [array]$target="",
        [Parameter(Mandatory=$True, HelpMessage='Specify the path of the firmware to be updated. The format of imageURl must be "sftp://..." or "tftp://...')]
        [string]$imageurl="",
        [Parameter(Mandatory=$True, HelpMessage='Specify the file server protocol. Support:["SFTP". "TFTP"]')]
        [string]$fsprotocol="",
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
        $update_firmware_url = "https://$ip" + $converted_object.Actions.'#UpdateService.SimpleUpdate'.'target'

        # Build request body
        $targets_list = $target
        $body = @{"ImageURI"=$imageurl; "Targets"=$targets_list; "TransferProtocol"=$fsprotocol}
        $json_body = $body | convertto-json
        try
        {
            $response = Invoke-WebRequest -Uri $update_firmware_url -Headers $JsonHeader -Method Post -Body $json_body -ContentType 'application/json'

            # The system will create a task to let user know the update firmware status
            if ($response.StatusCode -eq 202)
            {
                $converted_object = $response.Content | ConvertFrom-Json
                $task_uri = "https://$ip" + $converted_object.'@odata.id'
                $task_uri

                $task_state = ""
                while("Completed", "OK" -contains $task_state)
                {
                    # Get the task uri response
                    $response = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Get -UseBasicParsing
                    $converted_object = $response.Content | ConvertFrom-Json
                    $task_state = $converted_object.TaskState
                    if($task_state -eq "Exception")
                    {
                        Write-Host "Taskstate exception, firmware update failed."
                        return $False
                    }
                    Start-Sleep -Seconds 1
                }

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
        Write-Host
        [String]::Format("- PASS, statuscode {0} returned successfully update firmware", $response.StatusCode) 
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