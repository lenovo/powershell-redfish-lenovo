﻿###
#
# Lenovo Redfish examples - Bmc config backup
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

function lenovo_bmc_config_backup
{
    <#
   .Synopsis
    Cmdlet used to Bmc config backup
   .DESCRIPTION
    Cmdlet used to Get power limit from BMC using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id:Pass in ComputerSystem instance id(None: first instance, all: all instances)
    - backuppasswd:Pass in a password that will be used to encrypt values in the file.Note that you will be asked for this password when you use the file to restore a configuration.
    - backupfile:Pass in the file you want to save the backup configuration.default file is ./bmc_config_backup.json
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_bmc_config_backup -ip 10.10.10.10 -username USERID -password PASSW0RD -backupfile ./bmc_config_backup.json -backuppasswd 123456789
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$backupfile="./bmc_config_backup.json",
        [Parameter(Mandatory=$True)]
        [string]$backuppasswd,
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
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
    if($backuppasswd.Length -lt 9)
    {
        Write-Host "Password is at least 9 characters"
        return $False
    }

    try
    {
        $session_key = ""
        $session_location = ""

        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with sesison key for authentication
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }
        
        # Get the manager url
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $managers_url = $converted_object.Managers."@odata.id"

        #Get manager list 
        $manager_url_collection = @()
        $managers_url_string = "https://$ip"+ $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        foreach($i in $converted_object.Members)
        {
               $tmp_manager_url_string = "https://$ip" + $i."@odata.id"
               $manager_url_collection += $tmp_manager_url_string
        }
        
        # Loop all manager resource instance in $manager_url_collection
        foreach($manager_url_string in $manager_url_collection)
        {
            #get manager resource
            $response = Invoke-WebRequest -Uri $manager_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json

            #Get config url
            $oem_info = $converted_object.Oem.Lenovo
            $config_url = "https://$ip" + $oem_info.Configuration."@odata.id"
            
            #Get backup action url
            $response = Invoke-WebRequest -Uri $config_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            $action_backup_url = "https://$ip" + $converted_object.Actions."#LenovoConfigurationService.BackupConfiguration".target

            #Backup config
            $JsonBody = @{"Passphrase"=$backuppasswd}|ConvertTo-Json -Compress
            $response = Invoke-WebRequest -Uri $action_backup_url -Method Post -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
            $converted_object = $response.Content | ConvertFrom-Json
            $data = $converted_object.data
            $data|ConvertTo-Json | Out-File $backupfile
            $size = getDocSize -backupfile $backupfile
            if([double]$size -gt 255)
            {
                Remove-Item $backupfile
                Write-Host "Failed to back up the configuration because the size of configuration data is over 255KB."
                return $False
            }
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to backup config,file size is {1}KB",$response.StatusCode,$size)
            return $True
        }     
    }
    catch
    {
        # Handle http exception response
        if($_.Exception.Response)
        {
            $info=$_.InvocationInfo
            [String]::Format("`n-Error occured!file:{0} line:{1},col:{2},msg:{3},fullname:{4}`n" ,$info.ScriptName,$info.ScriptLineNumber,$info.OffsetInLine ,$_.Exception.Message,$_.Exception.GetType().FullName)
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

#get file size
function getDocSize
{
    param(
        [Parameter(Mandatory=$True)]
        [string]$backupfile
        )
    $Item = Get-Item $backupfile|select Length
    $size = $Item.Length/1KB
    return $size
}