###
#
# Lenovo Redfish examples - Reset BIOS Default
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


function reset_bios_default{
   <#
   .Synopsis
    Cmdlet used to reset BIOS default values
   .DESCRIPTION
    Cmdlet used to reset BIOS default values using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - system_id: Pass in System resource instance id(none: first instance, all: all instances)
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    reset_bios_default -ip 10.10.10.10 -username USERID -password PASSW0RD
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
        [string]$config_file="config.ini"
        )
        

    # get configuration info from config file
    $ht_config_ini_info = read_config -config_file $config_file
    
    # if the parameter is not specified via command line, use the setting from configuration file
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
        # create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        #build headers with sesison key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }
        
        # get the system url collection
        $system_url_collection = @()
        $system_url_collection = get_system_urls -bmcip $ip -session $session -system_id $system_id

        # loop all System resource instance in $system_url_collection
        foreach ($system_url_string in $system_url_collection)
        {
            
            # get Bios from the System resource instance
            $uri_address_system = "https://$ip"+$system_url_string
            
            $response = Invoke-WebRequest -Uri $uri_address_system -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            
            $temp = [string]$hash_table.BIOS
            $uri_address_bios = "https://$ip"+($temp.Split("=")[1].Replace("}",""))

            $response = Invoke-WebRequest -Uri $uri_address_Bios -Headers $JsonHeader -Method Get -UseBasicParsing

            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

            # Reset Bios default value for the System resource instance
            $temp = $hash_table."Actions"."#Bios.ResetBios"."target"
            $uri_reset_bios_default = "https://$ip"+ $temp
            $JsonBody = @{}|ConvertTo-Json -Compress
            
            $body = @{}
            if($converted_object.Actions.'#Bios.ResetBios'.'@Redfish.ActionInfo')
            {
               $url_actioninfo = "https://$ip"+$hash_table.Actions.'#Bios.ResetBios'.'@Redfish.ActionInfo'
               $response = Invoke-WebRequest -Uri $url_actioninfo -Headers $JsonHeader -Method Get -UseBasicParsing
               $converted_object = $response.Content | ConvertFrom-Json
               foreach($parameter in $converted_object."Parameters")
               {
                   if($parameter."Name" -and $parameter."AllowableValues")
                   {
                       $values = $parameter."AllowableValues"
                       $body = @{$parameter."Name"=$values[0]}
                   }
               }
            }
            $json_body = $body | convertto-json
                
            $response = Invoke-WebRequest -Uri $uri_reset_bios_default -Headers $JsonHeader -Method Post -Body $json_body -ContentType 'application/json'            

            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to reset bios default.",$response.StatusCode)

            return $True
        }
    }
    catch
    {
        if($_.Exception.Response)
        {
            Write-Host "Error occured, error code:" $_.Exception.Response.StatusCode.Value__
            if ($_.Exception.Response.StatusCode.Value__ -eq 401)
            {
                Write-Host "Error message: You are required to log on Web Server with valid credentials first."
            }
            if ($_.ErrorDetails.Message)
            {
                $response_j = $_.ErrorDetails.Message | ConvertFrom-Json | Select-Object -Expand error
                $response_j = $response_j | Select-Object -Expand '@Message.ExtendedInfo'
                Write-Host "Error message:" $response_j.Resolution
            }
        } 
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