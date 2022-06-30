###
#
# Lenovo Redfish examples - Restart Manager
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


function restart_bmc
{
   <#
   .Synopsis
    Cmdlet used to restart manager
   .DESCRIPTION
    Cmdlet used to restart manager using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    restart_bmc -ip 10.10.10.10 -username USERID -password PASSW0RD
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
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
    if ($manager_restart_value -eq "")
    {
        Write-Host "Please input manager_restart_value."
        return
    }
    if ($manager_id -eq "")
    {
        $manager_id = [string]($ht_config_ini_info['ManagerId'])
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

        # check connection
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        
        $managers_url = $converted_object.Managers."@odata.id"
        $managers_url_string = "https://$ip" + $managers_url
        $response = Invoke-WebRequest -Uri $managers_url_string -Headers $JsonHeader -Method Get -UseBasicParsing 
        
        # get the manager url collection
        $manager_url_collection = @()
        # convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }

        # set the $manager_url_collection by checking $manager_id value
        foreach ($i in $hash_table.Members)
        {
            $i = [string]$i
            $manager_url_string = ($i.Split("=")[1].Replace("}",""))   
            $manager_url_id = $manager_url_string.Split("/")[4]
            $manager_url_collection += $manager_url_string
        }

        # loop all manager resource instance in $manager_url_collection
        foreach ($manager_url_string in $manager_url_collection)
        {
            
            # get Manager restart url from the Manager resource instance
            $uri_address_manager = "https://$ip"+$manager_url_string
            
            $response = Invoke-WebRequest -Uri $uri_address_manager -Headers $JsonHeader -Method Get -UseBasicParsing
            
            $converted_object = $response.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            
            # set PowerAction for the Manager resource instance
            $temp = $hash_table."Actions"."#Manager.Reset"."target"
            $uri_restart_manager = "https://$ip"+$temp

            $body = @{}
            if($converted_object.Actions."#Manager.Reset".'@Redfish.ActionInfo')
            {
                $url_actioninfo = "https://$ip"+$converted_object.Actions."#Manager.Reset".'@Redfish.ActionInfo'
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
                $JsonBody = $body | ConvertTo-Json -Compress
            }elseif($hash_table."Actions"."#Manager.Reset"."ResetType@Redfish.AllowableValues")
            {
                $JsonBody = @{ "ResetType" = "GracefulRestart"
                    } | ConvertTo-Json -Compress
            }
            else 
            {
                $JsonBody = @{
                    "Action" = "Manager.Reset"
                    } | ConvertTo-Json -Compress
            }

            $response = Invoke-WebRequest -Uri $uri_restart_manager -Headers $JsonHeader -Method Post -Body $JsonBody -ContentType 'application/json'
            
            if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 204)
            {
                Write-Host
                [String]::Format("- PASS, statuscode {0} returned successfully to restart manager",$response.StatusCode)
                return $True
            }
            elseif ($response.StatusCode -eq 202)
            {
                $converted_object = $response.Content | ConvertFrom-Json
                $task_uri = "https://$ip" + $converted_object.'@odata.id'
                
                $result = task_monitor $session_key $task_uri

                # Delete the task when the task state is completed without any warning
                $severity = ''
                if ($result.ret -eq $True -and $result.task_state -eq "Completed" -and $result.msg -ne '')
                {
                    if ($null -ne $result.msg.'Severity')
                    {
                        $severity = $result.msg.'Severity'
                    }
                }
                if ($result.ret -eq $True -and $result.task_state -eq "Completed" -and ($result.msg -eq '' -or $severity -eq "OK"))
                {
                    $response_deltask = Invoke-WebRequest -Uri $task_uri -Headers $JsonHeader -Method Delete -UseBasicParsing
                }
                if ($result.ret -eq $True)
                {
                    $task_state = $result.task_state
                    if ($task_state -eq "Completed")
                    {
                        Write-Host
                        [String]::Format("- PASS, Restart BMC successfully. Messages: {0}", $result.msg.Message) 
                        return $True
                    }
                    else
                    {
                        Write-Host
                        [String]::Format("Failed to restart BMC. Messages: {0}", $result.msg.Message) 
                        return $False
                    }
                }
            }
        }
        
        return $True
        
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
            elseif ($_.ErrorDetails.Message)
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