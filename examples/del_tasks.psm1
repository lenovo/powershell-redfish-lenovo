###
#
# Lenovo Redfish examples - Del tasks
#
# Copyright Notice:
#
# Copyright 2022 Lenovo Corporation
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

function del_tasks
{
   <#
   .Synopsis
    Cmdlet used to Del tasks
   .DESCRIPTION
    Cmdlet used to Del tasks from BMC using Redfish API
    Connection information can be specified via command parameter or configuration file
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    
    optional parameter:you can only use one option [all/id] 
    - all: Delete all tasks
    - id: Pass in the task id you want to delete
   .EXAMPLE
    del_tasks -ip 10.10.10.10 -username USERID -password PASSW0RD -id ID / -all 
   #>

   param
   (
       [Parameter(ParameterSetName='all',Mandatory=$True)]
       [switch]$all,
       [Parameter(ParameterSetName='id',Mandatory=$True)]
       [string]$id,
       [Parameter(Mandatory=$False)]
       [string]$ip="",
       [Parameter(Mandatory=$False)]
       [string]$username="",
       [Parameter(Mandatory=$False)]
       [string]$password="",
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
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

        # Get the base url collection
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json       

        #Get taskservice url resource
        $taskservice_url = "https://$ip" + $converted_object.Tasks."@odata.id"
        $response = Invoke-WebRequest -Uri $taskservice_url -Header $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
     
        #Get taskservice tasks
        $tasks_url = "https://$ip" + $converted_object.Tasks."@odata.id"
        $response = Invoke-WebRequest -Uri $tasks_url -Header $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        
        if ($converted_object.Members.Length -eq 0)
        {
            Write-Host "There are no tasks found in this system!"
            return $True
        }
        $delete_url_list = @()
        foreach ($item in $converted_object.Members) 
        {
            $tmp_url = "https://$ip" + $item."@odata.id"
            $response = Invoke-WebRequest -Uri $tmp_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response.Content | ConvertFrom-Json
            if ($id) 
            {
                if ($id -eq $tmp_url.split("/")[-1])
                {
                    $delete_url_list += $tmp_url
                }
            }
            if ($all) 
            {
                $delete_url_list += $tmp_url
            }
        }
        if ($delete_url_list.Length -eq 0) 
        {
            Write-Host "There are no tasks to match the id specified."
            return $False
        }
        #Del tasks
        if($delete_url_list.Length -gt 0)
        {
            foreach($del_url in $delete_url_list)
            {
                $response = Invoke-WebRequest -Uri $del_url -Headers $JsonHeader -Method Delete -UseBasicParsing
            }
        }
        Write-Host "Del tasks successfully"
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
       
