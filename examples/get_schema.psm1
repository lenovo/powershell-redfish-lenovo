###
#
# Lenovo Redfish examples - Get schema
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

function get_schema
{
    <#
   .Synopsis
    Cmdlet used to get schema info
   .DESCRIPTION
    Cmdlet used to get schema info status from BMC using Redfish API.  Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - schema_prefix:Pass in schema prefix, get all schema with 'all', default value is 'all'
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    get_schema -ip 10.10.10.10 -username USERID -password PASSW0RD -schema_prefix all
   #>
   
    param(
        [System.String]
        [Parameter(Mandatory=$False)]
        $schema_prefix = "all",
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

        # Get base resource
        $base_url = "https://$ip" + "/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        
        # Get Json_Schemas resource
        $Json_Schemas_url = "https://$ip" + $converted_object.JsonSchemas."@odata.id"
        $response = Invoke-WebRequest -Uri $Json_Schemas_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        $schema_list = $converted_object."Members"
        $data_schema = @()
        $isfind = $False
        # Loop schema resource in shema list
        foreach($schema in $schema_list)
        {
            # Get schema url string
            $schema_url ="https://$ip" +  $schema."@odata.id"

            # Different server's type has different end character
            if($schema_url.EndsWith("/"))
            {
               $compare_schema = $schema_url.split('/')[-2]
            }
            else
            {
                $compare_schema = $schema_url.split('/')[-1]
            }

            # Match the prefix in schema string
            if($schema_prefix -eq "all" -or $schema_prefix -eq $compare_schema)
            {
                $tmp_schema = $schema_prefix
                if($schema_prefix -eq "all")
                {
                    $tmp_schema = $compare_schema
                }

                # Get schema resource 
                $response = Invoke-WebRequest -Uri $schema_url -Headers $JsonHeader -Method Get -UseBasicParsing
                $converted_object_schema = $response.Content | ConvertFrom-Json
                $ht_location = @{}

                # Get schema 
                foreach($location in $converted_object_schema.Location)
                {
                    $isfind = $True
                    # Check the uri is existed or not
                    $url ="https://$ip" +  $location.Uri
                    try
                    {
                        # Get schema uri
                        $response = Invoke-WebRequest -Uri $url -Headers $JsonHeader -Method Get -UseBasicParsing
                        $converted_object = $response.Content | ConvertFrom-Json
                        $ht_location[$tmp_schema] = "Found $tmp_schema,uri:$url"
                    }
                    catch
                    {
                        # Get uri fail
                        $ht_location[$tmp_schema] = "Found $tmp_schema,but can not get uri:$url"
                    }
                    
                    # Return result
                    $ht_location | ConvertTo-Json
                }
                
            }
            else
            {
                # No schema string matching continue
                continue
            }
        }

        # If not find
        if(-not $isfind)
        {
            Write-Host "can't find $schema_prefix"
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

