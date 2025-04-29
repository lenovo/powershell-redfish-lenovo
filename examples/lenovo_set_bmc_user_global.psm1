###
#
# Lenovo Redfish examples - Set the current BMC user global
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

function lenovo_set_bmc_user_global
{
   <#
   .Synopsis
    Cmdlet used to set bmc user global
   .DESCRIPTION
    Cmdlet used to set bmc user global from BMC using Redfish API. BMC user info will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    lenovo_set_bmc_user_global -ip 10.10.10.10 -username USERID -password PASSW0RD
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$ip="",
        [Parameter(Mandatory=$False)]
        [string]$username="",
        [Parameter(Mandatory=$False)]
        [string]$password="",
        [Parameter(Mandatory=$False)]
        [int]$PasswordChangeOnFirstAccess=-1,
        [Parameter(Mandatory=$False)]
        [int]$PasswordChangeOnNextLogin=-1,
        [Parameter(Mandatory=$False)]
        [int]$PasswordExpirationPeriodDays=-1,
        [Parameter(Mandatory=$False)]
        [int]$PasswordExpirationWarningPeriod=-1,
        [Parameter(Mandatory=$False)]
        [int]$MinimumPasswordLength=-1,
        [Parameter(Mandatory=$False)]
        [int]$MinimumPasswordReuseCycle=-1,
        [Parameter(Mandatory=$False)]
        [int]$MinimumPasswordChangeIntervalHours=-1,
        [Parameter(Mandatory=$False)]
        [int]$LockThreshold=-1,
        [Parameter(Mandatory=$False)]
        [int]$LockDuration=-1,
        [Parameter(Mandatory=$False)]
        [string]$config_file="config.ini"
        )

    $OemArgs = @("PasswordChangeOnNextLogin",
        "MinimumPasswordChangeIntervalHours", "PasswordExpirationPeriodDays",
        "PasswordChangeOnFirstAccess", "MinimumPasswordReuseCycle",
        "MinimumPasswordLength", "PasswordExpirationWarningPeriod")
        
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

        $base_url = "https://$ip/redfish/v1/"
        # Create session
        $session = create_session -ip $ip -username $username -password $password
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location
        $JsonHeader = @{ 
            "X-Auth-Token" = $session_key
            "Accept" = "application/json"
        }

        # Get the account server url via Invoke-WebRequest
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response content to hash table
        $converted_object = $response.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        $account_service_url_string = "https://$ip"+$hash_table.AccountService.'@odata.id'

        # Get the accountservice url via Invoke-WebRequest
        $response_account_service = Invoke-WebRequest -Uri $account_service_url_string -Headers $JsonHeader -Method Get -UseBasicParsing

        # Convert response_account_server content to hash table
        $converted_object = $response_account_service.Content | ConvertFrom-Json
        $hash_table = @{}
        $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
        
        $ht_userglobal_set = @{}
        foreach ($item in $OemArgs)
        {
            if($(Get-Variable "$item" -ValueOnly) -ne -1)
            {                
                $ht_userglobal_set['Oem'] = @{}
                $ht_userglobal_set['Oem']['Lenovo'] = @{}
                break
            }
            
        }

        if(-1 -ne $LockThreshold)
        {
            $ht_userglobal_set['AccountLockoutThreshold'] = $LockThreshold
        }
        if(-1 -ne $LockDuration)
        {
            $ht_userglobal_set['AccountLockoutDuration'] = $LockDuration
        }
        if(-1 -ne $PasswordChangeOnFirstAccess)
        {
            $ht_userglobal_set['Oem']['Lenovo']['PasswordChangeOnFirstAccess'] = [bool]$PasswordChangeOnFirstAccess
        }
        if(-1 -ne $PasswordChangeOnNextLogin)
        {
            $ht_userglobal_set['Oem']['Lenovo']['PasswordChangeOnNextLogin'] = [bool]$PasswordChangeOnNextLogin
        }
        if(-1 -ne $PasswordExpirationPeriodDays)
        {
            $ht_userglobal_set['Oem']['Lenovo']['PasswordExpirationPeriodDays'] = $PasswordExpirationPeriodDays
        }
        if(-1 -ne $PasswordExpirationWarningPeriod)
        {
            $ht_userglobal_set['Oem']['Lenovo']['PasswordExpirationWarningPeriod'] = $PasswordExpirationWarningPeriod
        }
        if(-1 -ne $MinimumPasswordLength)
        {
            $ht_userglobal_set['Oem']['Lenovo']['PasswordLength'] = $MinimumPasswordLength
        }
        if(-1 -ne $MinimumPasswordReuseCycle)
        {
            $ht_userglobal_set['Oem']['Lenovo']['MinimumPasswordReuseCycle'] = $MinimumPasswordReuseCycle
        }
        if(-1 -ne $MinimumPasswordChangeIntervalHours)
        {
            $ht_userglobal_set['Oem']['Lenovo']['MinimumPasswordChangeIntervalHours'] = $MinimumPasswordChangeIntervalHours
        }

        $json_body = $ht_userglobal_set | convertto-json
        $response = Invoke-WebRequest -Uri $account_service_url_string -Headers $JsonHeader -Method Patch  -Body $json_body -ContentType 'application/json'

        Write-Host
        [String]::Format("- PASS, statuscode {0} returned successfully update oem bmc user global", $response.StatusCode) 
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
    finally
    {
        if ($session_key -ne "")
        {
            delete_session -ip $ip -session $session
        }
    }
}
    
