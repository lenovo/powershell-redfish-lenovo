###
#
# Lenovo Redfish examples - Update SNMPv3 settings for a BMC user to receive SNMPv3 TRAPs.
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

Import-module $PSScriptRoot\lenovo_utils.psm1

function check_input_password
{
    <#
   .Synopsis
    Check input password
   .DESCRIPTION
    Check input password
    - passwordstr: Pass in password string
   #>
    param(
        [Parameter(Mandatory=$True)]
        [string] $passwordstr
        )

    if($passwordstr.length -lt 10 -or $passwordstr.length -gt 32)
    { 
        return $False 
    }
        
    $count_upchar = 0
    $count_lochar = 0
    $count_num = 0
    $passwordstr_list = $passwordstr -split ''

    foreach($char in $passwordstr_list)
    {
        if($char -ne '')
        {
            $val = [int]([char]$char)
            if($val -ge 65 -and $val -le 90)
            {
                $count_upchar += 1
            }
            elseif($val -ge 97 -and $val -le 122)
            { 
                $count_lochar += 1
            }
            elseif($val -ge 48 -and $val -le 57)
            {
                $count_num += 1
            }
        }
    }
    
    if($count_upchar -gt 0 -and $count_lochar -gt 0 -and $count_num -gt 0)
    {
        return $True
    }
    else
    {
        return $False
    }
}

function update_bmc_user_snmpinfo
{
    <#
   .Synopsis
    Cmdlet used to update user snmp info to receive SNMPv3 TRAPs
   .DESCRIPTION
    Cmdlet used to update user snmp info to receive SNMPv3 TRAPs using Redfish API. Information will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - bmc_username：Input the name of BMC user to configure for receiving SNMPv3 TRAPs.
    - authentication_protocol：Specify the Authentication Protocol as HMAC_SHA96 which is the hash algorithm used by the SNMP V3 security model for the authentication.
    - privacy_protocol：Privacy protocol can be used to encrypt and protect the data transferred between the SNMP client and the agent. The supported methods are CBC_DES and CFB128_AES128.
    - privacy_password：Privacy password can be used to encrypt and protect the data transferred between the SNMP client and the agent when privacy protocol is CBC_DES or CFB128_AES128.
    - config_file: Pass in configuration file path, default configuration file is config.ini
   .EXAMPLE
    update_bmc_user_snmpinfo -ip 10.10.10.10 -username USERID -password PASSW0RD -bmc_username USERID -authentication_protocol HMAC_SHA96 -privacy_protocol CFB128_AES128 -privacy_password Aa12345678
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
        [string]$bmc_username="",
        [Parameter(Mandatory=$False)][ValidateSet("None","HMAC_SHA96")]
        [string]$authentication_protocol="None",
        [Parameter(Mandatory=$False)][ValidateSet("None", "CBC_DES", "CFB128_AES128")]
        [string]$privacy_protocol="None",
        [Parameter(Mandatory=$False)]
        [string]$privacy_password="",
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
    # check input parameter
    if($authentication_protocol -eq 'None' -and $privacy_protocol -ne 'None')
    {
        Write-Host 'If privacy_protocol is not "None", authentication_protocol cannot be "None".'
        return $False
    }
    if($privacy_protocol -eq 'None' -and !($privacy_password -eq 'None' -or $privacy_password -eq ''))
    {
        Write-Host 'If privacy_protocol is "None", privacy_password cannot be set.'
        return $False
    }
    if($privacy_protocol -ne 'None' -and ($privacy_password -eq 'None' -or $privacy_password -eq ''))
    {
        Write-Host 'privacy_password is missing.'
        return $False
    }    
    if($privacy_password -ne 'None' -and $privacy_password -ne '')
    {
        $check_password = check_input_password -passwordstr $privacy_password
        if($check_password -eq $False)
        {
            Write-Host 'Invalid privacy_password. Length of privacy_password must be no less than 10. And it must contain at least 1 uppercase letter(A~Z), at least 1 lowercase letter(a~z) and at least 1 digit(0~9).'
            return $False
        }
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

        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json
        
        $account_service_url = $converted_object.AccountService."@odata.id"
        $account_service_uri = "https://$ip" + $account_service_url
        $response = Invoke-WebRequest -Uri $account_service_uri -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        $accounts_url = $converted_object.Accounts."@odata.id"
        $accounts_uri = "https://$ip" + $accounts_url
        $response = Invoke-WebRequest -Uri $accounts_uri -Headers $JsonHeader -Method Get -UseBasicParsing
        $converted_object = $response.Content | ConvertFrom-Json

        foreach ($i in $converted_object.Members)
        {
            $account_url = "https://$ip" + $i.'@odata.id'
            
            # Get account information if account is valid (UserName not blank)
            $response_account_x_url = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method Get -UseBasicParsing
            $converted_object = $response_account_x_url.Content | ConvertFrom-Json
            $hash_table = @{}
            $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
            if($hash_table.Keys -NotContains "SNMP")
            {
                Write-Host 'Target server does not support SNMP info setting for BMC user.'
                return $False
            }
            $username_x = $converted_object.'UserName'
            # Update the BMC user snmp info when the specified BMC username is found.
            if($username_x -eq $bmc_username){
                if($hash_table.Keys -Contains "@odata.etag")
                {
                    $etag = $hash_table.'@odata.etag'
                }
                else
                {
                    $etag = ""
                }

                $JsonHeader["If-Match"] = $etag
                $parameter = @{
                        "SNMP" = @{
                            "AuthenticationProtocol" = $authentication_protocol
                            "EncryptionProtocol" = $privacy_protocol
                        }
                    }
                if($privacy_password -ne 'None' -and $privacy_password -ne '')
                {
                    $parameter["SNMP"]["EncryptionKey"] = $privacy_password
                }
                $json_body = $parameter | ConvertTo-Json
                $response = Invoke-WebRequest -Uri $account_url -Headers $JsonHeader -Method patch -Body $json_body -ContentType 'application/json'
                if($response.StatusCode -in @(200,204))
                {
                    [String]::Format("The BMC user {0} snmp info is successfully updated.", $bmc_username)
                    return $True
                } 
                else
                {
                    [String]::Format("Update BMC user snmp info failed, url {0} response error code {1} " , $account_url, $response.StatusCode)
                    return $False
                }      
            } 
        }

        Write-Host [String]::format("Specified BMC username {0} doesn't exist. Please check whether the BMC username is correct.",$bmc_username)
        return $False
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

