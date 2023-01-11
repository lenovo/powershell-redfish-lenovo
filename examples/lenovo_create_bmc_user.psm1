###
#
# Lenovo Redfish examples - Create bmc user
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


function lenovo_create_bmc_user
{
    <#
   .Synopsis
    Cmdlet used to create bmc user
   .DESCRIPTION
    Cmdlet used to create bmc user from BMC using Redfish API. Set result will be printed to the screen. Connection information can be specified via command parameter or configuration file.
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
    - config_file: Pass in configuration file path, default configuration file is config.ini
    - newusername: Pass in the update account username
    - newuserpassword: Pass in user new userpasswd
    - authority: The value of this parameter shall be the privileges that this user includes. For super user, this property shall be Supervisor. default is Supervisor. For the user to view information only, this property shall be ReadOnly. For other OEM authority, You can only choose one or more values in the OEM privileges list:[UserroleManagement,RemoteConsoleAccess,RemoteConsoleAndVirtualMediaAcccess,RemoteServerPowerRestartAccess,AbilityClearEventLogs,AdapterConfiguration_Basic,AdapterConfiguration_NetworkingAndSecurity,AdapterConfiguration_Advanced]
   .EXAMPLE
    lenovo_create_bmc_user -ip 10.10.10.10 -username USERID -password PASSW0RD -newusername NEWUSERNAME -newuserpassword NEWPASSW0RD -authority @("Supervisor")
   #>
   
    param
    (
        [Parameter(Mandatory=$True)]
        [string]$newusername,
        [Parameter(Mandatory=$True)]
        [string]$newuserpassword,
        [Parameter(Mandatory=$False)]
        [String[]]$authority = @("Supervisor"),
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
        $JsonHeader = @{ "X-Auth-Token" = $session_key}
      
        # Get the base url collection
        $manager_url_collection = @()
        $base_url = "https://$ip/redfish/v1/"
        $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object = $response.Content | ConvertFrom-Json

        #Get accountservice resource
        $url_account_service ="https://$ip" + $converted_object.AccountService."@odata.id"
        $response = Invoke-WebRequest -Uri $url_account_service -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object_account_service = $response.Content | ConvertFrom-Json

        #Get accounts resource
        $url_accounts = "https://$ip" + $converted_object_account_service.Accounts."@odata.id"
        $response = Invoke-WebRequest -Uri $url_accounts -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object = $response.Content | ConvertFrom-Json

        $create_mode = "POST_Action"
        if(!$response.Headers['Allow'].contains('POST'))
        {
            $create_mode = "PATCH_Action"
        }
        if($create_mode -eq "POST_Action")
        {
            #Set rolename
            $role_name = ""
            if("Supervisor"  -in $authority)
            {
                $role_name = "Administrator"
            }elseif("Operator"  -in $authority)
            {
                $role_name = "Operator"
            }elseif("ReadOnly"  -in $authority)
            {
                $role_name = "ReadOnly"
            }else
            {
                $role_name = $authority[0]
            }
            $JsonBody = @{ "Password"=$newuserpassword
                "Name"=$newusername
                "UserName"=$newusername
                "RoleId"=$role_name
                "Enabled" = $true
                } | ConvertTo-Json -Compress
            $response = Invoke-WebRequest -Uri $url_accounts -Method Post -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to create account {1}",$response.StatusCode,$newusername)
        }

        if($create_mode -eq "PATCH_Action")
        {
            $list_url_account = @()
            foreach($url_account in $converted_object.Members)
            {
                $list_url_account += $url_account."@odata.id" 
            }
            #Get the first empty account url
            $url_dest = ""
            $roleuri = ""
            foreach($url_tmp_account in $list_url_account)
            {
                $url_account = "https://$ip" + $url_tmp_account
                $response = Invoke-WebRequest -Uri $url_account -Headers $JsonHeader -Method Get -UseBasicParsing 
                $converted_object = $response.Content | ConvertFrom-Json

                if($converted_object.UserName -eq "" -and $url_dest -eq "")
                {
                    $url_dest = $url_account
                    $roleuri = $converted_object."Links"."Role"."@odata.id"
                    $user_pos = $url_dest.Split("/")[-1]
                }
                elseif($converted_object.UserName -eq $newusername)
                {
                    Write-Host "username $newusername is existed"
                    return $False
                }
            }
            if($url_dest -eq "")
            {
                Write-Host "accounts is full,can't create a new account"
                return $False
            }
            $links_role = @{}
            if ("Supervisor" -in $authority -or "Administrator" -in $authority) 
            {
                $role_name = "Administrator"
            }
            elseif ("Operator" -in $authority) 
            {
                $role_name = "Operator"
            }
            elseif ("ReadOnly" -in $authority) 
            {
                $role_name = "ReadOnly"
            }
            else{
                $role_name = "CustomRole" + [string]$user_pos
                $result = set_custom_role_privileges -bmcip $ip -session $session -response $converted_object_account_service -rolename $role_name -authority $authority
                if($result -ne $True)
                {
                    $result = set_custom_role_privileges -bmcip $ip -session $session -response $converted_object_account_service -rolename $role_name -authority $authority
                    if($result -ne $True)
                    {
                        return $False
                    }
                }elseif(-not ($role_name -in $roleuri))
                {
                    $links_role["Role"]=@{"@odata.id"="/redfish/v1/AccountService/Roles/"+$role_name}
                }
                if(-not ($role_name -in $roleuri))
                {
                    $links_role["Role"]=@{"@odata.id"="/redfish/v1/AccountService/Roles/"+$role_name}
                }
            }
            $response = Invoke-WebRequest -Uri $url_dest -Headers $JsonHeader -Method Get -UseBasicParsing 
            $converted_object = $response.Content | ConvertFrom-Json
            if($converted_object.'@odata.etag' -ne $null)
            {
                $JsonHeader["If-Match"] = $converted_object.'@odata.etag'
            }
            else
            {
                $JsonHeader["If-Match"] = ""
            }
                
            if($links_role.keys -contains "Role")
            {
                $JsonBody = @{ "Password"=$newuserpassword
                    "UserName"=$newusername
                    "RoleId"=$role_name
                    "Enabled" = $true
                    "Links" = $links_role
                } | ConvertTo-Json -Compress
            }else
            {
                $JsonBody = @{ "Password"=$newuserpassword
                    "UserName"=$newusername
                    "RoleId"=$role_name
                    "Enabled" = $true
                } | ConvertTo-Json -Compress
            }
            $response = Invoke-WebRequest -Uri $url_dest -Method Patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
            Write-Host
            [String]::Format("- PASS, statuscode {0} returned successfully to create account {1}",$response.StatusCode,$newusername)
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

function set_custom_role_privileges
{
    param
    (
        [Parameter(Mandatory=$True)]
        [string]$bmcip,
        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$True)]
        $response,
        [Parameter(Mandatory=$True)]
        [string]$rolename,
        [Parameter(Mandatory=$True)]
        [String[]]$authority
    )
    try
    {
        $session_key = $session.'X-Auth-Token'
        $session_location = $session.Location

        # Build headers with session key for authentication
        $JsonHeader = @{ "X-Auth-Token" = $session_key
        }

        $list_auth = @("Supervisor","ReadOnly","UserAccountManagement","RemoteConsoleAccess","RemoteConsoleAndVirtualMediaAcccess","RemoteServerPowerRestartAccess","AbilityClearEventLogs","AdapterConfiguration_Basic"
,"AdapterConfiguration_NetworkingAndSecurity","AdapterConfiguration_Advanced")
        foreach($auth in $authority)
        {
            if($auth  -in $list_auth)
            {
                continue
            }
            else
            {
                Write-Host "custom privileges out of rang"
                return $False
            }
        }

        $url_roles ="https://$bmcip" + $response.Roles."@odata.id"
        $response = Invoke-WebRequest -Uri $url_roles -Headers $JsonHeader -Method Get -UseBasicParsing 
        $converted_object = $response.Content | ConvertFrom-Json

        $url_dest_role = ""
        foreach($role_info in $converted_object."Members")
        {
            $url_role ="https://$bmcip" + $role_info."@odata.id"
            $response = Invoke-WebRequest -Uri $url_role -Headers $JsonHeader -Method Get -UseBasicParsing 
            $converted_object = $response.Content | ConvertFrom-Json
        
            if($rolename -eq $converted_object.Name)
            {
                $url_dest_role = $url_role
                break
            }
        }

        if($url_roles -eq "")
        {
            Write-Host "role is not existed"
            return $False
        }

        $JsonBody = @{"OemPrivileges"=$authority}|ConvertTo-Json -Compress
        $response = Invoke-WebRequest -Uri $url_dest_role -Method Patch -Headers $JsonHeader -Body $JsonBody -ContentType 'application/json'
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
}