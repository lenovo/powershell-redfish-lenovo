###
#
# Lenovo Redfish Utilities
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

function create_session
{
    <#
   .Synopsis
    Create session
   .DESCRIPTION
    Create session, aqcuire session key for further http requests, and session location for session termination
    - ip: Pass in BMC IP address
    - username: Pass in BMC username
    - password: Pass in BMC username password
   #>
    param(
        [Parameter(Mandatory=$True)]
        [string]$ip="",
        [Parameter(Mandatory=$True)]
        [string]$username="",
        [Parameter(Mandatory=$True)]
        [string]$password=""
        )

    # Ignore SSL Certificates
    function Ignore_SSLCertificates
    {
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource=@'
            namespace Local.ToolkitExtensions.Net.CertificatePolicy
            {
                public class TrustAll : System.Net.ICertificatePolicy
                {
                    public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                    {
                        return true;
                    }
            }
        }
'@ 
        $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
        $TAAssembly=$TAResults.CompiledAssembly
        ## We create an instance of TrustAll and attach it to the ServicePointManager
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }
    
    Ignore_SSLCertificates

    # Set BMC access credential
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
    $bmc_username = $username
    $bmc_password = $password
    $bmc_password_secure = ConvertTo-SecureString $bmc_password -AsPlainText -Force
    $bmc_credential = New-Object System.Management.Automation.PSCredential($bmc_username, $bmc_password_secure)

    $base_url = "https://$ip/redfish/v1/"
    

    # Get SessionService url
    $response = Invoke-WebRequest -Uri $base_url -Method Get -Credential $bmc_credential -UseBasicParsing

    $converted_object = $response.Content | ConvertFrom-Json
    $hash_table = @{}
    $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
    $session_server_url_string = "https://$ip"+$hash_table.SessionService.'@odata.id'

    # Get session creation url from SessionService 
    $response = Invoke-WebRequest -Uri $session_server_url_string -Method Get -Credential $bmc_credential -UseBasicParsing
    $converted_object = $response.Content | ConvertFrom-Json
    $hash_table = @{}
    $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
    $session_url_string = "https://$ip"+$hash_table.Sessions.'@odata.id'

    $JsonBody = @{ "Password" = $password
            "UserName" = $username
            } | ConvertTo-Json -Compress

    # Create session and acquire session info
    $response = Invoke-WebRequest -Uri $session_url_string -Method Post -Body $JsonBody -ContentType 'application/json'

    $session = New-Object PSObject  
    $session|Add-Member -MemberType NoteProperty 'X-Auth-Token' $response.headers.'X-Auth-Token'
    $session|Add-Member -MemberType NoteProperty 'Location' $response.headers.Location
    
    return $session
}

function delete_session
{
    <#
   .Synopsis
    Delete session
   .DESCRIPTION
    Delete session after no further http reuqest is needed
    - ip: Pass in BMC IP address
    - session: Pass in session info for authentication
   #>
    param(
        [Parameter(Mandatory=$True)]
        $ip,
        [Parameter(Mandatory=$True)]
        $session
        )

    $session_key = $session.'X-Auth-Token'
    $session_location = $session.Location

    $JsonHeader = @{ "X-Auth-Token" = $session_key
    }

    # Complete the url if it's not start with proper format
    if($session_location.startswith('http') -eq $False)
    {
        $session_location =  "https://$ip" + $session_location
    }

    $response = Invoke-WebRequest -Uri $session_location -Headers $JsonHeader -Method Delete -DisableKeepAlive

}

function get_system_urls
{
   <#
   .Synopsis
    Get ComputerSystem instance URLs
   .DESCRIPTION
    Get ComputerSystem instance URLs, a URL collection is returned.
    - bmcip: Pass in BMC IP address
    - session: Pass in session info for authentication
    - system_id: Pass in ComputerSystem instance id(None: first instance, All: all instances)
   #>

    param(
        [Parameter(Mandatory=$True)]
        [string]$bmcip="",
        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$False)]
        [string]$system_id="None"
        )
    
    # Create an null array for result return
    $system_url_collection = @()
    
    # Get the system url collection via Invoke-WebRequest
    $base_url = "https://$bmcip/redfish/v1/"
    $session_key = $session.'X-Auth-Token'
    $JsonHeader = @{ "X-Auth-Token" = $session_key
    }
    $response = Invoke-WebRequest -Uri $base_url -Headers $JsonHeader -Method Get -UseBasicParsing
    $converted_object = $response.Content | ConvertFrom-Json
    $systems_url = $converted_object.Systems."@odata.id"
    $systems_url_string = "https://$bmcip" + $systems_url

    $response = Invoke-WebRequest -Uri $systems_url_string -Headers $JsonHeader -Method Get -UseBasicParsing
    
    # Convert response content to hash table
    $converted_object = $response.Content | ConvertFrom-Json
    $hash_table = @{}
    $converted_object.psobject.properties | Foreach { $hash_table[$_.Name] = $_.Value }
    
    # Set the $system_url_collection by checking $system_id value
    foreach ($i in $hash_table.Members)
    {
        $i = [string]$i
        $system_url_string = ($i.Split("=")[1].Replace("}",""))
        
        if ($system_id -eq "None")
        {
            $system_url_collection += $system_url_string
            break
        }
        elseif ($system_id -eq "all")
        {
            $system_url_collection += $system_url_string
            continue
        }
        else
        {
            $system_url_id = $system_url_string.Split("/")[4]
            if ($system_id -eq $system_url_id)
            {
                $system_url_collection += $system_url_string
                break
            }
            else
            {
                continue
            }
        }
    }
            
    return $system_url_collection
}

function read_config
{
   <#
   .Synopsis
    Read configuration file infomation
   .DESCRIPTION
    Read configuration file infomation
    - config_file: Pass in configuration file path
   #>
   
    param(
        [Parameter(Mandatory=$False)]
        [string]$config_file='config.ini'
        )
    
    $hash_table = @{'BmcIp'=''; 'BmcUsername'=''; 'BmcUserpassword'=''; 'SystemId'=''; 'ManagerId'=''; 'ChassisId'=''}
    if (-not [system.IO.File]::Exists($config_file))
    {
        $config_file = $PSScriptRoot + '\config.ini'
        if (-not [system.IO.File]::Exists($config_file))
        {
            return $hash_table
        }
    }
    $payload = Get-Content -Path $config_file |
    Where-object {$_ -like '*=*'} |
    ForEach-Object {
        $infos = $_ -split '='
        $key = $infos[0].Trim()
        $value = $infos[1].Trim()
        $hash_table[$key] = $value
    }
    
    return $hash_table
}

function handle_exception
{
    param(
        [Parameter(Mandatory=$True)]
        [object]$arg_object
        )

    # Handle HTTP exception response
    if($arg_object.Exception.Response)
    {
        Write-Host
        [String]::Format("Error occured, error code:{0}",$arg_object.Exception.Response.StatusCode.Value__)
        $sr = new-object System.IO.StreamReader $arg_object.Exception.Response.GetResponseStream()
        $resobject = $sr.ReadToEnd() | ConvertFrom-Json
        $ret = $resobject.error.('@Message.ExtendedInfo')
    }
    # Handle system exception response
    elseif($_.Exception)
    {
        $ret =  "Error message:" + $_.Exception.Message + ", Please check arguments or server status."
    }

    return $ret
    
}