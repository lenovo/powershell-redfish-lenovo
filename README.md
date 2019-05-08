# powershell-redfish-lenovo

Sample PowerShell scripts for using the Redfish API on Lenovo servers

Description
----------

This project includes a set of sample PowerShell scripts that utilize the Redfish API to manage Lenovo ThinkSystem servers.

For more information on the Redfish API, visit http://redfish.dmtf.org/

Installing
----------

* Get PowerShell Redfish Scripts
  `git clone https://github.com/lenovo/powershell-redfish-lenovo`
  A set of PowerShell examples is provided under the examples directory of this project.

* In order for these scripts to be executed, the execution policy needs to be lowered from "restricted". For instance, set the policy to "remotesigned" by running the following:
  `Set-ExecutionPolicy remoteSigned`

* Import example scripts individually as PowerShell modules, or auto-import all modules by enabling a profile

  To import individual modules:
    1. Open a PowerShell terminal and navigate to .\examples directory in powershell-redfish-lenovo
    2. Import the target script using Import-Module. For example:
    `Import-Module .\get_power_state.psm1`

  To automatically import all scripts by enabling a profile:
    1. Open a PowerShell terminal and type in `$profile`, This should display the path that would be used to store your profile
    2. Run `test-path $profile` to check whether your profile is already created
    3. If the profile is not created, type `new-item -path $profile -itemtype file -force` to create the profile
    4. You can customize the profile by launching the PowerShell ISE: `powershell_ise $profile`. This will open the profile ps1 file (typically named "Microsoft.PowerShell_profile.ps1")
    5. Enter the following code to the profile ps1 file. This will automatically import all the scripts on PowrShell startup:

       ```
       # directory where scripts are stored
       $psdir="D:\Documents\Powershell\Scripts\autoload"
       # import all scripts under 'autoload'
       foreach ($FUNC in $(dir ${psdir}\*.psm1)) {Import-Module $FUNC.FullName}
       Write-Host "Custom PowerShell Environment Loaded"
       ```

    6. Copy the powershell-redfish-lenovo repo ".psm1" example files to your "autoload" folder
    7. These files will automatically be imported as modules on evry new PowerShell session.

Requirements
----------

* PowerShell 5.0 or later

Usage
----------

* Use "Get-Module" command to get imported module list in a PowerShell terminal
  `Get-Module`

* Use "Get-Help" to show help information for a specific script module
  `Get-Help get_power_state`

* Use command options to specify target BMC connection information
  `get_power_state -ip 10.10.10.10 -username USERID -password PASSW0RD`

* Use can use a configuration file to store common parameters for the Lenovo PowerShell Redfish Scripts, such as the BMC IP address, user name, password. Default configuration file is config.ini, which is located in same folder with the scripts. You can create your own configuration file and specify it using the "--config" option. The scripts will load config.ini automatically if no configuration file is specified in command line.

Contributing
----------

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

Copyright and License
---------------------

Copyright 2019 Lenovo Corporation

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
