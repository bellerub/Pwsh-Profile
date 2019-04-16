<############################################################################################################
#                                                   My Profile
#
#
#    Changelog:
#         04/16/10 - Got rid of annoying EXO connecting at startup
#         04/10/19 - Forked from Codys profile (props to Cody)
#         11/04/18 - Added alias for Get-Command as gcmd
#                   Update References to ProfilePath
#        09/15/18 - Updated prompt support for PowerShell Core
#        03/23/18 - Added Prompt customizations
#                   Added Persistent history
#        03/17/18 - Added New-Key
#                   Moved Credential import to function instead of execution
#                   Added local option for file
#                   Invoke-Bsod
#        02/26/18 - Added Enable-RDP. Changed 'where' to 'Where-Object' in some functions
#        02/09/18 - Fixed Connect-ExchangeOnline bug
#        01/24/18 - Fixed Version bug. Added a Set-Location at the end.
#        12/31/17 - Added Hosts File Section which includes:
#                   Search-HostsFile
#                   Add-HostsFile
#                   Open-HostsFile
#        12/28/17 - PowerShell Core support for Get-XKCDPassword
#                   Removed unnecessary Cim call in Get-ComputerUptime
#        12/11/17 - PowerShell Core Support for Get-Goat
#        12/09/17 - PowerShell Core Support for Initial Setup
#                   Automated third version number based changelog
#        12/07/17 - Speed Optimization. Centralized Aliases Section
#        12/06/17 - Permanently moved to GitHub
#                   Added alias for grep, moved content, removed PSCX
#        12/03/17 - Overhaul of Connect-ExchangeOnline. Now checks for Modern Authentication
#        12/02/17 - Added Connect-SecurityAndComplianceCenter
#        10/22/17 - Added Resources Section which includes:
#                    Get-ComputerUtilization
#                    Get-ComputerCpuUtilization
#                    Get-ComputerMemoryUtilization
#                    Get-ComputerUptime
#        09/15/17 - Added Add-CredentialToCsv & changed credential handling in functions
#        09/14/17 - Added credential import from CSV
#                   Changed default module location to $ProfilePath\CstmModules
#                   Added Invoke-TextToSpeech
#        09/04/17 - Added Send-WakeOnLan
#        08/28/17 - Added Get-WindowsInstaller
#        08/03/17 - Added Resources section
#        07/19/17 - Added Get-HyperVHost
#        07/14/17 - Added Get-ExternalIPAddress
#        06/28/17 - Added Update-Profile for easy profile management & added cleanup
#        06/26/17 - v1 overhaul:
#                    $secret now brought in as secure string
#                    checks for existing profileKey even if not in default path
#                    new module handling
#                    Added Update Switch to update script and modules
#        06/25/17 - Added new alias & created connect-exchangeonline
#        06/20/17 - Added Get-goat
#        05/15/17 - Removed aggressive/unnecessary importing
#
############################################################################################################>


[CmdletBinding()]
Param(
    [Parameter(Position=0)]
    [string]$ProfilePath = $(Split-Path -Path $profile.CurrentUserAllHosts),
    [switch]$Version,
    [switch]$Update
)
$ProgressPreference='SilentlyContinue'
$PSProfileVersion = "1.3." + ((Get-Content $script:MyInvocation.MyCommand.Path | Select-String "/")[0].ToString().Split('-')[0] -replace '\D+(\d+)','$1')

#Print Profile Version & Exit
if ($Version.IsPresent) {
  $PSProfileVersion
  exit 0
}

#variables needed later
$profileKey = $null

#############################################################################################################
#
#                                           Custom Settings
#
#############################################################################################################

# Disable annoying beep on backspace
if ((Get-Command Set-PSReadlineOption -ErrorAction SilentlyContinue)) {Set-PSReadlineOption -BellStyle None}

# Persistent History
$HistoryFilePath = Join-Path $home .ps_history
Register-EngineEvent PowerShell.Exiting -Action { Get-History | Export-Clixml $HistoryFilePath } | out-null
if (Test-path $HistoryFilePath) { Import-Clixml $HistoryFilePath | Add-History }

# Customize my prompt
function Prompt{
    # Cache value so we can set it back later
    $realLASTEXITCODE = $LASTEXITCODE

    # whoami
    Write-Host "`n[" -NoNewline
    Write-Host "$(whoami)" -NoNewline -ForegroundColor Green

    if($PSVersionTable.OS -like "Darwin*"){ Write-Host "@$(scutil --get LocalHostName)]: " -NoNewline }
    else { Write-Host "@$(hostname)]: " -NoNewline }

    # Print current working directory
    Write-Host "$($(Get-Location).Path -replace ($home).Replace('\','\\'), "~")\".Replace('\\','\').Replace("Microsoft.PowerShell.Core\FileSystem::",'\') -ForegroundColor DarkGray

    # Print elevation status
    if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        Write-Host "(Elevated) " -ForegroundColor Red -NoNewline
    }

    # Set exitcode to its former glory
    $global:LASTEXITCODE = $realLASTEXITCODE

    # Return nested prompt level
    return "PS$('>' * ($nestedPromptLevel + 1)) "
}



#############################################################################################################
#
#                                           Useful/fun Functions
#
#############################################################################################################

# Get-Time
function Get-Time {  return $(get-date | ForEach-Object { $_.ToLongTimeString() } ) }

# Get-HyperVHost
Function Get-HyperVHost {
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    Invoke-command -ComputerName $ComputerName -ScriptBlock {
        return $(get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName") 
    }
}

# update profile & modules
function Update-Profile {
    [CmdletBinding(DefaultParameterSetName='Remote')]
    Param(
        [Parameter(ParameterSetName='Local')]
        [String]$Path,
        [Parameter(ParameterSetName='Remote')]
        [string]$URI = "https://raw.githubusercontent.com/bellerub/Pwsh-Profile/master/profile.ps1",
        [switch]$IncludeModules
    )
    # Copy from local location
    if($Path){
        if(Test-Path $Path){
            $confirm = Read-Host "This will overwrite the existing profile. Are you sure you want to proceed? (y/n)"
            if ($confirm -like "y*") {
                Copy-Item $Path -Destination "$ProfilePath\profile.ps1" -Force
            }
        }
    }
    else {
        Invoke-WebRequest -Uri $URI -OutFile "$ProfilePath\profile.ps1"
        # Need to unblock file for Windows hosts
        if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
            Unblock-File "$ProfilePath\profile.ps1"
        }
    }
    if($IncludeModules){
        $updateCommand = "$ProfilePath\profile.ps1 -Update"
        Invoke-Expression $updateCommand
    }
}

# get profile version
function Get-ProfileVersion { invoke-expression "$ProfilePath\profile.ps1 -Version" }

# why goat farming is better than IT
Function Get-Goat {
    $URI = "http://www.heldeus.nl/goat/GoatFarming.html"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $HTML = Invoke-WebRequest -Uri $URI
    Write-Host "Why Goatfarming is better than IT: " -NoNewline
    $response = ($HTML.Content.Remove(0,67) -split('<p class="goat">') |  Get-Random).TrimStart()
    $response.Substring(0,$response.indexof('</p>'))
    Write-Host ""
}

# Create Bsod
function Invoke-Bsod{
    Param(
        [String]$Computername = $env:COMPUTERNAME,
        [Pscredential]$Credential
    )
    Write-Host "This will cause a Blue Screen of Death on $Computername.`nAre you sure absolutely sure you want to proceed? (y/n): " -ForegroundColor Red -NoNewline
    $confirm = Read-Host 
    if ($confirm -notlike "y*") {
        return 0;
    }

    # splat invoke-command
    $params = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $params['ComputerName'] = $ComputerName
    }
    if ($Credential){ $params['Credential'] = $Credential }

    Invoke-Command @params -ScriptBlock {
        wmic process where processid!=0 call terminate
    }


}

Function Get-ExternalIPAddress{
    #stolen from https://gallery.technet.microsoft.com/scriptcenter/Get-ExternalPublic-IP-c1b601bb
    Param(
        [switch]$Full
    )
    if($full) {return Invoke-RestMethod http://ipinfo.io/json}
    else{return (Invoke-RestMethod http://ipinfo.io/json | Select-object -exp ip)}
}

# Useful on older versions of powershell
function Test-Admin {
    $admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (!($admin)){
        throw "You are not running as an administrator"
    }
    else {
        Write-Verbose "Got admin"
        return $true
    }
}

# Checks windows installer for what version of windows it contains
function Get-WindowsInstaller {
    param (
        [Parameter(Position=0,Mandatory=$true)][String]$DriveLetter
    )
    Test-Admin
    if(!(Get-Volume $DriveLetter[0] -ErrorAction SilentlyContinue)){throw "Volume with the property 'DriveLetter' equal to '$($DriveLetter[0])' cannot be found"}
    $file = "install.wim"
    if(Test-Path "$($DriveLetter[0]):\sources\install.esd"){ $file = "install.esd"}
    for($index = 1; $index -ne 0; $index++){
        $a = dism /Get-WimInfo /WimFile:$($DriveLetter[0])`:\sources\$file /index:$index | Select-String -Pattern "Name" -SimpleMatch
        
        if($a -ne $null){ write-host $a.ToString().SubString(7) }
        else { $index = -1 }
    }
}

# stolen from https://gallery.technet.microsoft.com/scriptcenter/Send-WOL-packet-using-0638be7b
function Send-WakeOnLan {
<# 
  .SYNOPSIS  
    Send a WOL packet to a broadcast address
  .PARAMETER mac
   The MAC address of the device that need to wake up
  .PARAMETER ip
   The IP address where the WOL packet will be sent to
  .EXAMPLE 
   Send-WOL -mac 00:11:32:21:2D:11 -ip 192.168.8.255 
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$MAC,
        [string]$IP="255.255.255.255", 
        [int]$Port=9
    )   
    $broadcast = [Net.IPAddress]::Parse($ip)
    $mac=(($mac.replace(":","")).replace("-","")).replace(".","")
    $target=0,2,4,6,8,10 | ForEach-Object {[convert]::ToByte($mac.substring($_,2),16)}
    $packet = (,[byte]255 * 6) + ($target * 16)
    $UDPclient = new-Object System.Net.Sockets.UdpClient
    $UDPclient.Connect($broadcast,$port)
    [void]$UDPclient.Send($packet, 102) 
}

# TODO: add option to send to different computer
function Invoke-TextToSpeech {
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)] [string] $Text)
    [Reflection.Assembly]::LoadWithPartialName('System.Speech') | Out-Null   
    $object = New-Object System.Speech.Synthesis.SpeechSynthesizer 
    $object.Speak($Text) 
}

# Get-XKCDPassword 2.0
# TODO: add more options
function Get-XKCDPassword {
    Param(
        [String]$Path = "$ProfilePath\dictionary.txt",
        [String]$Uri = "https://raw.githubusercontent.com/SoarinFerret/Pwsh-Profile/master/dictionary.txt",
        [Int32]$Count = 3,
        [switch]$UpdateDictionary
    )

    if($UpdateDictionary -or !(Test-Path $Path)){
        Write-Host "Updating Dictionary..." -ForegroundColor Green
        Remove-Item -Path $Path -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Force
        Invoke-WebRequest -Uri $Uri -OutFile $Path
    }

    # Get words
    $words = Get-Content $Path | Get-Random -Count $($Count*3)

    # Generate Phrases
    $out = @(); for($x = 0; $x -lt $count; $x++){
        $pwd = $("{0:D2}" -f (Get-Random -Maximum 99))+`
               $words[$x*$count]+`
               $words[$x*$count+1].toUpper()+`
               $words[$x*$count+2]+`
               $("{0:D2}" -f (Get-Random -Maximum 99))
        $out += $pwd
    }
    return $out
}

function Enable-RemoteDesktop {
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential
    )
    # splat the computername and credential. 'Invoke-Command' is
    # much quicker if computername is not specified on localhost

    $credHash = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $credHash['ComputerName'] = $ComputerName
    }
    if ($Credential){ $credHash['Credential'] = $Credential }

    Invoke-Command @credhash -ScriptBlock{
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0;
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    }
}

#############################################################################################################
#
#                                        Modern Authentication O365
#
#############################################################################################################

# connect to exchangeonline using modern authentication or basic
function Connect-ExchangeOnline {
    Param(
        [String]$UserPrincipalName = "",
        [PSCredential]$Credential = $null,
        [String]$ConnectionURI = 'https://outlook.office365.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $PSSession = $null

    # Check if Exchange Online PowerShell module is installed, otherwise revert to old way
    $Module = "Microsoft.Exchange.Management.ExoPowershellModule.dll"
    if(!$UseBasic -and ($ModulePath = (Get-ChildItem $env:LOCALAPPDATA\Apps -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like $Module -and $_.DirectoryName -like "*tion*"}))){
        $ModulePath= $ModulePath[0].FullName
        $global:ConnectionUri = $ConnectionUri
        $global:AzureADAuthorizationEndpointUri = 'https://login.windows.net/common'
        $global:UserPrincipalName = $UserPrincipalName
        Import-Module $ModulePath
        $PSSession = New-ExoPSSession -UserPrincipalName $UserPrincipalName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri
    }
    else{
        $PSSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionURI -AllowRedirection -Credential $Credential -Authentication Basic
    }
    if ($PSSession -ne $null) { Import-PSSession $PSSession -AllowClobber }
}

# connect to the security and compliance center using modern or basic authentication
function Connect-SecurityAndComplianceCenter {
    Param(
        $UserPrincipalName = "",
        [PSCredential]$Credential = $null,
        $ConnectionURI = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $param = @{UserPrincipalName=$UserPrincipalName;Credential=$Credential;ConnectionURI=$ConnectionURI;UseBasic=$UseBasic}
    Connect-ExchangeOnline @param
}

#############################################################################################################
#
#                                             Resources
#
#############################################################################################################

function Get-ComputerUptime {
    Param(
        [String]$ComputerName = "localhost",
        [pscredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName
    $bootuptime = (Get-CimInstance Win32_OperatingSystem -CimSession $session).LastBootUpTime
    $uptime = (date) - $bootuptime
    return New-Object psobject -Property @{"UpTime"=$uptime;"LastBootUpTime"=$bootuptime}
}

function Get-ComputerMemoryUtilization {
    Param(
        [String]$ComputerName = "localhost",
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName
    Get-CimInstance Win32_OperatingSystem -CimSession $session | `
    Select-Object @{Name = "FreeGB";Expression = {[math]::Round($_.FreePhysicalMemory/1mb,2)}},@{Name = "TotalGB";Expression = {[int]($_.TotalVisibleMemorySize/1mb)}}
}

function Get-ComputerCpuUtilization {
    Param(
        [String]$ComputerName = "Localhost",
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName    
    Get-CimInstance win32_processor -CimSession $session | Measure-Object -property LoadPercentage -Average | Select-Object Average
}

Function Get-ComputerUtilization{
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential,
        [ValidateSet("CPU","RAM","ID")]
        [String]$Sort = "CPU",
        [int]$Size = 15,
        [Switch]$Continue
    )
    
    # splat the computername and credential. 'Invoke-Command' is
    # much quicker if computername is not specified on localhost

    $credHash = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $credHash['ComputerName'] = $ComputerName
    }
    if ($Credential){ $credHash['Credential'] = $Credential }
    
    $s; switch($sort){
        "ID"  {$s = "ID"}
        "CPU" {$s = "CPU"}
        "RAM" {$s = "PM"}
    }
    do{
        Invoke-Command @credhash -ArgumentList $s,$size -ScriptBlock{
            Get-Process | Sort-Object -Descending $args[0] | Select-Object -First $args[1] | Format-Table
        }
        if($Continue){ Start-Sleep 1; Clear-Host; Write-Host "`n`t`t`tPress Ctrl-C to exit`n" -ForegroundColor Red }
    } while ($Continue)
}

#############################################################################################################
#
#                                             PSCredentials
#
#############################################################################################################

function Add-PSCredentialsToCsv{
    param (
        [pscredential]$Credential = (Get-Credential), 
        [String]$VariableName,
        [String]$Path = "$home\Documents\WindowsPowerShell\credentials.csv"
    )
    $username = $Credential.UserName
    $SecurePass = $Credential.Password | ConvertFrom-SecureString -ErrorAction SilentlyContinue
    if(!(Test-Path $Path)){
        New-Item $Path -ItemType File
        "`"VariableName`",`"Username`",`"Password`"" | Out-File $Path -Append
    }
    "`"$VariableName`",`"$username`",`"$SecurePass`"" | Out-File $Path -Append
}

function Import-PSCredentialCsv{
    param(
        [String]$Path = "$ProfilePath\credentials.csv",
        [String]$VariablePrefix = "cred",
        [String]$KeyFile
    )
    try{
        if(Test-Path $Path){
            $credCSV = Import-CSV $Path
            forEach($item in $credCSV){
                $username = $item.Username
                $SecurePass = $item.Password | ConvertTo-SecureString -ErrorAction SilentlyContinue
                if($SecurePass){
                    New-Variable -Name $("cred" + $item.VariableName) -Value (
                        New-Object PSCredential $username,$SecurePass
                    )
                }
            }
        }
    }catch{
        Write-Error $_
    }
}

function Set-ODQuota {

    Connect-SPOService -Url https://esu2org-admin.sharepoint.com #-Credential $credential
    
    #define target user
    $targetuser = Read-Host -Prompt 'Input the username to change storage quota'
    $path = $targetuser.replace('@',"_").replace('.',"_")
    
    $Date = Get-Date
    
    Write-Host "You input $targetuser on $Date"
    
    #Set the Quota to Maximim of 5TB
    Set-SPOSite -Identity https://esu2org-my.sharepoint.com/personal/$path -StorageQuota 5242880
    
    #Check to make sure the change was applied
    Get-SPOSite -Identity https://esu2org-my.sharepoint.com/personal/$path | select -property storagequota
    }


# Create Randomized Key
function New-Key {
    param (
        [ValidateSet(16,24,32)]
        [Int32]$Size = 16,
        [String]$Path = $null
    )

    $Key = New-Object Byte[] $Size   # You can use 16, 24, or 32 for AES
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
    if(Test-Path $Path){ $key | Set-Content -Path $Path }
    else {return $key}
}


#############################################################################################################
#
#                                             Hosts File
#
#############################################################################################################

# TODO: Remove-HostsFile

function Search-HostsFile {
    Param(
        [String]$Hostname = "*",
        [ipaddress]$IP = $null
    )
    $file = ""
    if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
        $file = "$env:windir\System32\drivers\etc\hosts"
    } else { $file = "/etc/hosts" }
    $lines = Get-Content $file | Where-Object {$_[0] -ne '#' -and $_.trim() -ne "" -and $_ -like $Hostname}
    if($ipaddress -ne $null){
        $lines = $lines | Where-Object {$_ -like $ipaddress}
    }
    $hosts = @()
    forEach ($line in $lines){
        $parts = $line -replace "#.*" -split '\s+' # doesnt include EOL comments like this
        $ip = $parts[0]
        $names = $parts[1..($parts.Length-1)] | Where-Object {$_ -ne ""}
        $hosts += New-Object -TypeName psobject -Property @{IPAddress=$ip;Hostname=$names}
    }
    return $hosts
}

function Add-HostsFile {
    Param(
        [Parameter(Mandatory=$true)]
        [String[]]$Hostname,
        [Parameter(Mandatory=$true)]
        [ipaddress]$IP
    )
    Test-Admin
    $file = ""
    if($PSEdition -eq "Desktop" -or $PSVersionTable.OS -like "*Windows*"){
        $file = "$env:windir\System32\drivers\etc\hosts"
    } else { $file = "/etc/hosts" }
    "$($ip.IPAddressToString)`t$hostname" | Out-File $file -Append -Encoding ascii
}

function Open-HostsFile {
    Start-Process notepad "$env:windir\System32\drivers\etc\hosts"
}

#############################################################################################################
#
#                                            Trusted Hosts
#
#############################################################################################################
function Add-TrustedHost {
    Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    [String[]]$ComputerName #for example, dc-cluster1 or 10.0.0.25
    )#end param
    process{ forEach($c in $ComputerName) { Set-Item WSMan:\localhost\Client\TrustedHosts -Value $c -Force -Concatenate } }
}

function Get-TrustedHost {
    Param(
    [Parameter(Position=0,ValueFromPipeline=$true)]
    [String[]]$ComputerName = "*"#for example, dc-cluster1 or 10.0.0.25
    )#end param
    process{ forEach($c in $ComputerName){ (Get-Item WSMan:\localhost\Client\TrustedHosts).Value.Split(',') | Where-Object {$_ -like "*$c*"} }}
}

function Remove-TrustedHost {
    Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    [String[]]$ComputerName #for example, dc-cluster1 or 10.0.0.25
    )#end param
    process{
        forEach($c in $ComputerName){
            if((Get-TrustedHost $c) -eq $c) {
                $TrustedHosts = ""
                (Get-TrustedHost).Replace("$c","") | ForEach-Object {if($_ -ne "") {$TrustedHosts += $_ + ","}}
                Set-Item WSMan:\localhost\Client\TrustedHosts $TrustedHosts.TrimEnd(",") -Force
            }
        }
    }
}


#############################################################################################################
#
#                                   Get Cool Modules from Me/PSGallery
#
#############################################################################################################

function profileGetModules{ 
    #install NuGet
    if(!(Get-Module -ListAvailable -Name PackageManagement)){
        Get-PackageProvider -Name NuGet -Force | Out-Null
    }

    $modules = "NTFSSecurity","Posh-SSH","AzureAD"

    ForEach($module in $modules){
        if(!(Get-Module -ListAvailable -Name $module)){
            Find-Module $module
            Install-Module $module -Force -AllowClobber
        }else {Update-Module $module}
    }
}



#############################################################################################################
#
#                                              Aliases
#
#############################################################################################################

function profileSetAlias{
    Param(
        [parameter(Position=0)][String]$Alias,
        [parameter(Position=1)][String]$Command
    )
    if (!(Get-alias $Alias -ErrorAction SilentlyContinue) -and (Get-Command $Command -ErrorAction SilentlyContinue)){
        new-Alias $Alias $Command -Scope 1
    }
}

# Standard Cmdlets
profileSetAlias set-ODquota OD
profileSetAlias touch New-Item
profileSetAlias grep Select-String
profileSetAlias get-commands get-command #bc I always accidently type this instead
profileSetAlias gcmd get-command
profileSetAlias Shutdown-Computer Stop-Computer #because it makes more sense

# PS Core Aliases
profileSetAlias wget Invoke-WebRequest
profileSetAlias ls Get-ChildItem

# Hyper-V specific
profileSetAlias Shutdown-VM Stop-VM

# Active Directory specific
profileSetAlias Reset-ADAccountPassword Set-ADAccountPassword #because I cant remember this for some reason

# Useful / Fun Cstm Functions
profileSetAlias gt Get-Time
profileSetAlias gg Get-Goat
profileSetAlias geip Get-ExternalIPAddress
profileSetAlias Test-isAdmin Test-Admin
profileSetAlias Check-WindowsInstaller Get-WindowsInstaller
profileSetAlias Send-WOL Send-WakeOnLan
profileSetAlias gxp Get-XKCDPassword
profileSetAlias Enable-RDP Enable-RemoteDesktop

# O365 Modern Auth
profileSetAlias Connect-Exo Connect-ExchangeOnline
profileSetAlias Connect-SaCC Connect-SecurityAndComplianceCenter

# Resources
profileSetAlias Get-Uptime Get-ComputerUptime
profileSetAlias Get-ComputerMemory Get-ComputerMemoryUtilization
profileSetAlias Get-MemoryUsage Get-ComputerMemoryUtilization
profileSetAlias Get-CpuUsage Get-ComputerCpuUtilization
profileSetAlias top Get-ComputerUtilization


#############################################################################################################
#
#                                           Execution
#
#############################################################################################################


#if not ran in correct directory, get user input about stuff
if($(Split-Path $script:MyInvocation.MyCommand.Path) -ne $ProfilePath){
    $response = Read-Host "'$($MyInvocation.MyCommand)' was not run from its default location.`nWould you like to copy it there? This action will overwrite any previously created profile. (Y/N) "
    if($response -like "y*"){
        #create path if non-existent, otherwise copy item
        if(!(test-path $ProfilePath)){New-Item -Path $ProfilePath -ItemType Directory -Force}
        Copy-Item ".\$($MyInvocation.MyCommand)" -Destination "$ProfilePath\profile.ps1" -Force
    }
    else { $ProfilePath = (Get-Location).Path }

      }

if($Update){ profileGetModules; }

# Import credentials
Import-PSCredentialCsv

# Import custom modules
if(test-path $ProfilePath\CstmModules){
    Get-ChildItem "$ProfilePath\CstmModules" | ForEach-Object{ Import-Module $_.FullName -Force -WarningAction SilentlyContinue }
}

$ProgressPreference='Continue'

# Clean up items
Remove-Item -Path Function:\profile*
Remove-Item -Path Variable:\profileKey
Remove-Variable Update,Version

# Change Directory to $home
Set-Location $home


