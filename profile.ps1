#############################################################################################################
#                                                   My Profile
#
#    Default Location: "$Home\Documents\WindowsPowerShell\Profile.ps1"
#
#    TODO: Make compatible with PowerShell v3 and v4?
#          -Package Management Preview for v3 & v4 msi should fix issues
#    TODO: make script faster, needs to be under 500ms to suppress warning
#    TODO: add help comments to TrustedHost, or move back to module instead of profile embed
#
#    Changelog:
#        12/03/17 - Overhaul of Connect-ExchangeOnline. Now checks for Modern Authentication
#        12/02/17 - Added Connect-SecurityAndComplianceCenter
#        10/22/17 - Added Resources Section which includes:
#                    Get-ComputerUtilization
#                    Get-ComputerCpuUtilization
#                    Get-ComputerMemoryUtilization
#                    Get-CompuerUptime
#        09/15/17 - Added Add-CredentialToCsv & changed credential handling in functions
#        09/14/17 - Added credential import from CSV
#                   Changed default module location to $defaultPath\CstmModules
#                   Added Invoke-TextToSpeech
#        09/04/17 - Added Send-WakeOnLan
#        08/28/17 - Added Get-WindowsInstaller
#        08/03/17 - Added Resources section
#        07/19/17 - Added Get-HyperVHost
#        07/14/17 - Added Get-ExternalIPAddress
#        06/28/17 - Added Update-Profile for easy profile management & added cleanup
#        06/26/17 - v1 overhaul:
#                    $secret now brought in as secure string
#                    $checks for existing profileKey even if not in default path
#                    new module handling
#                    Added Update Switch to update script and modules
#        06/25/17 - Added new alias & created connect-exchangeonline
#        06/20/17 - Added Get-goat
#        05/15/17 - Removed aggressive/unnecessary importing
#
#############################################################################################################
[CmdletBinding()]
Param(
  [switch]$Version,
  [switch]$Update,
  [string]$defaultPath = "$Home\Documents\WindowsPowerShell",
  [string]$hashedKey = "17849254117232230311251061602172192521711073196135452308324153250156321261542172814449"
)
$ProgressPreference='SilentlyContinue'
$PSProfileVersion = '1.2.120317'

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

#Disable annoying beep on backspace
Set-PSReadlineOption -BellStyle None

#############################################################################################################
#
#                                              Aliases
#
#############################################################################################################
set-alias touch New-Item
set-alias get-commands get-command #bc I always accidently type this instead
set-alias Shutdown-Computer Stop-Computer #because it makes more sense

#hyperv specific
if(Get-Module Hyper-V){
    Set-Alias Shutdown-VM Stop-VM
}

#active directory specific
if(Get-Module -ListAvailable -Name ActiveDirectory){
    Set-alias Reset-ADAccountPassword Set-ADAccountPassword #because I cant remember this for some reason
}

#############################################################################################################
#
#                                           Useful/fun Functions
#
#############################################################################################################

#Get-Time
function Get-Time {  return $(get-date | ForEach-Object { $_.ToLongTimeString() } ) }

#Get-HyperVHost
Function Get-HyperVHost {
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.CredentialAttribute()]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    Invoke-command -ComputerName $ComputerName -ScriptBlock {
        return $(get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName") 
    }
}

#update profile & modules
function Update-Profile {
    Param(
        [switch]$IncludeModules
    )
    $uri = "https://raw.githubusercontent.com/SoarinFerret/Pwsh-Profile/master/profile.ps1"
    Invoke-WebRequest -Uri $uri -OutFile "$Home\Documents\WindowsPowerShell\profile.ps1"
    Unblock-File "$Home\Documents\WindowsPowerShell\profile.ps1"
    if($IncludeModules){
        $updateCommand = "$Home\Documents\WindowsPowerShell\profile.ps1 -Update"
        Invoke-Expression $updateCommand
    }
}

#get profile version
function Get-ProfileVersion { invoke-expression "$Home\Documents\WindowsPowerShell\profile.ps1 -Version" }

#why goat-farming is better than IT
Function Get-Goat {
    $URI = "http://www.heldeus.nl/goat/GoatFarming.html"
    $HTML = Invoke-WebRequest -Uri $URI
    Write-Host "Why Goatfarming is better than IT: " -NoNewline
    (($HTML).ParsedHtml.getElementsByTagName("p") | Where-Object { $_.className -eq "goat" } ).innerText | Get-Random
    Write-Host ""
}

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
    if(!$UseBasic -and ($ModulePath = (ls $env:LOCALAPPDATA\Apps -Recurse | where {$_.Name -like $Module -and $_.DirectoryName -like "*tion*"})[0].FullName)){
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
if(!(Get-alias Connect-Exo -ErrorAction SilentlyContinue)){ Set-Alias Connect-Exo Connect-ExchangeOnline }

# connect to the security and compliance center using modern or basic authentication
function Connect-SecurityAndComplianceCenter {
    Param(
        $UserPrincipalName = "",
        $Credential = $null,
        $ConnectionURI = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $param = @{UserPrincipalName=$UserPrincipalName;Credential=$Credential;ConnectionURI=$ConnectionURI;UseBasic=$UseBasic}
    Connect-ExchangeOnline @param
}
if(!(Get-alias Connect-SaCC -ErrorAction SilentlyContinue)){ Set-Alias Connect-SaCC Connect-SecurityAndComplianceCenter }

Function Get-ExternalIPAddress{
    #stolen from https://gallery.technet.microsoft.com/scriptcenter/Get-ExternalPublic-IP-c1b601bb
    Param(
        [switch]$Full
    )
    if($full) {return Invoke-RestMethod http://ipinfo.io/json}
    else{return (Invoke-RestMethod http://ipinfo.io/json | Select-object -exp ip)}
}
if(!(Get-alias geip -ErrorAction SilentlyContinue)) {Set-alias geip Get-ExternalIPAddress}

#Useful on older versions of powershell
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
#backwards compatability with my old scripts
if(!(Get-alias geip -ErrorAction SilentlyContinue)) {Set-alias Test-isAdmin Test-Admin}

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
if(!(Get-alias geip -ErrorAction SilentlyContinue)) {Set-Alias Check-WindowsInstaller Get-WindowsInstaller}

# stolen from https://gallery.technet.microsoft.com/scriptcenter/Send-WOL-packet-using-0638be7b
function Send-WakeOnLan
{
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
    $target=0,2,4,6,8,10 | % {[convert]::ToByte($mac.substring($_,2),16)}
    $packet = (,[byte]255 * 6) + ($target * 16)
    $UDPclient = new-Object System.Net.Sockets.UdpClient
    $UDPclient.Connect($broadcast,$port)
    [void]$UDPclient.Send($packet, 102) 
}
if(!(Get-alias geip -ErrorAction SilentlyContinue)) {Set-Alias Send-WOL Send-WakeOnLan}

# TODO: add option to send to different computer
function Invoke-TextToSpeech {
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)] [string] $Text)
    [Reflection.Assembly]::LoadWithPartialName('System.Speech') | Out-Null   
    $object = New-Object System.Speech.Synthesis.SpeechSynthesizer 
    $object.Speak($Text) 
}

function Add-CredentialsToCsv{
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

#############################################################################################################
#
#                                             Resources
#
#############################################################################################################

function Get-ComputerUptime {
    Param(
        [String]$ComputerName = "localhost",
        [System.Management.Automation.CredentialAttribute()]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName
    $bootuptime = (Get-CimInstance Win32_OperatingSystem -CimSession $session).LastBootUpTime
    $uptime = (date) - (Get-CimInstance Win32_OperatingSystem -Namespace root\CIMV2).LastBootUpTime
    return New-Object psobject -Property @{"UpTime"=$uptime;"LastBootUpTime"=$bootuptime}
}
if(!(Get-Alias Get-Uptime -ErrorAction SilentlyContinue)){ Set-Alias Get-Uptime Get-ComputerUptime }

function Get-ComputerMemoryUtilization {
    Param(
        [String]$ComputerName = "localhost",
        [System.Management.Automation.CredentialAttribute()]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName
    Get-CimInstance Win32_OperatingSystem -CimSession $session | `
    Select-Object @{Name = "FreeGB";Expression = {[math]::Round($_.FreePhysicalMemory/1mb,2)}},@{Name = "TotalGB";Expression = {[int]($_.TotalVisibleMemorySize/1mb)}}
}
if(!(Get-alias Get-ComputerMemory -ErrorAction SilentlyContinue)) {Set-Alias Get-ComputerMemory Get-ComputerMemoryUtilization}
if(!(Get-alias Get-MemoryUsage -ErrorAction SilentlyContinue)) {Set-Alias Get-MemoryUsage Get-ComputerMemoryUtilization}

function Get-ComputerCpuUtilization {
    Param(
        [String]$ComputerName = "Localhost",
        [System.Management.Automation.CredentialAttribute()]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName    
    Get-CimInstance win32_processor -CimSession $session | Measure-Object -property LoadPercentage -Average | Select-Object Average
}
if(!(Get-alias Get-CpuUsage -ErrorAction SilentlyContinue)) {Set-Alias Get-CpuUsage Get-ComputerCpuUtilization}

Function Get-ComputerUtilization{
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.CredentialAttribute()]$Credential,
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
        if($Continue){
            sleep 1; Clear-Host; Write-Host "`n`t`t`tPress Ctrl-C to exit`n" -ForegroundColor Red
        }
    } while ($Continue)
}
if(!(Get-alias top -ErrorAction SilentlyContinue)) {Set-Alias top Get-ComputerUtilization}

function Install-DockerPS{
    Register-PSRepository -Name DockerPS-Dev -SourceLocation https://ci.appveyor.com/nuget/docker-powershell-dev
    Install-Module -Name Docker -Repository DockerPS-Dev -Scope CurrentUser -force
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
                (Get-TrustedHost).Replace("$c","") | %{if($_ -ne "") {$TrustedHosts += $_ + ","}}
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

    $modules = "NTFSSecurity","Posh-SSH","PSCX","AzureAD"

    ForEach($module in $modules){
        if(!(Get-Module -ListAvailable -Name $module)){
            Find-Module $module
            Install-Module $module -Force -AllowClobber
        }else {Update-Module $module}
    }
}

function profileUpdateCustomModules{
    $data = "FortiVPN.psm1 76492d1116743f0423413b16050a5345MgB8AEUASQAzAGEARQBEADkAWgBYADMAbgBXAHcAYQA4ADAAVQBoAEgANQB2AHcAPQA9AHwAOQAzADYAYgBhADUAMgAzAGIAMgA3AGIAOAA4AGIAZQAzADkAMAAzADEANAA1ADUANgA5ADUAOQBkAGIAMwA4AGYAMQBmADUANwBjADYAZgA0ADUANQAwADgAOAA0AGUAZABjADEAZAA0AGMAMQAxAGQAZAAyADcANAA1AGQAYQAxAGUANgA5ADIAYQA3ADAAMAA0ADcAZQAyADAAOQA5ADIANwA3AGUAYQA3AGYANAA1ADgAYQBmAGYAOABhADkAMgBkADEANQAwAGEANQAyAGMAMAAwADAAZQA2ADIAMABkADEAZgBmAGMAMgA2ADMAYgA2AGQAMgBhADUAMQAzADIAMgAyADIANwBhADgAYQAzADIAMAAwADkANwA3ADMAZgBkADcAZAAyADEAMABmADcAYQBiADAAYwAwADYAYgBhADgAMQBjADMAYQA1AGIANABjADQANABlADcAYwA4ADAANQA5ADMAOABmAGMANwA0AGEAYQBiAGMANgAyAGMAOQAxADcAZQA3ADEAOQBmADkAYwA0AGMAYQAzADYAZAAyADYANwA3AGIAOAAwADIAYwA5ADMANgAwADkANwBjADUAZAA0ADgANQA2ADEAMQBmAGQAZQBiAGEAZAAxAGQAZQBkADUAOAA5ADAANABlADEAMwBkADgAMwAxADcAOAA0ADcAZQAzAGUAMwA2ADgAMgBhADUAMQBhADgAMAA1ADIAMgBmADQAMQA3AGYAMgBiAGUAOABkADcAZAA3ADIAMgBmADAAMwBkADQAZABkADYAYgBjAGIAMgBjAGQAOQA4AGIAMwBlADcANwBmAGQAOAA0AGUAZAAwADAAYwAyADAANABjADkAZAA2AGIAMQA4ADYAOQA1ADMAMgBhADMAMgAwADIAOQBhAGIANABmADQAMwBiAGYAYQBlAGUAYQAwADIAMgA0ADIAMAA5ADUANQA3AGMAYgBhADQAMwBkAGUAYQA5ADEAYQA5AGUAMABhADgAYQBiAGYANgBjAGUAMwA0AGMAOAAzADkAMQAzADQAMwBjAGQANgBhAGYAMQAyAGQAMQBjAGMAMQAyAGQAYwBjAGQANgBlAGMAYQBlADEANwBiADkAOQA4AGQAMABmAGUANAA0ADEAMgA1ADIAYwBhADYAYwA4AGQANgBkADMAMwA3ADAAYgBkADkAOABlAGIAYgA0ADMAZABkAGQAYgAxADkANgBlAGUANAA3ADUAZQA3ADMAYQAyAGEAYwA2AGQANgBjAGIAZQA5AGIANwA5ADMAMwBmADYAOAAyADgAYQBmAGUANgBjAGEAMwA1AGUAYgA5ADkAMQAyADQAMwBiADYAYwBlADEANQBkAGYAMQAwADkANABhAGQANQA4ADIAZABhADIANQA0ADMANQA3ADkAOABjAGUAMQBmAGQANwAzAGMAZgA2ADUAMgA2ADQANwBlADcANABhADAAYQBkAGYAZQBhAGMANgA2ADgAZgBkADQAMQA4ADcANAA0AGUAYgBjAGEAYwBmAGUANAA3ADkAMwA5AGEAMAA3AGIAMAA3ADYANwA5ADYAYwAzADkANgAzADMAYwA4ADMANQA4ADIAMgBkADQANAA5ADAAMQBmADMAMwAzAGIAOABjADUAMwBkADgAMAA5ADAANgBjADkAMwA0ADkANgAzADgANgAwAGMANgAyADQAMgBhAGIAYgA0ADgAYgA3ADAANQBmADAAZgA2ADEAMQBjAGYAMAA0ADQANwA3AGIAZQA1AGQAMAA3ADEAYwAwADIA
HostFile.psm1 76492d1116743f0423413b16050a5345MgB8AFcAWgArAFoARwAyAEkASgBQAEUANgBaAHAAYQA1AHQAMABBAG4AYwBSAGcAPQA9AHwAZAA0ADYAZAA1ADQAZgBiADcAMgBhAGUAMQBhAGQAMAA3AGIAZQA1ADkAYgA3AGYANwBiAGMAOQBhADEAYgA3ADUANwBkAGIAZgBlADEAYgA2ADgAYQA4AGEAMAA5ADgAMgAyADkAZgA5ADYAMAAwADMAMwAxADEAYQBiADgAMgAyADAAMAAxADkANgAxAGQANAA2AGQAMABhAGYAMQBjAGEAZAA3ADgANgBlADAAZAA2AGMAZAAyADQANwBhADEAMgBmAGUAMwA0ADQAMAA2ADcAZABmADQAZgAxAGEAMAA3ADIANgAzAGMAOQA3ADEAMAAzADAAMgA5ADgAOABkADYAZABlADUANwA3AGQAZgA2ADgAYgAyADQAMgBlAGYAMwA3AGIANQA2ADkAZAA3AGQAMgA2ADEAYQA5AGQANABhAGYANgA3ADgAMgBlAGIAZABhAGUAMAA0AGUAMgBjADAAYwBlADYAZgAzADIANwA2ADAAYgA3ADgAMwA0ADQAZgAxADEAZAA1ADIAOQBiADYANAA5ADgAMQAwAGEAMgAyAGIAYgBmADUAMwA5ADEAYwA3ADYAMABjADAAMgBiADMAZAAyAGQANAAyADYANgA1AGQAOAA0AGEAYQA2ADIAMgAwADgAZgAxADAAMwBkADIAYwA0AGQAYQA2ADUAOABjAGQANgAxADUAYQA3ADMAMAA5ADQAYwBiAGEAMwA3AGUANAA4ADgAOQA1AGUANwA2ADEANAA3AGEAMgBhADAAMAA1ADMAMQA0ADEANABmAGMAYQA4AGYAMwA3AGQAMgA2ADQAZAAxAGIAMQA3AGIAZAAxADcAYgAxADEAMABkAGYAZQA1ADcAOQA0ADYAOQA3AGYAYgBhAGEANABkADUAZAA2ADEANwA4ADAAYgAxADcAOAA3ADQANQA5ADgANQA5AGUAZgAyAGMANQAxADkANgA4ADAAMwAyADYAMQBmADQANQBkADAAZgA3AGQAMgBjAGMAYQAwAGYANABhADMAMgBkADkAOQBlAGYANgAyAGQANQBiAGEAMQBmADEANAA2AGQAYwA4ADEAMwA1ADMANQBlADcAMAA5ADAAMwBiAGQANwA0ADkAYwBhADYAZAA5AGIAMwAyAGMAMQBlADAANwA2AGIANAAxADAAZgBjADMAMAA2ADEAZABmADIAMABiAGUAYQBiADYAMQA2ADUAMwA1ADEAYQBkADgANAA2ADUAMQA5AGIANgBmADAANABkADkAMgAwADcAOQAxAGQANgBhADAANQAyADUANwA0AGUAMwBmADgAYwAyAGQANQAyADgAMgAyAGEAMgA0AGUAYQBjADMANAAxADMAZQA2AGIAYgA2AGEAZgA2ADkAOQAxAGEAMQA4ADAAYgAyAGEAZAA2AGQANwA4AGIAMQBjAGMAMQBjADAAZgA2AGMANQAxADEAOABhADYAYgBlADkANgAyAGIAMABmAGIAMQAwAGYAMgBjADEAZABhADYAMAA5AGQAMgA3AGYAYwAzADQANAA5AGEAZAA0ADYAOQBhADcAMwBiADAANABhAGIAOAA0AGIAYwBmAGUAYQBiADcAOQAxADAAYgA1AGQANgA1ADcAMwA4AGUAZgBhADUANQBlADEANAA4ADQAMgA3AGUAMwAzAGYAYwAwADEANgA1ADMAYwBjADEAZABjAGYAYgBlADgAMgA2ADgANABjADUANwA4AGYANAA3ADYAMAA2AGUAOQAxAGYANwAwADkANQAyADAAMQAzADYAMQA1AGMA
Store-Credentials.psm1 76492d1116743f0423413b16050a5345MgB8AEYAWQBOADUAWgB2AHoAbwBPAE8AcgArAGgAQwBjAHgAOQAxAFoAYQB6AGcAPQA9AHwAYwAyADUANAAxAGEAZAA4AGIAMQA4ADQAZgBkAGQAOABlADEAZQA1AGUAOAAxADgANwAxAGYANgAzADgAYgA2ADYAYwBjADQAMwA0ADEAOQAxAGEAMgAzADUAOQA3AGQAOAA0ADgAYQA4ADEAYQA0AGMAZABlAGYAMgA2ADcAZQA4AGIAMAAxAGMAZQAwAGUANgA3AGEAMgA4AGUAYwBmADIAZgA0ADgAYQAyAGIAYgA3AGMAMgBlAGYAOAA3ADkAYgBhAGEAMwA1AGQAYQA3ADIAMgAwADMAZAA5AGUAZABmADMAMQA0ADYAZgBkADQAMwA1AGQANQA4ADEAYgAyAGIAYwAzAGMAMwAyAGEAYQAzAGEANQA4ADIANQAwAGUAOQA1ADgAOABlADEAYwA4AGYAZgAzAGIANQAyADkAZQAxADIAZgA5ADIAOQAxADAAMwAyAGMAYgA5AGIAOQA4AGEAZABmADEAMAA5ADQAYgAyADQANwBjAGIAYgA4ADAAMwAxADQAZABmAGEAZAA4ADMAOQA2ADYAZAAxADIANwA5AGMAMQBjADYANgA2ADIAMgAxAGQAZABmAGQANwA5AGMAYgA4ADAANgBjADUAZgA1AGEANAA1ADMAYQAxADgAZAA5AGYAOABiADYAYwA0ADQAMgA2AGQAMAA1ADUAMAA3ADUAOABiADkAOQBlADYANQAyAGMAZQA4AGMAMgAwADEAMgA5AGUAYwA2ADMAYgBjADQAMwBiAGMAYgA5ADYAZgA2ADcAYgA3AGUAYgBkAGIAYQAxADIAMQA2AGEAMgA0AGEANgA1ADQAZQBhADgAYQAyAGQAMQA2AGIAZQAwADkAZQBhAGYANAA1ADkAOQA1ADgAMgBlAGYAMgAxADIAZAAxADgAZAA4AGUAZABjADcAYQA0ADkAOQBhADEAOQA2AGYAZABhADgAMgBhAGEAZgBiAGUANwBhAGEAZgA2AGYAYQA0ADkAZQA1AGEAOQBhADYANABjAGYANAA3AGYANgBkADYAYgBhAGQAYQAyADIAMwBhAGQANgA3AGEAMAA2AGYAMwA1AGIAOABiADcANABlAGEAZQAyAGYAZAAxADIAMwBjADUANQBkADkANQBjADIANwA4AGEAZABlADQAMgBlADUAOAA0ADAANgBkADgANwAwADMANAA3AGEAZABiADMAYQA0ADEAYQAyADQAMgBlAGUAYQBjADkAMwBlADkAZAA4ADQAMQAyADAANQBlAGYAMABiADUAZgA5ADAAOAAwAGEANQA2ADUAYQBiADgAMgA5ADQAOABiAGQAMgA0AGUAMABjADEAZQBlADAAZQBmADYANAAwADYAMwA1AGUAZAA0ADkANgA3ADUAOABkADkAMQBkAGYAOQA0AGEAMgA1ADEAMQA2ADEAMwBjAGQAMAA5ADIAYQAzADQAMQBmADEAZQA3ADEAZAAzADkAMwBmAGYANAA4ADQAZAAwADMAZgA2ADQANAA4ADAAZQA0AGQANwA4AGUAMwBhADcANQBmADcAZgBmADYAMAA5ADYAOQBiADQAZQAyAGMAYwA2AGQAZgAzAGUANQA3ADUAOQAwAGUANwBhADIAYwBmADkANwBkAGEANABkAGUAZQA5AGMANQAxADUAYgBhAGIANQBmADkAYwAyADUANgBmAGMAYwA4AGMAZQBiADYAMABmADEAYQA4AGEAOABkADQAMwBlADQAZQA2ADIAOAA0AGEAZgAyADYAMQBlADgAYwA0ADIAYgBiADkAYgBlAGIA
Micellaneous.psm1 76492d1116743f0423413b16050a5345MgB8ADQATQBkAGIAawAwAHcAdQBhADkANwBHAEsAZwBCADQASQBKAEQAZwBVAGcAPQA9AHwAOAA5ADIANwAyADMAOQBiADAANABkAGQAZgBjAGUAYwBlADIAMgA5ADYAMgAxADUAZAA4ADgAYgA2AGQAZQBjADYAOAAxADgANgBhADkANAA3ADUAOQBlADIAOQA0ADgAYgBlAGQAOABiADEAMwA3AGQAMgAxAGEAMgA3AGYANABmAGQAZQBhADAAOABhADMAOQBjADYAMgBiADIAMABkADcAMgBkADAAMQBhADQAYQBjADcANAA0AGMAMAA2ADUAOQAzAGQAZQA2ADQAYgAwADgAYgA0AGIAMwA0AGIAMgA2ADIAMQBjADkAMQAyADcAMABjADQAMgA0ADEAZgA3ADEAMwA5AGIANQA1ADQAOAA2ADYAMQBiADMAMwA5AGEAOABlADgANAA5ADYAMABlADkAZAA5AGQAOAA5AGQAYgA5ADYANAAyADEAMgAxAGYAZABmADgANwBkADYAMwA2ADIANwAzADQANQA1ADEAYQBkADMAMwA1ADYAMwA2AGEAMABlADIAOAAyAGUANQBlAGMAYwAxADUANgBiAGMAYwA3ADkAMgAwAGMAMwBmADQAYwA1AGEAYQBmADAAYgA3ADMAZgAwADYANABkAGMAMAA4AGMAZgAxADMAZQBiADIANwA5AGMAZQBlADEAMgAyADIAOAAxAGMAZAA3ADIAYwA0ADkAOQA2ADYANQBjADcAZgBjADMAMQBmADYAOQA5ADYAOAA3ADAAMQA0ADkAMwBhAGEAOQBlADYAMwA1ADAAYQAxAGYAYgAxADUANQBlADMAMQA4ADgAZgA5ADMANwAyADQANAAyADMAYgBhADUANgA4ADMAYQAxADIAZABkADYAYwAyAGMAYQA0ADcAOQA5ADMAZgAwAGUAOQAwADcAMAA3ADYAMwA5AGMAYQBlADAANAA1ADQAZgBiAGIANwAwAGIAMAA5AGYAMQAzAGYAMAA1ADYAOQBmAGQAZAAzADgANQA4ADgANABmADAAYgAwADAAYwAyADgAMAA5ADEAYwA2ADcANAAzAGEAMgA3ADUAOABlADEAMwBiAGQAYwBjADIAOAA2ADAAZQBjAGEAOAA4AGMAYQBkAGYAMAA4ADUAMABkADQAZQBjAGQANAAyADkAMABkAGEANgBjAGUAYQA4ADcANwBiAGUAYwBjAGMAZAAwAGQANgBmADMANQAxAGIANwA0ADUANgA4ADYAZQAzADAAYwA0AGIAZgBlAGEAYgA4ADQANgA4ADgAZgBlAGMAZQBkAGIANgA5ADYAZABiADUAMABmADAAMwAzADkANABlAGQAMgBjAGMANQBlADEAOABhADAAZQA3AGIANgA1ADMAYgBmADIAYgA4AGEANQA1AGUAOQA1ADcAZQA5ADIANwA0ADQAOQA1ADQANwBmADgAMwA2AGYANwAyADUAMABlADcAZgA5AGIANQBmADIAMwBlADMAYQA5ADkAYQBmADIAMAA1ADAANgA0ADYANwA3AGIAOAAwADAAYQA5ADkAOQA2AGUAYQBlADEAYwBhAGMAMABhADUANAA2AGYANwBlAGMAZgBlADcANAA4AGYAYQBkADkAMABkAGQAOAA4ADEAYwBmAGYANAA4ADIAYwA2AGEANABlAGEAOABjADMAOQAwADIAMQA0ADMAMAA4ADQANABjAGIAOAA5ADkAYwBiAGIAMABhAGUANQBmAGUAZABlADEANQA2ADEAOQA1AGEAZgA1AGIAZQBhADQAZAA3ADYAYQA0AGMANgAzAGYAOABlADgAZgAzAGYA
TimeClock.psm1 76492d1116743f0423413b16050a5345MgB8AFAAOQBiAEYATABNAEYAUQB0AFkAMQBOAHUATQA5AGkAegBCAFUATgBRAFEAPQA9AHwAYwAzADgAYQAwADEAYwAwAGIANgA1AGIAMABlAGIANQA4ADMAZABiADcAOQA5ADYAYwAxADYAMABhAGQAZQBiADgAZgAzAGIAMgA4ADIAOQAwADQAMABlADcAZAA2ADEAOABiADAAZgA1AGMANQAzAGEAYwBjADMAYQA2ADAAYgA4AGMAZAAxAGUAZgAzADYAOAAzADAAZQA1ADgAYgA3ADUAYQBjADgAMwA4AGUAMQBhADMAZABhAGIAOABlAGEANQAyAGEAZQAwAGUAOAA2ADgAYgAwADAAMwBjADkAYgBiADgAOQAwADkAOQBhAGQANQBjAGUAYgBkADQAMgAxAGYAZABkADEANAAxADQAMwBkADQAMQBmAGYANwAxADcAYQA4ADEAZgAyADIANwA5AGUANwBiAGIAMABiADAAYwBjAGEANgA1ADgAZQBiADEAZgBjADAAMAA3AGQANAAzADkAMABkADcAZAAxADgANAA1AGYAOQBmAGUANABlADMAYgA1ADAAYwBhADIAMwA2ADAAYgA1ADQAMgBlADQAMQBhAGMAZgA0ADUANwAxAGMAYQA5AGMANwAzADAAMwA3AGYAZgA4AGQAZABmADYAZABkADQANAA4AGUAYwAxAGEAOAAxADIANwBmADkAZQAxAGIAYgBhADUAYQBjAGIANQBjADQAOABkADkAYgBkADMANAAyADcANwBlADcAOABhADcAYwAzAGEAZAA1AGMAZQAyAGYANAAyAGYANABkAGEAZgA5ADkAMQAxADIAYgBkADMAOQA4AGQAMgAyAGUANwBkADMAOABjADUAYgA4AGIANwAwADkAZgA3ADcAZAA3ADIANwAxAGYAZAAyADcAYgAxADUAYgA3ADEAMAAwADcAYgAwAGIAZgA5ADkAZABjAGIAMQBjADkAYwA5ADcAYgAzADEAZgBmADIAZAAwAGQAOQBlAGMAZgAzAGUANABiAGIANABkADgAYgAyADQAZgBjADcAZgA3ADMANgBhADUAMwA2ADIANwA5ADMAZgA5AGEANQBjADkANwBmADMAMwAzADUAZQBlADAAOQAwADIANgA0ADAAZQBmADgAYwA4ADYAZQAwADEAYgBmADkAMAAwADQAMABiAGMAMgBiADUAZAA5ADIAZQA2ADIAYwAwAGMAMwBhAGUAYgBiAGMAMwBlAGMANgA1ADQAZQBiADgAOAAxADgAOQBkAGIAOAA4ADIANAAyADEAYgA2AGYAYgA1ADEAMQA4AGMANwAxADMAZQBkAGIAZQBkADkAOQA5AGEANwA1ADQANgA0ADEANgBjADkAZQBhAGIAZgBkAGEAYQA0ADQANQA5ADUAMgAyADcAMQA5ADMANwAxADgAYwBkADkAMwA3AGMAMgA4ADYANgA0ADcAMgA1AGUAOQBiAGIANgBhADkAYwA5ADgAMgBlAGYAMwBhAGIAMQA0ADkAMABjADkAZgAyAGIANAA2ADYAMQA3ADkAMwA1ADIAYwA5ADkAYwBjAGQANQA0AGIAZABiAGUAZgA0ADkAMgA5ADAAZgA3ADQAYQA4ADUANwA0ADYAMgBmAGEAZAAzADQAZABmADQAMQBjAGIANwA2AGYANwBjADgAMAA0ADAAYgBlADUANQAwAGMAOABhAGMAZQA5ADgANQBjADEAZABmAGMAMwBlADYAYQBlADQANwA3ADkAYwBjAGUANAAwADYANQAzADMAZAAzADUANgBlADEAZgBmADEAYwAyAGMAMwBiADYAZgAxAGUAMQAxADMA"

    #Clean Slate Protocol
    if(!$(Test-Path "$defaultPath\CstmModules")){ 
        New-Item "$defaultPath\CstmModules" -ItemType Directory -Force
    }else{
        Get-ChildItem "$defaultPath\CstmModules" -Recurse | Remove-item -Force
    }

    forEach($module in $data.Split("`n")){
        $url = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $module.Split(" ")[1] -Key $profileKey)))    
        $fileName = "$($module.Split(" ")[0])"
        Invoke-WebRequest -Uri $url -OutFile "$defaultPath\CstmModules\$fileName"
        Unblock-File "$defaultPath\CstmModules\$fileName"
    }
}

#############################################################################################################
#
#                                           Execution
#
#############################################################################################################

#set profileKey
if(Test-Path "$defaultPath\key"){ $profileKey = Get-Content "$defaultPath\key" }

#if not ran in correct directory, get user input about stuff
if($(Split-Path $script:MyInvocation.MyCommand.Path) -ne $defaultPath){
    $response = Read-Host "'$($MyInvocation.MyCommand)' was not run from its default location.`nWould you like to copy it there? This action will overwrite any previously created profile. (Y/N) "
    if($response -like "y*"){
        #create path if non-existent, otherwise copy item
        if(!(test-path $defaultPath)){New-Item -Path $defaultPath -ItemType Directory -Force}
        Copy-Item ".\$($MyInvocation.MyCommand)" -Destination "$defaultPath\profile.ps1" -Force
    }
    else { $defaultPath = (Get-Location).Path }

    #test existing profileKey, check against known hash, else ask for profileKey
    $hasher = New-Object System.Security.Cryptography.SHA256Managed
    if($profileKey -eq $null -or $(-join $hasher.ComputeHash($profileKey) -ne $hashedKey)){
        do{
            $secret = Read-Host "Please enter the profileKey phrase to download and setup the scripts: " -AsSecureString
            $profileKey = [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)))
        }while( $(-join $hasher.ComputeHash($profileKey)) -ne $hashedKey )
    }
    #save profileKey if staying on computer
    if($response -like "y*") { $profileKey | Out-File -FilePath "$defaultPath\key" }
}

if($Update){ profileGetModules; profileUpdateCustomModules }

#Special import of PSCX
if(Get-Module -ListAvailable -Name PSCX){
    Import-Module Pscx -ArgumentList @{ModulesToImport=@{CD=$false}} -NoClobber -Prefix CX
}

# Import credentials
if(Test-Path $defaultPath\credentials.csv){
    $credCSV = Import-CSV "$defaultPath\credentials.csv"
    forEach($item in $credCSV){
        $username = $item.Username
        $SecurePass = $item.Password | ConvertTo-SecureString -ErrorAction SilentlyContinue
        if($SecurePass){
            New-Variable -Name $("cred" + $item.VariableName) -Value (
                New-Object System.Management.Automation.PSCredential $username,$SecurePass
            )
        }
    }
}

# Import custom modules
if(test-path $defaultPath\CstmModules){
    Get-ChildItem "$defaultPath\CstmModules" | ForEach-Object{ Import-Module $_.FullName -Force -WarningAction SilentlyContinue }
}

$ProgressPreference='Continue'

#Set profile variable to the name of your profile
$Global:profile = "$home\Documents\WindowsPowerShell\profile.ps1"

# Clean up items
Remove-Item -Path Function:\profile*
Remove-Item -Path Variable:\profileKey
Remove-Variable defaultPath,Update,Version,hashedKey
