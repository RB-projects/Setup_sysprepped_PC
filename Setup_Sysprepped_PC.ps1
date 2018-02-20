param(
[string]$SettingsFile = "$PSScriptRoot\settings.xml"
)
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}
$Error.Clear()
$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent

If (Test-Path $SettingsFile){# tikrinama ar nustatymu failas egzistuoja kitaip nera tiklso testi
    [xml]$settings = [xml](Get-Content $SettingsFile)
    }
Else{
    Write-Warning "Settings.xml file does not exist in the same directory as setup file.`r`nPlease check this or use parameter -SettingsFile c:/path/to/settings/file.xml"
    Read-Host -Prompt "Press any key to exit.."
    Exit
}

[array]$XMLversionArr = $settings.Setup.version.Split(".")
If ($XMLversionArr[0] -gt 1){
    Write-Warning "Settings XML file version are not supported"
    Read-Host -Prompt "Press any key to exit.."
    Exit
}
Else{
    [string]$CompName = $env:COMPUTERNAME
    [string]$user = $settings.Setup.DomainSettings.user
    [string]$Password = $settings.Setup.DomainSettings.Password
    [string]$Domain = $settings.Setup.DomainSettings.Domain
    [string]$OU = $settings.Setup.DomainSettings.OU
    [string]$SetupLogFile = $settings.Setup.SetupSettings.SetupLogFile
    [string]$SetupTempDir = $settings.Setup.SetupSettings.SetupTempDir
    [string]$AfterSysprep = $Settings.Setup.SetupSettings.AfterSysprep
    [string]$AfterSetup = $Settings.Setup.SetupSettings.AfterSetup
    [string]$TemporaryTaskName = $Settings.Setup.SetupSettings.TemporaryTaskName
    [int]$IPOctets = $Settings.Setup.DomainSettings.IPOctets
    [int]$IPZeros = $Settings.Setup.DomainSettings.IPZeros
    [string]$ComputerNamePrefix = $Settings.Setup.DomainSettings.ComputerNamePrefix
    [string]$UnattendFileName = $Settings.Setup.Optional.UnattendFileName
    [string]$KMSServer = $Settings.Setup.Optional.KMSServer
    [string]$KMSClientKey = $Settings.Setup.Optional.KMSClientKey
    [string]$OfficeVersion = $Settings.Setup.Optional.OfficeVersion
    [string]$PSExecutionPolicy = $Settings.Setup.Optional.PSExecutionPolicy
}

Function TXTlog($LogMessage){
    $LogTime = Get-Date -UFormat "%Y-%m-%d %H:%M:%S"
    If (!(Test-Path "$SetupTempDir\$SetupLogFile")){
        If (!(Test-Path $SetupTempDir)){
            New-Item $SetupTempDir -type directory
        }
        New-Item "$SetupTempDir\$SetupLogFile" -type file
        Add-Content "$SetupTempDir\$SetupLogFile" "$LogTime Starting setup... Temporary folder `"$SetupTempDir`" created.`n"
    }
    Add-Content "$SetupTempDir\$SetupLogFile" "$LogTime $LogMessage`n"
}

Function LastError(){
    if ($Error){
        $LastError = ($Error | Out-String)
        TXTLog "ERROR `r`n$LastError"
        $Error.clear()
    }
    Else{
        TXTLog "SUCCESS"
        $Error.Clear()
    }
}

Function ChangeUnattendProcArch($ChangeFrom, $ChangeTo, $UnattendFileSource, $UnattendFileDestination){
    (Get-Content $UnattendFileSource) |
    Foreach-Object { $_ -replace "processorArchitecture=`"$ChangeFrom`"", "processorArchitecture=`"$ChangeTo`"" } |
    Set-Content $UnattendFileDestination
}

Function TestNetwork(){
    $net = $false
    While ($net -eq $false){
        TXTLog "Checking network. If network down, then waiting for 3 seconds and trying one more time."
        Start-Sleep -Seconds 3
        $net = Test-Connection -ComputerName $Domain -Count 1 -Quiet
        LastError
    }
}

Function RegistryEdit($RegAction, $RegValue){
    # $RegAction: Delete, Add, Modify, RegGet.
    # $RegValue: Steps to do.
    $RegHome = "hklm:software"
    $RegPath = "SetupTMP"
    Switch ($RegAction){
        RegAdd{
            If ((Test-Path -Path "$RegHome\$RegPath") -eq $false){
                TXTLog "Adding REG key `"$RegHome\$RegPath`"."
                New-Item -Path $RegHome -Name $RegPath
                LastError
            }
            If ((Test-Path -Path "$RegHome\$RegPath") -eq $True){
                TXTLog "Adding REG property `"Stage`" with value `"$RegValue`"."
                New-ItemProperty -Path "$RegHome\$RegPath" -Name "Stage" -PropertyType "String" -Value $RegValue
                LastError
            }
        }
        RegEdit{
            TXTLog "Changing property `"Stage`" value to `"$RegValue`"."
            set-itemproperty -Path "$RegHome\$RegPath" -Name "Stage" -value $RegValue
            LastError
        }
        RegGet{
            If ((Test-Path -Path "$RegHome\$RegPath") -eq $True){
                TXTLog "Obtaining REG property `"Stage`" value."
                Get-ItemPropertyValue "$RegHome\$RegPath" -Name "Stage"
                LastError
            } Else {
                TXTLog "REG property `"Stage`" not exist"
            }

        }
        RegDel{
            If ((Test-Path -Path "$RegHome\$RegPath") -eq $True){
                TXTLog "Removing REG key `"$RegHome\$RegPath`"."
                Remove-Item -Path "$RegHome\$RegPath" -Recurse
                LastError
            }
        }
        Default{
            write-host "Usage with arguments: RegAdd [StepNr], RegEdit [StepNr], RegDel, RegGet"
            TXTLog "Error: possible function RegistryEdit is used without action (RegAdd [StepNr], RegEdit [StepNr], RegDel, RegGet) argument."
        }
    }
}

Function TaskSchedule($action){
    Switch ($action){
        TaskAdd{
            TXTLog "Creating task `"$TemporaryTaskName`"."
            Schtasks /Create /RU "SYSTEM" /TN "$TemporaryTaskName" /TR "powershell.exe -file $SetupTempDir\setup.ps1 -SettingsFile $SetupTempDir\Settings.xml" /RL HIGHEST /SC ONSTART
            LastError
        }
        TaskRun{
            TXTLog "Running task `"$TemporaryTaskName`"."
            Schtasks /Run /TN "$TemporaryTaskName"
            LastError
        }
        TaskDel{
            TXTLog "Removing task `"$TemporaryTaskName`"."
            Schtasks /Delete /TN "$TemporaryTaskName" /F
            LastError
        }
        Default{
            write-host "Usage with arguments: TaskAdd, TaskRun, TaskDel"
        }
    }
}

Function PreSetup(){
    TXTlog "Copying `"unattend.xml`" file to temporary folder `"$SetupTempDir`"."
    If (Test-Path "$PSScriptRoot\$UnattendFileName"){
        If ([System.Environment]::Is64BitProcess) {
            ChangeUnattendProcArch x86 amd64 "$PSScriptRoot\$UnattendFileName" "$SetupTempDir\unattend.xml"
        }
        Else {
            ChangeUnattendProcArch amd64 x86 "$PSScriptRoot\$UnattendFileName" "$SetupTempDir\unattend.xml"
        } 
        LastError
    }
    Else{
        TXTLog "`"$PSScriptRoot\unattend.xml`" not exist. Setup will continue without unattend"
    }
    TXTlog "Copying file `"settings.xml`" to temporary folder `"$SetupTempDir`"."
    Copy-Item "$PSScriptRoot\settings.xml" "$SetupTempDir\"
    LastError
    TXTlog "Copying setup file to temporary folder `"$SetupTempDir`"."
    Copy-Item "$PSCommandPath" "$SetupTempDir\setup.ps1"
    LastError
    TaskSchedule TaskAdd
    TXTlog "Registering stage `"Stage=0`""
    RegistryEdit RegAdd "0"
    If (Test-Path "$SetupTempDir\unattend.xml"){
        $command = "C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /$AfterSysprep /unattend:$SetupTempDir\unattend.xml"
    }
    Else{
        $command = "C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /$AfterSysprep"
    }
    TXTlog "Runing sysprep `"$command`""
    Invoke-Expression -command $command
    LastError
}

Function ChangeComputerName(){
    TestNetwork
    TXTLog "Obtaining computer IP address."
    $IP = ((Test-Connection $CompName -count 1 | select Address,Ipv4Address).Ipv4Address.IPAddressToString)
    LastError
    TXTLog "Computer IP is $IP."
    TXTLog "Generating new Computer name for `"$CompName`"."
    [array]$IP = $IP.split('.')
    For ($i=0; $i -lt 4; $i++){
        While($IP[$i].Length -le $IPZeros-1 ){
            $IPString = $IP[$i]
            $IP[$i] = "0$IPString"
        }
    }
    $ComputerNameSufix = ""
    For ($i = 4 - $IPOctets; $i -le 3; $i++){
        if (($i -le 3) -and ($i -ge 0)) {# IP Octets array element must by between 0 and 3
            $ComputerNameSufix = "$ComputerNameSufix-$($IP[$i])"
        }
    }
    $NewComputerName = "$($ComputerNamePrefix)$($ComputerNameSufix)"
    TXTLog "New computer name will by `"$NewComputerName`". Now going to change it."
    Rename-Computer -NewName $NewComputerName
    LastError
    TXTLog "Registering for next step `"Step=1`""
    RegistryEdit RegEdit "1"
    TXTLog "Restarting computer"
    Restart-Computer -Force
 }
 
 Function JoinToAD(){
    TestNetwork
    TXTLog "Joining computer `"$CompName`" to Active Directory. Computer OU will be `"$OU`"."
    $credential = New-Object System.Management.Automation.PSCredential("$Domain\$user",(ConvertTo-SecureString "$Password" -AsPlainText -Force))
    Add-Computer -DomainName $Domain -Credential $credential -OUPath $OU
    LastError
    TXTLog "Registering for next step `"Step=2`"."
    RegistryEdit RegEdit "2"
    TXTLog "Restarting computer"
    Restart-Computer -Force
}

Function ActyvateMSProducts(){
    TestNetwork
    TXTLog "Going to install Windows KMS key"
    $KMSString = (cscript c:\windows\system32\slmgr.vbs -ipk $KMSClientKey | Out-String)
    TXTLog "$KMSString"
    TXTLog "Going to set KMS server"
    $KMSString = (cscript c:\windows\system32\slmgr.vbs -skms $KMSServer | Out-String)
    TXTLog "$KMSString"
    TXTLog "Going to activate Windows"
    $KMSString = (cscript c:\windows\system32\slmgr.vbs -ato | Out-String)
    TXTLog "$KMSString"

    If (Test-Path -Path "C:\Program Files\Microsoft Office\Office$OfficeVersion\ospp.vbs"){
        TXTLog "Going to set KMS server for Office."
        $KMSString = (cscript "C:\Program Files\Microsoft Office\Office$OfficeVersion\ospp.vbs" /sethst:$KMSServer | Out-String)
        TXTLog "$KMSString"
        TXTLog "Going to activate Office."
        $KMSString = (cscript "C:\Program Files\Microsoft Office\Office$OfficeVersion\ospp.vbs" /act | Out-String)
        TXTLog "$KMSString"
    }
    ElseIf (Test-Path -Path "C:\Program Files (x86)\Microsoft Office\Office$OfficeVersion\ospp.vbs"){
            TXTLog "Going to set KMS server for Office."
            $KMSString = (cscript "C:\Program Files (x86)\Microsoft Office\Office$OfficeVersion\ospp.vbs" /sethst:$KMSServer | Out-String)
            TXTLog "$KMSString"
            TXTLog "Going to activate Office."
            $KMSString = (cscript "C:\Program Files (x86)\Microsoft Office\Office$OfficeVersion\ospp.vbs" /act | Out-String)
            TXTLog "$KMSString"  
    }
    Else {
        TXTLog "Office $OfficeVersion not found."
    }
}

Function PostSetup() {
    TXTLog "Removing temporary data"
    If (Test-Path "$SetupTempDir\unattend.xml"){
        TXTLog "Removig `"unattend.xml`" file from temporary folder `"$SetupTempDir`""
        Remove-Item -Path "$SetupTempDir\unattend.xml" -recurse
        LastError
    }
    If (Test-Path "$SetupTempDir\settings.xml"){
        TXTLog "Removig `"settings.xml`" file from temporary folder `"$SetupTempDir`""
        Remove-Item -Path "$SetupTempDir\settings.xml" -recurse
        LastError
    }
    TaskSchedule TaskDel
    RegistryEdit RegDel
    TXTLog "Removing setup script file `"$PSCommandPath`""
    Remove-Item -Path $PSCommandPath -recurse
    LastError
    TXTLog "Changing PowerSell Execution Policy to `"$PSExecutionPolicy`""
    Set-ExecutionPolicy $PSExecutionPolicy -Confirm:$False
    LastError
    TXTLog "Setup complyted. Going to Shutdown/Reboot"
    shutdown -$AfterSetup -t 0
}

$Stage = RegistryEdit RegGet
if ($Stage -eq "0"){
    ChangeComputerName
}
ElseIf ($Stage -eq "1"){
    JoinToAD
}
ElseIf ($Stage -eq "2"){
    ActyvateMSProducts
    PostSetup
}
Else {
    PreSetup
}