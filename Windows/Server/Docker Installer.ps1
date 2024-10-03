$ErrorActionPreference = "Stop"

$welcomeMessage = @'
=====================================================================================
Docker Desktop Installer for Windows Server 2022/2019

Author : CrowKing77077
Version : 1.0.0
Date : 2024-09-13
=====================================================================================
'@

Write-Host $welcomeMessage -ForegroundColor Cyan

$config = @{
    Name = "Docker Desktop Installer"
    # InstallPath = "C:\Fusion Pipeline Manager"
    TempPath = "C:\docker_temp"

    OsVersion = $null
    OsBuildNumber = $null
    OsEdition = $null
    
    alreadyInstalledWsl2 = $false
    alreadyInstalledVmPlatform = $false
    alreadyInstalledHyperV= $false
    alreadyInstalledDockerDesktop = $false

    DockerDesktopVersion = $null
    DockerDesktopEndpointConnectable = $null
    DockerBackend = $null
}

function Read-ConfirmPrompt {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string[]]$AnwerSets
    )

    $answer = Read-Host -Prompt "$Message ($($AnwerSets -join "/"))"
    while ($true) {
        # Check if the answer is in the answer set
        # case insensitive
        if ($AnwerSets -contains $answer) {
            return $answer
        } else {
            Write-Host "Invalid input." -ForegroundColor Red
            $answer = Read-Host -Prompt "$Message ($($AnwerSets -join " / "))"
        }
    }
}

try {
    # 관리자 권한으로 실행했는지 확인
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "Please run this script as an administrator"
    }

    # 스크립트 실행 정책 확인
    $scriptPolicy = Get-ExecutionPolicy
    if ($scriptPolicy -ne "Bypass") {
       throw "Please set the execution policy to Bypass"
    }

    # $installedModule = Get-Module -ListAvailable -Name Docker -ErrorAction SilentlyContinue
    $comInfo = Get-ComputerInfo
    # OsVersion                                               : 10.0.20348
    # OsCSDVersion                                            : 
    # OsBuildNumber                                           : 20348

    # Windows 최신 업데이트 설치
    # KB5014021 업데이트 및 확인
    
    # CPU 정보 확인
    $processor = Get-WmiObject -Query "SELECT * FROM Win32_Processor"
    # CPU 코어 수 확인
    $cpuCores = $processor.NumberOfCores
    # 메모리 확인 (메모리 크기는 MB 단위로 가져오고, 이를 GB로 변환)
    $memoryGB = [math]::round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)

    Write-Host "CPU Name : $($processor.Name)" -ForegroundColor Cyan
    Write-Host "CPU Caption : $($processor.Caption)" -ForegroundColor Cyan
    Write-Host "CPU Cores : $cpuCores" -ForegroundColor Cyan
    Write-Host "Memory : $memoryGB GB" -ForegroundColor Cyan
    
    Write-Host "OS Edition : $($comInfo.WindowsProductName)" -ForegroundColor Cyan
    Write-Host "OS Version : $($comInfo.OsVersion)" -ForegroundColor Cyan
    Write-Host "OS Build Number : $($comInfo.OsBuildNumber)" -ForegroundColor Cyan
    Write-Host "OS Edition : $($comInfo.WindowsProductName)" -ForegroundColor Cyan

    $config.OsVersion = $comInfo.OsVersion
    $config.OsBuildNumber = $comInfo.OsBuildNumber
    $config.OsEdition = $comInfo.WindowsProductName


    if ($comInfo.WindowsInstallationType -ne "Server") {
        Write-Host "This installer is only for Windows Server" -ForegroundColor Red
        throw "This script is only for Windows Server"
    }
    
    if ($processor.VirtualizationFirmwareEnabled -ne $true) {
        Write-Host "Virtualization Supported: $($processor.VirtualizationFirmwareEnabled)" -ForegroundColor Red
        Write-Host "Please enable Virtualization in BIOS" -ForegroundColor Yellow
        throw "Virtualization is not enabled"
    }

    # OS 지원 여부 확인
    if ($config.OsBuildNumber -ge 20348) {
        # Windows Server 2022 ~
        $config.DockerDesktopVersion = "166053"
        $config.DockerBackend = "wsl-2"
    } elseif ($config.OsBuildNumber -ge 17763) {
        # Windows Server 2019 ~ 2022
        $config.DockerDesktopVersion = "84025"
        # 73704 - 4.4.4
        # 84025 - 4.11.1
        $config.DockerBackend = "hyper-v"
    } else {
        Write-Host "This script is only for Windows Server 2019 or later" -ForegroundColor Red
        throw "This script is only for Windows Server 2019 or later"
    }

    # 하드웨어 요구사항 확인
    if ($cpuCores -lt 4) {
        throw "CPU Cores must be at least 4"
    }
    if ($memoryGB -lt 8) {
        throw "Memory must be at least 4GB"
    }

    # docker가 설치되어 있는지 확인
    $dockerInstalled = Get-Command -Name docker -ErrorAction SilentlyContinue
    if (-not $dockerInstalled) {
        $config.alreadyInstalledDockerDesktop = $false

        $dockerInstallerConnectable = Test-NetConnection -ComputerName "desktop.docker.com" -Port 443
        if ($dockerInstallerConnectable.TcpTestSucceeded -eq $true) {
            $config.DockerDesktopEndpointConnectable = $true
        } else {
            Write-Host "Cannot connect to Docker Desktop Installer" -ForegroundColor Red
            $config.DockerDesktopEndpointConnectable = $false
            throw "Cannot connect to Docker Desktop Installer"
        }
    } else {
        $config.alreadyInstalledDockerDesktop = $true
        $config.DockerDesktopVersion = (docker --version).Split(" ")[2].Replace(",", "")
    }

    if (($config.alreadyInstalledDockerDesktop -eq $false) -and ($config.DockerDesktopEndpointConnectable -eq $true)) {
        # Docker Desktop 다운로드
        New-Item -ItemType Directory -Path $config.TempPath -Force | Out-Null

        Start-BitsTransfer -Source "https://desktop.docker.com/win/main/amd64/$($config.DockerDesktopVersion)/Docker%20Desktop%20Installer.exe" `
                       -Destination "$($config.TempPath)\Docker Desktop Installer.exe"
    }

    
    $restartNeeded = $false
    $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    if ($wslFeature.State -eq "Enabled") {
        $config.alreadyInstalledWsl2 = $true
        if ($config.DockerBackend -eq "wsl-2") {
            Write-Host "WSL is already enabled" -ForegroundColor Green
        }
    } else {
        if ($config.DockerBackend -eq "wsl-2") {
            Write-Host "Enabling WSL" -ForegroundColor Yellow
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart | Out-Null
            $restartNeeded = $true
        }
    }

    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
    if ($hyperVFeature.State -eq "Enabled") {
        $config.alreadyInstalledHyperV = $true
        if ($config.DockerBackend -eq "hyper-v") {
            Write-Host "Hyper-V is already enabled" -ForegroundColor Green
        }
    } else {
        if ($config.DockerBackend -eq "hyper-v") {
            Write-Host "Enabling Hyper-V" -ForegroundColor Yellow
            # # windows client에 해당
            # Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart | Out-Null
            Install-WindowsFeature -Name Hyper-V -IncludeManagementTools | Out-Null
            $restartNeeded = $true
        }
    }
    
    $virtualMachinePlatform = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    if ($virtualMachinePlatform.State -eq "Enabled") {
        Write-Host "Virtual Machine Platform is already enabled" -ForegroundColor Green
        $config.alreadyInstalledVmPlatform = $true
    } else {
        Write-Host "Enabling Virtual Machine Platform" -ForegroundColor Yellow
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart | Out-Null
        $restartNeeded = $true
    }

    $config | ConvertTo-Json | Out-File -FilePath "$($config.TempPath)\config.json" -Encoding utf8 -Force

    
    if ($restartNeeded) {
        $afterRunScript=@'
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$JobName,

    # [Parameter(Mandatory = $true)]
    # [ValidateSet("hyper-v", "windows", "wsl-2")]
    # [string]$DockerBackend,

    [Parameter(Mandatory = $true)]
    [string]$TempPath
)

Start-Transcript -Path "$($TempPath)\afterReboot.log" -Append | Out-Null
$ErrorActionPreference = "Stop"
$logout = $false
try {
    $configStr = Get-Content -Path "$($TempPath)\config.json" -ErrorAction Stop
    $config = $configStr | ConvertFrom-Json

    if (($config.alreadyInstalledWsl2 -eq $false) -and ($config.DockerBackend -eq "wsl-2")) {
        Write-Host "Enabling WSL2" -ForegroundColor Yellow
        wsl --set-default-version 2
    }

    if ($config.alreadyInstalledDockerDesktop -eq $false) {
        Write-Host "Installing Docker Desktop, please do not close this window" -ForegroundColor Yellow
        Start-Process -FilePath "$($TempPath)\Docker Desktop Installer.exe" -Wait -ArgumentList "install","--backend",$config.DockerBackend,"--quiet","--accept-license","--always-run-service"
    }

    # # Machine, User 환경변수 reload
    # $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    # $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User")

    $logout = $true
    Write-Host "Installation completed. Will be logout....." -ForegroundColor Green

    # Remove the scheduled task after the script continues execution
    Unregister-ScheduledTask -TaskName $JobName -Confirm:$false
    Read-Host "Press any key to continue..."
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    # Remove the scheduled task after the script continues execution
    Unregister-ScheduledTask -TaskName $JobName -Confirm:$false
    Read-Host "Press any key to continue..."
}
finally {
    Stop-Transcript | Out-Null
    
    if ($logout) {
        Remove-Item -Path $TempPath -Recurse -Confirm:$false | Out-Null

        # 로그아웃
        shutdown /l
    }
}
'@
        $jobName = "DockerInstaller_ResumeScriptAfterReboot"
        $afterRunScript | Out-File -FilePath "$($config.TempPath)\afterReboot.ps1" -Encoding utf8 -Force

        $arg = "-File `"$($config.TempPath)\afterReboot.ps1`" -JobName `"$($jobName)`" -TempPath `"$($config.TempPath)`""
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $arg
        $trigger = New-ScheduledTaskTrigger -AtLogOn #-AtStartup
        # $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # 현재 로그인된 사용자 계정으로 실행
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName $jobName -Description "This task resumes the script after reboot." | Out-Null

        $answer = (Read-ConfirmPrompt -Message "Do you want to restart the computer?" -AnwerSets "Y", "N")
        if (($answer -eq "Y") -or ($answer -eq "y")) {
            Write-Host "Restarting computer after 5 seconds....." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
    }
}    
catch {
    <#Do this if a terminating exception happens#>
    Write-Host $_.Exception.Message -ForegroundColor Red
    # $config | ConvertTo-Json | Out-File -FilePath "$($config.TempPath)\config.json" -Encoding utf8 -Force
} finally {
    Read-Host -Prompt "Press Enter to exit"
}

