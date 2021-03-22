<#
.SYNOPSIS
    Script for checking when accounts are set with Password Never Expires
.DESCRIPTION
    Queries Active Directory for users with the Password Never Expires flag set.  Compares users against previous list and will write a log when a new user is observed.
    Requires the Active Directory powershell module.
    Must be run as an Active Directory User.
.PARAMETER FirstRun
    [OPTIONAL] [SWITCH] Use this switch during the first run.  This will create the initial list of users
.PARAMETER Check
    [OPTIONAL] [SWITCH] Use this switch during all subsequent runs.  This will query users and compare the against the most up to date list.  Will also update list
.PARAMETER EnabledOnly
    [OPTIONAL] [SWITCH] Use this switch to filter results to Enabled users only
.EXAMPLE
    Get-PNEUsers -Check -Enabled
.NOTES
    Congigure a scheduled task to run this script on a regular bases (e.g. hourly, daily). 
    The task must be run as an active directory user with file write permissions where the script is stored. 
    The user must have network access, so you will need to store the password when asked by task scheduled.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [switch]$FirstRun,
    [Parameter(Mandatory = $false)] [switch]$Check,
    [Parameter(Mandatory = $false)] [switch]$EnabledOnly
)

$scriptPath = Get-Location
$logfile = "$($scriptPath)\GET-PNEUsers.log"
$userfile = "$($scriptPath)\PNEUsers.txt"
$globalloglevel = 2

Function Write-Log {  

    # This function provides logging functionality.  It writes to a log file provided by the $logfile variable, prepending the date and hostname to each line
    # Currently implemented 4 logging levels.  1 = DEBUG / VERBOSE, 2 = INFO, 3 = ERROR / WARNING, 4 = CRITICAL
    # Must use the variable $globalloglevel to define what logs will be written.  1 = All logs, 2 = Info and above, 3 = Warning and above, 4 = Only critical.  If no $globalloglevel is defined, defaults to 2
    # Must use the variable $logfile to define the filename (full path or relative path) of the log file to be written to
    # Auto-rotate feature written but un-tested
           
    [CmdletBinding()]
    Param([Parameter(Mandatory = $true)] [string]$logdetail,
        [Parameter(Mandatory = $false)] [int32]$loglevel = 2
    )
    if (($globalloglevel -ne 1) -and ($globalloglevel -ne 2) -and ($globalloglevel -ne 3) -and ($globalloglevel -ne 4)) {
        $globalloglevel = 2
    }

    if ($loglevel -ge $globalloglevel) {
        try {
            $logfile_exists = Test-Path -Path $logfile
            if ($logfile_exists -eq 1) {
                if ((Get-Item $logfile).length/1MB -ge 10) {   # THIS IS THE LOG ROTATION CODE --- UNTESTED!!!!!
                    $logfilename = ((Get-Item $logdetail).Name).ToString()
                    $newfilename = "$($logfilename)"+ (Get-Date -Format "yyyymmddhhmmss").ToString()
                    Rename-Item -Path $logfile -NewName $newfilename
                    New-Item $logfile -ItemType File
                    $this_Date = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
                    Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
                }
                else {
                    $this_Date = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
                    Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
                }
            }
            else {
                New-Item $logfile -ItemType File
                $this_Date = Get-Date -Format "MM/dd/yyyy hh:mm:ss tt"
                Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
            }
        }
        catch {
            Write-Error "***ERROR*** An error occured writing to the log file: $_"
        }
    }
}

Function Get-CurrentPNEUsers {
    if ($EnabledOnly.IsPresent) {
        Write-Log -loglevel 1 -logdetail "Querying AD for users with PasswordNeverExpire = True; enabled users only"
        Try {
            $currentPNEUsers = Search-ADAccount -PasswordNeverExpires -UsersOnly | where {$_.enabled} | where {$_.UserPrincipalName}
        }
        Catch {
            Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured querying Active Directory: $_"
        }
    }
    else {
        Write-Log -loglevel 1 -logdetail "Querying AD for users with PasswordNeverExpire = True; all"
        Try {
            $currentPNEUsers = Search-ADAccount -PasswordNeverExpires -UsersOnly | where {$_.UserPrincipalName} 
        }
        Catch {
            Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured querying Active Directory: $_"
        }
    }
    Return $currentPNEUsers
}

Function Get-PreviousPNEUsers {
    $previoususers = @()
    Try {
        foreach( $line in Get-Content $userfile ) {
            $previoususers += $line
        }
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured retreiving previous user list: $_"
    }
    Return $previoususers
}

Function Compare-PNEUsers ($prevUsers, $currentUsers) {
    $cUPN = @()
    $currentUsers | ForEach-Object  {
        if (!($prevUsers.Contains($_.UserPrincipalName))) {
            Write-Log -loglevel 4 -logdetail "New PNE Flag Found. UPN:$($_.UserPrincipalName)|Name: $($_.Name)|SamAccoutName:$($_.SamAccountName)|LastLogonDate:$($_.LastLogonDate)"
            $cUPN += $_
        }
    }    
}

Function Write-PNEUsers ($users) {
    $null | Out-File -FilePath $userfile -Force
    $users | ForEach-Object {
        $_.UserPrincipalName | Out-File -FilePath $userfile -Append
    }
}

if ($FirstRun.IsPresent -and -not($Check.IsPresent)) {
    Write-Log -loglevel 3 -logdetail "Initiating..."
    Try {
        $u = Get-CurrentPNEUsers
        Write-PNEUsers $u
        Write-Log -LogLevel 3 -LogDetail "Initation complete. Initial User list written to $($userfile)"
    }
    Catch {
        Write-Log -LogLevel 4 -LogDetail "***ERROR*** An error occured: $_"
        Exit
    }
}

if ($Check.IsPresent -and -not($FirstRun.IsPresent)) {
    if (!(Test-Path $userfile)) {
        Write-Log -LogLevel 4 -LogDetail "***ERROR*** The initial list has not been initiated. Please run script with the -FirstRun switch before using the -Check option. Exiting"
        Write-Error "The initial list has not been initiated. Please run script with the -FirstRun switch before using the -Check option. Exiting"
        Exit
    }
    Write-Log -loglevel 2 -logdetail "PNE User check initiatied"
    $u = Get-CurrentPNEUsers
    $p = Get-PreviousPNEUsers
    Compare-PNEUsers $p $u
    Write-PNEUsers $u
}
