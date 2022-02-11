## Copyright (c) Microsoft Corporation. All rights reserved.

<#
.SYNOPSIS
This cmdlet collects a performance recording of Microsoft Defender Antivirus
scans.

.DESCRIPTION
This cmdlet collects a performance recording of Microsoft Defender Antivirus
scans. These performance recordings contain Microsoft-Antimalware-Engine
and NT kernel process events and can be analyzed after collection using the
Get-MpPerformanceReport cmdlet.

This cmdlet requires elevated administrator privileges.

The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.

.EXAMPLE
New-MpPerformanceRecording -RecordTo:.\Defender-scans.etl

#>
function New-MpPerformanceRecording {
    [CmdletBinding()]
    param(

        # Specifies the location where to save the Microsoft Defender Antivirus
        # performance recording.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RecordTo
    )

    # Dependencies
    [string]$wprProfile = "$PSScriptRoot\MSFT_MpPerformanceRecording.wprp"
    [string]$wprCommand = 'wpr.exe'

    if (-not (Test-Path -LiteralPath:$RecordTo -IsValid)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot record Microsoft Defender Antivirus performance recording to path '$RecordTo' because the location does not exist."
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidPath',$category,$RecordTo
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Resolve any relative paths
    $RecordTo = $psCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RecordTo)

    #
    # Test dependency presence
    #

    if (-not (Test-Path -LiteralPath:$wprProfile -PathType:Leaf)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency file '$wprProfile' because it does not exist."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprProfile
        $psCmdlet.WriteError($errRecord)
        return
    }

    if (-not (Get-Command $wprCommand -ErrorAction:SilentlyContinue)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency command '$wprCommand' because it does not exist."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprCommand
        $psCmdlet.WriteError($errRecord)
        return
    }

    #
    # Ensure Ctrl-C doesn't abort the app without control
    #

    $savedControlCAsInput = [Console]::TreatControlCAsInput
    [Console]::TreatControlCAsInput = $true

    #
    # Start recording
    #

    Write-Host "Starting Microsoft Defender Antivirus performance recording... " -NoNewline

    & $wprCommand -start "$wprProfile!Scans.Light" -filemode -instancename MSFT_MpPerformanceRecording
    switch ($LASTEXITCODE) {
        0 {}
        0xc5583001 {
            Write-Error "Cannot start performance recording because Windows Performance Recorder is already recording."
            return
        }
        default {
            Write-Error ("Cannot start performance recording: 0x{0:x08}." -f $LASTEXITCODE)
            return
        }
    }

    Write-Host "ok.`n`nRecording has started." -NoNewline

    Write-Host "`n`n=> Reproduce the scenario that is impacting the performance on your device.`n`n   Press <ENTER> to stop and save recording or <Ctrl-C> to cancel recording: " -NoNewline

    do {
        $key = [Console]::ReadKey($true)
        if (($key.Modifiers -eq [ConsoleModifiers]::Control) -and ($key.Key -eq [ConsoleKey]::C)) {

            #
            # Cancel recording
            #

            Write-Host "`n`nCancelling Microsoft Defender Antivirus performance recording... " -NoNewline

            & $wprCommand -cancel -instancename MSFT_MpPerformanceRecording

            switch ($LASTEXITCODE) {
                0 {}
                0xc5583000 {
                    Write-Error "Cannot cancel performance recording because currently Windows Performance Recorder is not recording."
                    return
                }
                default {
                    Write-Error ("Cannot cancel performance recording: 0x{0:x08}." -f $LASTEXITCODE)
                    return
                }
            }

            Write-Host "ok.`n`nRecording has been cancelled."

            #
            # Restore Ctrl-C behavior
            #

            [Console]::TreatControlCAsInput = $savedControlCAsInput

            return
        }

    } while (($key.Modifiers -band ([ConsoleModifiers]::Alt -bor [ConsoleModifiers]::Control -bor [ConsoleModifiers]::Shift)) -or ($key.Key -ne [ConsoleKey]::Enter))

    #
    # Stop recording
    #

    Write-Host "`n`nStopping Microsoft Defender Antivirus performance recording... " -NoNewline

    & $wprCommand -stop $RecordTo -instancename MSFT_MpPerformanceRecording
    switch ($LASTEXITCODE) {
        0 {}
        0xc5583000 {
            Write-Error "Cannot stop performance recording because Windows Performance Recorder is not recording a trace."
            return
        }
        default {
            Write-Error ("Cannot stop performance recording: 0x{0:x08}." -f $LASTEXITCODE)
            return
        }
    }

    Write-Host "ok.`n`nRecording has been saved to '$RecordTo'."

    Write-Host `
'
The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.
'
    Write-Host `
'
The trace you have just captured may contain personally identifiable information,
including but not necessarily limited to paths to files accessed, paths to
registry accessed and process names. Exact information depends on the events that
were logged. Please be aware of this when sharing this trace with other people.
'

    #
    # Restore Ctrl-C behavior
    #

    [Console]::TreatControlCAsInput = $savedControlCAsInput

    return
}

function ParseFriendlyDuration
{
    [OutputType([TimeSpan])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $FriendlyDuration
    )

    if ($FriendlyDuration -match '^(\d+)(?:\.(\d+))?(sec|ms|us)$')
    {
        [string]$seconds = $Matches[1]
        [string]$decimals = $Matches[2]
        [string]$unit = $Matches[3]

        [uint32]$magnitude =
            switch ($unit)
            {
                'sec' {7}
                'ms' {4}
                'us' {1}
            }

        if ($decimals.Length -gt $magnitude)
        {
            throw [System.ArgumentException]::new("String '$FriendlyDuration' was not recognized as a valid Duration: $($decimals.Length) decimals specified for time unit '$unit'; at most $magnitude expected.")
        }

        return [timespan]::FromTicks([int64]::Parse($seconds + $decimals.PadRight($magnitude, '0')))
    }

    [timespan]$result = [timespan]::FromTicks(0)
    if ([timespan]::TryParse($FriendlyDuration, [ref]$result))
    {
        return $result
    }

    throw [System.ArgumentException]::new("String '$FriendlyDuration' was not recognized as a valid Duration; expected a value like '0.1234567sec' or '0.1234ms' or '0.1us' or a valid TimeSpan.")
}

[scriptblock]$FriendlyTimeSpanToString = { '{0:0.0000}ms' -f ($this.Ticks / 10000.0) }

function New-FriendlyTimeSpan
{
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$Ticks
    )

    $result = [TimeSpan]::FromTicks($Ticks)
    $result.PsTypeNames.Insert(0, 'MpPerformanceReport.TimeSpan')
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyTimeSpanToString
    $result
}

function Add-DefenderCollectionType
{
    param(
        [Parameter(Mandatory = $true)]
        [ref]$CollectionRef
    )

    if ($CollectionRef.Value | Get-Member -Name:'Processes','Files','Extensions','Scans')
    {
        $CollectionRef.Value.PSTypeNames.Insert(0, 'MpPerformanceReport.NestedCollection')
    }
}

filter ConvertTo-DefenderScanInfo
{
    [PSCustomObject]@{
        PSTypeName = 'MpPerformanceReport.ScanInfo'
        ScanType = [string]$_.ScanType
        StartTime = [DateTime]::FromFileTime($_.StartTime)
        EndTime = [DateTime]::FromFileTime($_.EndTime)
        Duration = New-FriendlyTimeSpan -Ticks:$_.Duration
        Reason = [string]$_.Reason
        Path = [string]$_.Path
        ProcessPath = [string]$_.ProcessPath
        ProcessId = if ($_.ProcessId -gt 0) { [int]$_.ProcessId } else { $null }
    }
}

filter ConvertTo-DefenderScanStats
{
    [PSCustomObject]@{
        PSTypeName = 'MpPerformanceReport.ScanStats'
        Count = $_.Count
        TotalDuration = New-FriendlyTimeSpan -Ticks:$_.TotalDuration
        MinDuration = New-FriendlyTimeSpan -Ticks:$_.MinDuration
        AverageDuration = New-FriendlyTimeSpan -Ticks:$_.AverageDuration
        MaxDuration = New-FriendlyTimeSpan -Ticks:$_.MaxDuration
        MedianDuration = New-FriendlyTimeSpan -Ticks:$_.MedianDuration
    }
}

filter ConvertTo-DefenderScannedFilePathStats
{
    $result = $_ | ConvertTo-DefenderScanStats

    $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedFilePathStats')
    $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:($_.Path)

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
    }

    $result
}

filter ConvertTo-DefenderScannedFileExtensionStats
{
    $result = $_ | ConvertTo-DefenderScanStats

    $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedFileExtensionStats')
    $result | Add-Member -NotePropertyName:'Extension' -NotePropertyValue:($_.Extension)

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
    }

    $result
}

filter ConvertTo-DefenderScannedProcessStats
{
    $result = $_ | ConvertTo-DefenderScanStats

    $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedProcessStats')
    $result | Add-Member -NotePropertyName:'ProcessPath' -NotePropertyValue:($_.Process)

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue@(
            $_.Files | ConvertTo-DefenderScannedProcessInfo
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
    }

    if ($null -ne $_.Extensions)
    {
        $result | Add-Member -NotePropertyName:'Extensions' -NotePropertyValue:@(
            $_.Extensions | ConvertTo-DefenderScannedFileExtensionStats
        )

        Add-DefenderCollectionType -CollectionRef:([ref]$result.Extensions)
    }

    $result
}

<#
.SYNOPSIS
This cmdlet reports the file paths, file extensions, and processes that cause
the highest impact to Microsoft Defender Antivirus scans.

.DESCRIPTION
This cmdlet analyzes a previously collected Microsoft Defender Antivirus
performance recording and reports the file paths, file extensions and processes
that cause the highest impact to Microsoft Defender Antivirus scans.

The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopExtensions:10 -TopProcesses:10 -TopScans:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopScansPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopProcessesPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopProcessesPerFile:3 -TopScansPerProcessPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopScansPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopFilesPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopFilesPerExtension:3 -TopScansPerFilePerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopProcessesPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopProcessesPerExtension:3 -TopScansPerProcessPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopScansPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopExtensionsPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopExtensionsPerProcess:3 -TopScansPerExtensionPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopFilesPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopFilesPerProcess:3 -TopScansPerFilePerProcess:3

#>

function Get-MpPerformanceReport {
    [CmdletBinding()]
    param(
        # Specifies the location of Microsoft Defender Antivirus performance recording to analyze.
        [Parameter(Mandatory=$true,
                Position=0,
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Location of Microsoft Defender Antivirus performance recording.")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        # Requests a top files report and specifies how many top files to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFiles = 0,

        # Specifies how many top scans to output for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFile = 0,

        # Specifies how many top processes to output for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerFile = 0,

        # Specifies how many top scans for output for each top process for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerFile = 0,


        # Requests a top extensions report and specifies how many top extensions to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensions = 0,

        # Specifies how many top scans to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtension = 0,

        # Specifies how many top files to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerExtension = 0,

        # Specifies how many top scans for output for each top file for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerExtension = 0,

        # Specifies how many top processes to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerExtension = 0,

        # Specifies how many top scans for output for each top process for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerExtension = 0,


        # Requests a top processes report and specifies how many top processes to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcesses = 0,

        # Specifies how many top scans to output for each top process in the Top Processes report, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcess = 0,

        # Specifies how many top files to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerProcess = 0,

        # Specifies how many top scans for output for each top file for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerProcess = 0,

        # Specifies how many top extensions to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensionsPerProcess = 0,

        # Specifies how many top scans for output for each top extension for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtensionPerProcess = 0,


        # Requests a top scans report and specifies how many top scans to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScans = 0,

        ## TimeSpan format: d | h:m | h:m:s | d.h:m | h:m:.f | h:m:s.f | d.h:m:s | d.h:m:.f | d.h:m:s.f => d | (d.)?h:m(:s(.f)?)? | ((d.)?h:m:.f)

        # Specifies the minimum duration of any scans or total scan durations of files, extensions and processes included in the report.
        # Accepts values like  '0.1234567sec' or '0.1234ms' or '0.1us' or a valid TimeSpan.
        [ValidatePattern('^(?:(?:(\d+)(?:\.(\d+))?(sec|ms|us))|(?:\d+)|(?:(\d+\.)?\d+:\d+(?::\d+(?:\.\d+)?)?)|(?:(\d+\.)?\d+:\d+:\.\d+))$')]
        [string]$MinDuration = '0us'
    )

    #
    # Validate performance recording presence
    #

    if (-not (Test-Path -Path:$Path -PathType:Leaf)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find path '$Path'."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$Path
        $psCmdlet.WriteError($errRecord)
        return
    }

    function ParameterValidationError {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]
            $ParameterName,

            [Parameter(Mandatory)]
            [string]
            $ParentParameterName
        )

        $ex = New-Object System.Management.Automation.ValidationMetadataException "Parameter '$ParameterName' requires parameter '$ParentParameterName'."
        $category = [System.Management.Automation.ErrorCategory]::MetadataError
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidParameter',$category,$ParameterName
        $psCmdlet.WriteError($errRecord)
    }

    #
    # Additional parameter validation
    #

    if ($TopFiles -eq 0)
    {
        if ($TopScansPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFile' -ParentParameterName:'TopFiles'
        }

        if ($TopProcessesPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerFile' -ParentParameterName:'TopFiles'
        }
    }

    if ($TopProcessesPerFile -eq 0)
    {
        if ($TopScansPerProcessPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerFile' -ParentParameterName:'TopProcessesPerFile'
        }
    }

    if ($TopExtensions -eq 0)
    {
        if ($TopScansPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopFilesPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopProcessesPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerExtension' -ParentParameterName:'TopExtensions'
        }
    }

    if ($TopFilesPerExtension -eq 0)
    {
        if ($TopScansPerFilePerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerExtension' -ParentParameterName:'TopFilesPerExtension'
        }
    }

    if ($TopProcessesPerExtension -eq 0)
    {
        if ($TopScansPerProcessPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerExtension' -ParentParameterName:'TopProcessesPerExtension'
        }
    }

    if ($TopProcesses -eq 0)
    {
        if ($TopScansPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopFilesPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopExtensionsPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopExtensionsPerProcess' -ParentParameterName:'TopProcesses'
        }
    }

    if ($TopFilesPerProcess -eq 0)
    {
        if ($TopScansPerFilePerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerProcess' -ParentParameterName:'TopFilesPerProcess'
        }
    }

    if ($TopExtensionsPerProcess -eq 0)
    {
        if ($TopScansPerExtensionPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtensionPerProcess' -ParentParameterName:'TopExtensionsPerProcess'
        }
    }

    if (($TopFiles -eq 0) -and ($TopExtensions -eq 0) -and ($TopProcesses -eq 0) -and ($TopScans -eq 0)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "At least one of the parameters 'TopFiles', 'TopExtensions', 'TopProcesses' or 'TopScans' must be present."
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidArgument',$category,$wprProfile
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Dependencies
    [string]$PlatformPath = (Get-ItemProperty -Path:'HKLM:\Software\Microsoft\Windows Defender' -Name:'InstallLocation' -ErrorAction:Stop).InstallLocation

    #
    # Test dependency presence
    #

    [string]$mpCmdRunCommand = "${PlatformPath}MpCmdRun.exe"

    if (-not (Get-Command $mpCmdRunCommand -ErrorAction:SilentlyContinue)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find '$mpCmdRunCommand'."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$mpCmdRunCommand
        $psCmdlet.WriteError($errRecord)
        return
    }

    # assemble report arguments

    [string[]]$reportArguments = @(
        $PSBoundParameters.GetEnumerator() |
            Where-Object { $_.Key.ToString().StartsWith("Top") -and ($_.Value -gt 0) } |
            ForEach-Object { "-$($_.Key)"; "$($_.Value)"; }
        )

    [timespan]$MinDurationTimeSpan = ParseFriendlyDuration -FriendlyDuration:$MinDuration

    if ($MinDurationTimeSpan -gt [TimeSpan]::FromTicks(0))
    {
        $reportArguments += @('-MinDuration', ($MinDurationTimeSpan.Ticks))
    }

    $report = & $mpCmdRunCommand -PerformanceReport -RecordingPath $Path @reportArguments | ConvertFrom-Json

    $result = [PSCustomObject]@{
        PSTypeName = 'MpPerformanceReport.Result'
    }

    if ($TopFiles -gt 0)
    {
        $result | Add-Member -NotePropertyName:'TopFiles' -NotePropertyValue:@($report.TopFiles | ConvertTo-DefenderScannedFilePathStats)

        Add-DefenderCollectionType -CollectionRef:([ref]$result.TopFiles)
    }

    if ($TopExtensions -gt 0)
    {
        $result | Add-Member -NotePropertyName:'TopExtensions' -NotePropertyValue:@($report.TopExtensions | ConvertTo-DefenderScannedFileExtensionStats)

        Add-DefenderCollectionType -CollectionRef:([ref]$result.TopExtensions)
    }

    if ($TopProcesses -gt 0)
    {
        $result | Add-Member -NotePropertyName:'TopProcesses' -NotePropertyValue:@($report.TopProcesses | ConvertTo-DefenderScannedProcessStats)

        Add-DefenderCollectionType -CollectionRef:([ref]$result.TopProcesses)
    }

    if ($TopScans -gt 0)
    {
        $result | Add-Member -NotePropertyName:'TopScans' -NotePropertyValue:@($report.TopScans | ConvertTo-DefenderScanInfo)

        Add-DefenderCollectionType -CollectionRef:([ref]$result.TopScans)
    }

    $result
}

Export-ModuleMember -
$exportModuleMemberParam = @{
    Function = @(
        'New-MpPerformanceRecording'
        'Get-MpPerformanceReport'
        )
}

Export-ModuleMember @exportModuleMemberParam

# SIG # Begin signature block
# MIIhdAYJKoZIhvcNAQcCoIIhZTCCIWECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB66cI40u3insbF
# hmcPzFY3D5BsSSqbn4n/USDESwFI+6CCC14wggTrMIID06ADAgECAhMzAAAIMJFU
# sm0DDuykAAAAAAgwMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIwMTIxNTIyMzYyMloXDTIxMTIwMjIyMzYyMlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpgkY9Csw/
# uH67FTpWJI3MnC5fLg2eQvJzS/VPEAyOfdfKF3ngteszX/rledZW+v/X7ryyzdVC
# 97dVSXxHwOx08iQqcaTPpAyjp2FP9T7zU2K/O/L5oYGhsR9SQIxaShApXxjcw0Ms
# sSANnF1rM0+OgqrAdJeuBnqUC0rAnFefsWo1qOvdSuCTEd/Enlk9MJ8AxwzpbXnb
# lxz7d0Peh9A4l02NDnR2dAlArEbbsnvfOJS7ns9r5PeSyztpaYSBMalj54bcepDL
# S+RDUpeGuTrZERSWpe9YPeneVxugiQRPX4/5K2MAKqBVTCBrXrsm1jfUzfuKmVjg
# N9zvsYbaAx/BAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUu1eSysVlRSSolEd2tVtE7T6e63owUAYDVR0RBEkw
# R6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MRYwFAYDVQQFEw0yMzAwMjgrNDYzMDEyMB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY
# 5QD/89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBX
# BggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB
# /wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFfK0IevjjEK/EC4xf9HY4ccUXgDK6xm
# h8pjDAXmYBnYfrFSU0E0f6t50BE+BjfAnnqxt7vexdVLu12tqo6Xtu+hxPNVudlW
# VPXJIkZGlnclxFv6Vcg+Pt5Vuh5ND17lHexYqNEiOrerImzFQNGHdhu+jFdVfZXS
# BUTzMQle6vJsWCDuZuKU7UzCEKMZGDxYFp2tnb0LFWn4c4iKjTpM1Hm4yVQdMHZv
# 7WdtGdWhiLxhTPm2NyXLSfiJ8ogTYXoYN3KJL2jNSe+sLek9SeY6gpaP0jSGV93R
# uBt79HRVT58d5MCw0+oHod6B9mIZSaaDk+2q54mzO7sA204Y3sVaw/UwggZrMIIE
# U6ADAgECAgphDGoZAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMjNaFw0y
# NTA3MDYyMDUwMjNaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHm7OrHwD4S4rWQqdRZz0LsH9j4NnRTk
# sZ/ByJSwOHwf0DNV9bojZvUuKEhTxxaDuvVRrH6s4CZ/D3T8WZXcycai91JwWiwd
# lKsZv6+Vfa9moW+bYm5tS7wvNWzepGpjWl/78w1NYcwKfjHrbArQTZcP/X84RuaK
# x3NpdlVplkzk2PA067qxH84pfsRPnRMVqxMbclhiVmyKgaNkd5hGZSmdgxSlTAig
# g9cjH/Nf328sz9oW2A5yBCjYaz74E7F8ohd5T37cOuSdcCdrv9v8HscH2MC+C5Me
# KOBzbdJU6ShMv2tdn/9dMxI3lSVhNGpCy3ydOruIWeGjQm06UFtI0QIDAQABo4IB
# 4zCCAd8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNFPqYoHCM70JBiY5QD/
# 89Z5HTe8MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEALkGmhrUGb/CAhfo7yhfpyfrkOcKUcMNk
# lMPYVqaQjv7kmvRt9W+OU41aqPOu20Zsvn8dVFYbPB1xxFEVVH6/7qWVQjP9DZAk
# JOP53JbK/Lisv/TCOVa4u+1zsxfdfoZQI4tWJMq7ph2ahy8nheehtgqcDRuM8wBi
# QbpIdIeC/VDJ9IcpwwOqK98aKXnoEiSahu3QLtNAgfUHXzMGVF1AtfexYv1NSPdu
# QUdSHLsbwlc6qJlWk9TG3iaoYHWGu+xipvAdBEXfPqeE0VtEI2MlNndvrlvcItUU
# I2pBf9BCptvvJXsE49KWN2IGr/gbD46zOZq7ifU1BuWkW8OMnjdfU9GjN/2kT+gb
# Dmt25LiPsMLq/XX3LEG3nKPhHgX+l5LLf1kDbahOjU6AF9TVcvZW5EifoyO6BqDA
# jtGIT5Mg8nBf2GtyoyBJ/HcMXcXH4QIPOEIQDtsCrpo3HVCAKR6kp9nGmiVV/UDK
# rWQQ6DH5ElR5GvIO2NarHjP+AucmbWFJj/Elwot0md/5kxqQHO7dlDMOQlDbf1D4
# n2KC7KaCFnxmvOyZsMFYXaiwmmEUkdGZL0nkPoGZ1ubvyuP9Pu7sCYYDBw0bDXzr
# 9FrJlc+HEgpd7MUCks0FmXLKffEqEBg45DGjKLTmTMVSo5xqx33AcQkEDXDeAj+H
# 7lah7Ou1TIUxghVsMIIVaAIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAx
# MAITMwAACDCRVLJtAw7spAAAAAAIMDANBglghkgBZQMEAgEFAKCBrjAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQg+C0cU762mMIomH93+6CUKZF6g+dGwpNzFqsZTJaL
# FzMwQgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAbSlLs8yQe
# iMQnLTiNDIDpZtaZY5K5S8+Ayv/EwIpe89R5OdNdV+H9dbXk02FwFGM2X+Y4VPlJ
# o9OsYmFJvh4cLPaNbPeAn8mQxhWmlq1VsTs+q/HP0CjKKkiXCYzvIDjsgyu+T9+Z
# ojaLyfwsQJ+5p3KBzJBWn/1UQRdShD6ciACrqo0KpzGPgiZgTFKwz+gcN7+aT4JB
# 8NdAL3xY5CnBfehF2dxwHrEyj4Ij/9Y0Ux8Ps39QEbYLpkb4tjZsF6Xuv97sKgxD
# ZsC3iG3EEWYVIm/LnGqZHJCnVnHcAZ0yTDCGt/nJsIjyD+Jh16WsBR5IRWxXzGEf
# /ek1y5rTbo5NoYIS+zCCEvcGCisGAQQBgjcDAwExghLnMIIS4wYJKoZIhvcNAQcC
# oIIS1DCCEtACAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIN9umWTs
# vXIwqrfZwWGNQUktYxghFxOmKBtqq7M1R+ALAgZhSLiHFwQYEzIwMjEwOTMwMjM1
# MjA2LjEzN1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MkFENC00QjkyLUZB
# MDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg5KMIIE
# +TCCA+GgAwIBAgITMwAAATjzlCHWYb7wKQAAAAABODANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMDEwMTUxNzI4MjBaFw0y
# MjAxMTIxNzI4MjBaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjJBRDQtNEI5Mi1GQTAxMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAxbn4p6lecIMyAgKjbK7+A/vdqY+y1pmgXIjOwXGv
# DAjy7aKPsp978FH+VPHh+3Yk9tc0ET3554bbS7TrObejbAH8bQ3UMqT7sU79nkAL
# xKqykp2lYfI/ZvrDVBecswbz1v/9CZcTdrSailbNDIg1lTfSA0LDhebTt02J+R5e
# CZrhfXedCWJP1kt1jy0E5wJUryqYOhXsrgewGdQsdH2bvp5JfRip+vg8rwVAJ78R
# HbbT5xTof+oFLOCAgmJG0e2yC7PAItErKPMWjM86pkVKR6atoVKuA5oG4d4NWkti
# UzKT2bynwlVkx74uu6rF7U+56udCwwk2mnNjD+OXDhyPGQIDAQABo4IBGzCCARcw
# HQYDVR0OBBYEFN/qrdzo76xTsTL7OYjFYMGeccC1MB8GA1UdIwQYMBaAFNVjOlyK
# MZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWlj
# cm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3
# LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEu
# Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQELBQADggEBAKN4sEhcC7G/DRKQy9LIto5OI5VZUgS3SBFZrNHsr/ZzR5MsaiY3
# eVxm9zZmbg+m4utdCi8FcUdPScD6r8FotfHO3dF/I6rjXej/sGbNv7h8HsBPWmL3
# Se+mZ+//IQrFi5rktqxs6LSkCPirmMhYZ6hUfJgN4PgtkG/mwqSqF04f74G8A2JH
# whDzsLBi4MYBZDT4KLJ9KAOgWZAmS4O3MAYxzsfbsN0WsjMgDMq8B2XqQNzILESw
# kAPRJKWXfX73C6IJS5MHWarGIj+BygDs5p6M28w53sXPWAKNAqt7ZGBaspG+k/t3
# xfWAm8eD4CnvEKSVM8Vffr2HwG+CUgACppowggZxMIIEWaADAgECAgphCYEqAAAA
# AAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBB
# dXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/F
# w+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC
# 3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd
# 0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHR
# D5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9E
# uqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsG
# AQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUA
# ZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkq
# hkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpX
# bRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvc
# XBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr
# 5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA
# 6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38
# ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooP
# iRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6ST
# OvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmy
# W9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3g
# hvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9
# zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKh
# ggLUMIICPQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MkFENC00QjkyLUZB
# MDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAEC86zs20AKnzakuISFLJspZ5oH5oIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDlAGWaMCIYDzIw
# MjExMDAxMDAzNDM0WhgPMjAyMTEwMDIwMDM0MzRaMHQwOgYKKwYBBAGEWQoEATEs
# MCowCgIFAOUAZZoCAQAwBwIBAAICLPgwBwIBAAICEXUwCgIFAOUBtxoCAQAwNgYK
# KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
# AwGGoDANBgkqhkiG9w0BAQUFAAOBgQCsuNWm5zgLaL4PQn9ZwyT+rXEoSBdatT9V
# R3p6+hgA+X7glG6bZAIARzZA8Fo1QrXr7pixEhx2oKOHz564XSIlIMw3HbsG7ltd
# fxNJza8WfVAVeqoiluwdn4rN9dYvWJolRPES9KYwGNqkPiBTSZ12b9A74Vu4633u
# wv4hJleZjjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwAhMzAAABOPOUIdZhvvApAAAAAAE4MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkq
# hkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIPYGe/RjdMFF
# kP1CC3Ue43nz39PBImigJ1cbSthmCusrMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB
# 5DCBvQQgQ0CTSvl/RCqSSGLiLKbu7sbS3mjmCOpO+ith7RaPhygwgZgwgYCkfjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAATjzlCHWYb7wKQAAAAAB
# ODAiBCAxxKFeDIFhxYiRiZJfbcWR+pmmOOYKhk7gavdRGFDegDANBgkqhkiG9w0B
# AQsFAASCAQBpcFtBVgV/XMYlJ2K6ncUyMpKFxJ9t4JvKLihwOxZ1zXiez4HxZKwl
# KZ1nCW8LM7hfNpJFsd85HS/c1uUqBXDMXqW7A+LhuQoHFgD23EraH2wVuXn/6CCu
# fSBWBRJDwUl4+o8Oe+DXQ4uFIsld4ap3FU+xRVS4ciuuCgtXpzWAPDfg1F0T+b2Z
# 4oGPWDA3bgVlH33JmKl2Kphqixma0yS006htHdRXH/17Ke2dLnwEad7p6rRc2R8H
# YkPVlU8hYjADZKTpVB12lkIGLSsixervEStmQsQP0WEyDYps6zvqpu7oyTKBVqTp
# hCmF3gITCZ9/6j6FvhrpK4wlZi6ShqSg
# SIG # End signature block
