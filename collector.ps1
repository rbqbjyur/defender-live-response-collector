# SPDX-License-Identifier: 0BSD
#Requires -Version 5.1

<#
.SYNOPSIS
    Collects timeline-relevant Windows triage artefacts into one zip, for
    retrieval through Microsoft Defender for Endpoint (MDE) Live Response.

.DESCRIPTION
    Upload to the Defender Live Response library and run it on a device. It
    writes <hostname>_<UTC timestamp>Z.zip under the Defender for Endpoint
    sensor's Temp folder (ProgramData\Microsoft\Windows Defender Advanced Threat
    Protection\Temp\Collections), falling back to a LiveResponseCollector folder
    in Windows\SystemTemp or the account's temp folder, and prints a
    per-artefact summary, the getfile command for the zip, and getfile commands
    for locked machine-wide files it could not read, with the SHA-256 of the
    zip (or of each volume) to check the download against. A zip larger than the
    part size set in CONFIG is split into standard split volumes
    (<name>.zip.001, .002, ...).

    Best effort: anything that can't be read is skipped silently and counted in
    the summary; the run never stops on an error. No child processes are
    started, and the output is left in place for retrieval.

.EXAMPLE
    run collector.ps1

    In a Live Response session, after uploading the script to the library.

.EXAMPLE
    .\collector.ps1

    From an elevated Windows PowerShell 5.1 prompt, e.g. for testing.

.NOTES
    Version: $CollectorVersion below (semver); changes are in CHANGELOG.md.
    Requires Windows PowerShell 5.1; no modules, no network access.
    License: 0BSD.

.LINK
    https://github.com/rbqbjyur/defender-live-response-collector
#>

# Every catch {} in this script is deliberate: failures are skipped and the run
# carries on (best effort, no failure log - see the project's design rules).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '',
    Justification = 'Best-effort collection: unreadable items are skipped silently by design.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Internal helpers of a non-interactive Live Response script: no -WhatIf or -Confirm.')]
param()

# ============================== CONFIG ==============================

$CollectorVersion = '1.5.0'

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Resolve the system drive from the environment so the script is not tied to a C:
# install; every artefact path below is taken relative to it (or to a profile).
$sysDrive = $env:SystemDrive                 # e.g. C:
if (-not $sysDrive) { $sysDrive = [System.IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\') }

$hostName = $env:COMPUTERNAME
# UTC, so the name is unambiguous across time zones; trailing 'Z' marks it as UTC.
$runStart  = (Get-Date).ToUniversalTime()
$timestamp = $runStart.ToString('yyyyMMdd_HHmmss') + 'Z'

# Where the output goes, in order of preference: the first folder that can be
# created and holds the zip wins. Only the last folder in each path is ever
# created - a candidate whose parent doesn't exist is skipped. Each run adds its
# own zip, so repeated collections accumulate side by side.
$outDirs = @(
    # The Defender for Endpoint sensor's own Temp (Live Response keeps its script
    # transcripts there too).
    Join-Path $sysDrive 'ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp\Collections'
    # The SYSTEM-only temp folder of newer Windows builds (SYSTEM and Administrators).
    Join-Path $sysDrive 'Windows\SystemTemp\LiveResponseCollector'
    # The running account's temp folder (C:\Windows\Temp for SYSTEM).
    Join-Path ([System.IO.Path]::GetTempPath()) 'LiveResponseCollector'
)
$zipName = "${hostName}_${timestamp}.zip"

# Largest output file. A bigger zip is split in place at the end into standard
# split volumes - <name>.zip.001, .002, ... (a byte split of the one zip: join
# them, or open .001 in 7-Zip) - so each getfile stays well within its 3 GB and
# time limits. A zip that fits is left as it is.
$zipPartSize = 1GB

# Where user profiles live, relative to the system drive: modern first, then
# legacy (XP). Each folder under a root is one profile (see Get-UserProfilePath).
$profileRoots = @('Users', 'Documents and Settings')

# Reasons a gap is normal for the host, shared by the artefact rows' ExpectMissing
# rules so the same reason always reads the same in the summary. Only known OS or
# configuration reasons (off by default, not on this edition/version, not
# configured) - never usage or changeable state, as an artefact that is merely empty or
# absent may have been removed and belongs under Warnings. Add a reason here,
# then refer to it from a row.
$gapReasons = @{
    Server          = 'normal for Windows Server'
    ServerOnly      = 'Windows Server only'
    WindowsVersion  = 'not on this Windows version'
    OffByDefault    = 'off by default'
    NotDomainJoined = 'not joined to on-premises AD'   # PartOfDomain false: Entra-joined or workgroup
}

# Artefacts to collect: one row per summary line. Add an artefact by adding a row.
#   Name     Summary label.
#   Group    1 = drive root (NTFS metafiles), 2 = other system files, 3 = user-specific.
#   System   Path pattern(s) relative to the system drive (or to each drive, see
#            Volumes).
#   Volumes  Which drives the System patterns apply to: 'System' (the default; the
#            system drive only), 'All' (every ready local drive - fixed or
#            removable, any file system) or 'NTFS' (those formatted NTFS, for the
#            NTFS metafiles, which FAT/exFAT have no file equivalent of). For
#            per-volume artefacts such as the Recycle Bin.
#   User     Path pattern(s) relative to each user profile.
#   Logs     Also collect each match's registry transaction logs (<file>.LOG1/.LOG2).
#   Literal  Use the path as-is, without listing it. For NTFS metafiles, which
#            PowerShell can neither see nor open: they stay as 'Not accessible'
#            placeholders so future raw/sensor-based collection slots in cleanly.
#   GetFile  Literal rows only: the Defender sensor's getfile can fetch it, so the
#            command is printed at the end if the read failed.
#   FollowUp Which of the row's locked files get a printed getfile command:
#            'System' (machine-wide paths; the default) or 'User' (user-profile
#            paths). Transaction logs (.LOG*) never do.
#   CountBy  'Folder' counts one unit per folder holding matches (e.g. per browser
#            profile) instead of one per file.
#   Supporting  CountBy rows: file-name patterns of supporting files (journals,
#            ESE logs). A unit counts as collected only if its main file was read;
#            supporting files alone don't count while a main file is present.
#   ExpectMissing  Rules for when "Missing" is normal for this artefact: a list of
#            @{ When = { condition on $hostInfo, see Get-HostInfo }; Why = <a reason
#            from $gapReasons> }. The first rule that holds gives the note "(<Why>)".
#   ExpectPresent  Condition under which this artefact should exist on the host,
#            so a Missing status is unusual and listed under Warnings. Rows without
#            it may be present or not (usage, configuration): Missing is shown, but
#            not warned about.
#   ExpectLocked  Condition under which "not accessible" is normal; the summary
#            then notes "(requires <Requires>)". Unknown host facts never count as
#            expected, so unusual gaps stand out (they go to Warnings).
#   Requires What reading this artefact's locked files would take, shown in that
#            note; defaults to 'NTFS parser' (matches the README's table).
#   RegDirs  Folders named by registry values (Key, Value), each searched with its
#            Pattern. Local drive paths only: shares are skipped (no network access).
# Within a row, patterns run from the modern, standard location to legacy and
# alternative ones: current Windows first, then older Windows forms (Windows 7,
# XP), then the previous install kept in Windows.old after a feature update.
# Legacy forms are part of the same artefact, so they share its summary line.
# Pattern syntax: see Resolve-PathPattern. Collection, progress and summary all
# run in Group order, then by Name alphabetically ignoring non-alphanumerics (e.g.
# the leading '$'). That order is applied at run time, so a row's position in
# this list doesn't matter - but keep it in that order for readability.
$artefacts = @(
    # 1. Drive root: the timeline-relevant NTFS metafiles (the "NTFS Triforce").
    @{ Name = '$LogFile';    Group = 1; Volumes = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; Literal = $true; System = '$LogFile' }   # no getfile route (reported as empty)
    @{ Name = '$MFT';        Group = 1; Volumes = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; Literal = $true; GetFile = $true; System = '$MFT' }
    @{ Name = '$UsnJrnl:$J'; Group = 1; Volumes = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; Literal = $true; System = '$Extend\$UsnJrnl:$J' }   # no getfile route

    # 2. Other system files.
    # Application compatibility / program execution records: Amcache.hve and the
    # Program Compatibility Assistant files (Windows 11 22H2+), then their
    # predecessors - RecentFileCache.bcf (Windows 7) and Syscache.hve (Windows 7 /
    # Server 2008 R2), both replaced by Amcache.hve in Windows 8 - then Windows.old.
    @{ Name = 'Application Compatibility'; Group = 2; ExpectPresent = { <# Amcache, or RecentFileCache on Windows 7 #> $true }; Logs = $true
       ExpectLocked = { <# Syscache.hve is a loaded hive before Windows 8 #> $hostInfo.Build -and $hostInfo.Build -lt 9200 }
       System = @(
           'Windows\AppCompat\Programs\Amcache.hve'
           'Windows\appcompat\pca\*'
           'Windows\AppCompat\Programs\RecentFileCache.bcf'               # Windows 7
           'System Volume Information\Syscache.hve'                       # Windows 7 / Server 2008 R2
           'Windows.old\Windows\AppCompat\Programs\Amcache.hve'
           'Windows.old\Windows\AppCompat\Programs\RecentFileCache.bcf'
       ) }
    # BITS job database (qmgr.db) and its ESE logs: downloads and persistence.
    @{ Name = 'BITS';          Group = 2; ExpectPresent = { $true }; System = 'ProgramData\Microsoft\Network\Downloader\**\*' }
    # Defender text logs (MPLog etc.) and detection history; not the quarantine
    # (file content). Defender event logs are covered by Event Logs.
    @{ Name = 'Defender Logs'; Group = 2; System = @(
        'ProgramData\Microsoft\Windows Defender\Support\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections.log'
        'Windows\Temp\MpCmdRun.log'
        'ProgramData\Microsoft\Microsoft AntiMalware\Support\**\*'      # older Defender / SCEP
        'Windows.old\Windows\Temp\MpCmdRun.log'
    ) }
    @{ Name = 'Event Logs'; Group = 2; ExpectPresent = { $true }; System = @(
        'Windows\System32\winevt\logs\*.evtx'
        'Windows\System32\config\*.evt'                                  # XP
        'Windows.old\Windows\System32\winevt\logs\*.evtx'
    ) }
    @{ Name = 'Firewall Log'; Group = 2; ExpectMissing = @(@{ When = { $true }; Why = $gapReasons.OffByDefault }); System = @(                     # logging off by default
        'Windows\System32\LogFiles\Firewall\pfirewall.*'
        'Windows.old\Windows\System32\LogFiles\Firewall\pfirewall.*'
    ) }
    # Group Policy: local policy and scripts, and the cached copies of domain GPOs
    # (incl. Group Policy Preferences XML such as ScheduledTasks.xml) - persistence
    # and deployment evidence.
    @{ Name = 'Group Policy'; Group = 2; ExpectMissing = @(@{ When = { $hostInfo.DomainJoined -eq $false }; Why = $gapReasons.NotDomainJoined })
       System = @(
           'Windows\System32\GroupPolicy\**\*'
           'ProgramData\Microsoft\Group Policy\History\**\*'
           'Windows.old\Windows\System32\GroupPolicy\*.ini'
           'Windows.old\Windows\System32\GroupPolicy\*.pol'
           'Windows.old\Windows\System32\GroupPolicy\*\Scripts\**\*'
       )
       User = 'AppData\Local\Microsoft\Group Policy\History\**\*' }
    @{ Name = 'Prefetch'; Group = 2; ExpectPresent = { <# on by default on workstations #> $hostInfo.Server -eq $false }; ExpectMissing = @(@{ When = { $hostInfo.Server }; Why = $gapReasons.Server }); System = @(
        'Windows\Prefetch\*.pf'
        'Windows.old\Windows\Prefetch\*.pf'
    ) }
    # Transaction logs hold un-flushed changes, so Registry Explorer / RegRipper /
    # plaso can replay a dirty hive and recover the most recent entries. RegBack
    # copies are usually empty on current Windows, but older snapshots when present.
    @{ Name = 'Registry Hives (system)'; Group = 2; ExpectPresent = { $true }; ExpectLocked = { <# loaded hives #> $true }; Logs = $true; System = @(
        'Windows\System32\config\SAM'
        'Windows\System32\config\SECURITY'
        'Windows\System32\config\SOFTWARE'
        'Windows\System32\config\SYSTEM'
        'Windows\System32\config\RegBack\SAM'
        'Windows\System32\config\RegBack\SECURITY'
        'Windows\System32\config\RegBack\SOFTWARE'
        'Windows\System32\config\RegBack\SYSTEM'
        'Windows\System32\config\RegBack\SYSTEM1'
        'System Volume Information\_restore*\RP*\snapshot\_REGISTRY_*'  # XP restore points
        'Windows.old\Windows\System32\config\SAM'
        'Windows.old\Windows\System32\config\SECURITY'
        'Windows.old\Windows\System32\config\SOFTWARE'
        'Windows.old\Windows\System32\config\SYSTEM'
        'Windows.old\Windows\System32\config\RegBack\SAM'
        'Windows.old\Windows\System32\config\RegBack\SECURITY'
        'Windows.old\Windows\System32\config\RegBack\SOFTWARE'
        'Windows.old\Windows\System32\config\RegBack\SYSTEM'
        'Windows.old\Windows\System32\config\RegBack\SYSTEM1'
    ) }
    # XP restore-point logs (rp.log: each restore point's creation time and description).
    @{ Name = 'Restore Point Logs'; Group = 2; ExpectMissing = @(@{ When = { $hostInfo.Build -ge 6000 }; Why = $gapReasons.WindowsVersion }); System = 'System Volume Information\_restore*\RP*\rp.log' }
    # Configuration Manager (SCCM) client logs; only on ConfigMgr-managed hosts.
    @{ Name = 'SCCM Client Logs';   Group = 2; System = 'Windows\CCM\Logs\*' }
    # XML task definitions, plus PowerShell scheduled jobs (definitions and output).
    @{ Name = 'Scheduled Tasks'; Group = 2; ExpectPresent = { $true }
       System = @(
           'Windows\System32\Tasks\**\*'
           'Windows\SysWOW64\Tasks\**\*'
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\Tasks\*.job'                                         # legacy at.exe / Task Scheduler 1.0
           'Windows\SchedLgU.txt'                                        # legacy Task Scheduler log
           'Windows.old\Windows\System32\Tasks\**\*'
           'Windows.old\Windows\Tasks\*.job'
           'Windows.old\Windows\SchedLgU.txt'
       )
       User = 'AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*' }
    # Device/driver install logs.
    @{ Name = 'SetupAPI'; Group = 2; ExpectPresent = { $true }; System = @(
        'Windows\INF\setupapi*.log'
        'Windows\setupapi.log'                                           # XP
        'Windows.old\Windows\INF\setupapi*.log'
    ) }
    # SRUDB.dat plus its ESE logs and checkpoint, for dirty-database recovery.
    @{ Name = 'SRUM'; Group = 2; ExpectPresent = { <# workstations, Windows 8+ #> $hostInfo.Server -eq $false -and $hostInfo.Build -ge 9200 }; ExpectMissing = @(@{ When = { $hostInfo.Server }; Why = $gapReasons.Server }; @{ When = { $hostInfo.Build -and $hostInfo.Build -lt 9200 }; Why = $gapReasons.WindowsVersion }); ExpectLocked = { <# often held open #> $true }; System = @(
        'Windows\System32\SRU\**\*'
        'Windows.old\Windows\System32\SRU\**\*'
    ) }
    # User Access Logging (Windows Server): clients and users per role, with first
    # and last access times. ESE databases plus their logs, needed to repair them.
    @{ Name = 'User Access Logging (SUM)'; Group = 2; ExpectPresent = { <# on by default on Windows Server #> $hostInfo.Server }; ExpectMissing = @(@{ When = { $hostInfo.Server -eq $false }; Why = $gapReasons.ServerOnly }); ExpectLocked = { <# Current.mdb held by the UAL service #> $true }; System = 'Windows\System32\LogFiles\Sum\**\*' }

    # 3. User-specific. Service accounts (SYSTEM, LocalService, NetworkService) are
    # not user profiles; where they matter, their paths are listed under System.
    # .NET CLR usage logs: one log per process that loaded the CLR (e.g. .NET tooling).
    @{ Name = '.NET CLR Usage Logs'; Group = 3
       System = @(
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
           'Windows.old\Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
       )
       User = 'AppData\Local\Microsoft\CLR_*\**\*.log' }
    # Browser history: one pattern per browser (or channel), counted per user x
    # browser x profile. History DB only (plus its journal). Maintained browsers
    # first, then IE / legacy Edge (WebCache, index.dat) and other discontinued
    # browsers or formats, then XP profile paths.
    @{ Name = 'Browser History'; Group = 3; ExpectLocked = { <# WebCache / running browsers #> $true }; CountBy = 'Folder'
       Supporting = @('*-journal', '*-wal', '*-shm', '*Provider Cache', '*.log', '*.chk', '*.jrs', '*.jfm')
       System = @(
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome Beta\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome Dev\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome SxS\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Chromium\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Supermium\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\WaveBrowser\User Data\*\History*'
       )
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\History*'                                   # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\History*'                              # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\History*'                               # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\History*'                               # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\History*'                                    # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\History*'                               # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\History*'                                # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\History*'                                # Chrome Canary
           'AppData\Local\Chromium\User Data\*\History*'                                         # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\History*'                      # Brave
           'AppData\Local\Vivaldi\User Data\*\History*'                                          # Vivaldi
           'AppData\Roaming\Opera Software\Opera Stable\History*'                                # Opera (single profile)
           'AppData\Roaming\Opera Software\Opera Stable\*\History*'                              # Opera (profiles)
           'AppData\Local\Yandex\YandexBrowser\User Data\*\History*'                             # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\History*'   # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\History*'                                   # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\History*'                                # QQ Browser
           'AppData\Roaming\360se6\User Data\*\360History*'                                      # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\History*'                                      # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'           # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\History*'                                        # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite*'                           # Firefox
           'AppData\Local\Microsoft\Windows\WebCache\*'                                          # IE 10/11, legacy Edge
           'AppData\Local\Microsoft\Windows\History\**\index.dat'                                # IE 9 and earlier
           'AppData\Local\Microsoft\Windows\IEDownloadHistory\**\index.dat'                      # IE 9/10 downloads
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\downloads.sqlite*'                        # Firefox < 26 downloads
           'AppData\Roaming\Opera\Opera\global_history.dat'                                      # Opera <= 12
           'AppData\Roaming\Opera\Opera\typed_history.xml'                                       # Opera <= 12
           'AppData\Roaming\Apple Computer\Safari\History.plist'                                 # Safari for Windows
           'Local Settings\Application Data\Google\Chrome\User Data\*\History*'                  # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\History*'             # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\History*'              # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\History*'              # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\History*'                       # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'   # XP: Prisma Access
           'Application Data\Supermium\User Data\*\History*'                                     # XP: Supermium
           'Application Data\Mozilla\Firefox\Profiles\*\places.sqlite*'                          # XP: Firefox
           'Application Data\Mozilla\Firefox\Profiles\*\downloads.sqlite*'                       # XP: Firefox < 26 downloads
           'Application Data\Opera\Opera\global_history.dat'                                      # XP: Opera <= 12
           'Application Data\Opera\Opera\typed_history.xml'                                       # XP: Opera <= 12
           'Application Data\Apple Computer\Safari\History.plist'                                 # XP: Safari
           'Local Settings\History\History.IE5\**\index.dat'                                     # XP: IE
       ) }
    # File History catalogs (Catalog1/2.edb): metadata about backed-up files, not
    # the files themselves; only present when File History is enabled.
    @{ Name = 'File History Catalogs'; Group = 3; ExpectMissing = @(@{ When = { $true }; Why = $gapReasons.OffByDefault }); User = 'AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb' }
    @{ Name = 'JumpLists'; Group = 3; User = @(
        'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms'
        'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms'
    ) }
    # Shortcuts: recent files, Office recent, desktop and Start Menu (top level only).
    @{ Name = 'LNK'; Group = 3
       System = @(
           'ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk'
           'System Volume Information\_restore*\RP*\*.lnk'               # XP restore points
       )
       User = @(
           'AppData\Roaming\Microsoft\Windows\Recent\*.lnk'
           'AppData\Roaming\Microsoft\Office\Recent\**\*'
           'Desktop\*.lnk'
           'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk'
           'Recent\**\*'                                                 # XP
       ) }
    # OneDrive: settings (file lists, sync database) and client activity logs (.odl,
    # .odlgz, .odlsent, .aodl, .loggz) with the .keystore needed to decode their
    # obfuscated strings, then the older SkyDrive and Windows 8.1
    # built-in client locations. Not the ETW traces (.etlgz, bulk), the client's
    # own program files or the synced files.
    @{ Name = 'OneDrive Metadata'; Group = 3; ExpectMissing = @(@{ When = { $hostInfo.Server }; Why = $gapReasons.Server }); User = @(
        'AppData\Local\Microsoft\OneDrive\settings\**\*'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.odl*'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.aodl'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.loggz'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.keystore'
        'AppData\Local\Microsoft\SkyDrive\logs\**\*'                       # SkyDrive
        'AppData\Local\Microsoft\Windows\OneDrive\logs\**\*'              # Windows 8.1
    ) }
    # PSReadLine history for every host (console, VS Code, ...), including SYSTEM's.
    @{ Name = 'PowerShell History'; Group = 3
       System = @(
           'Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
           'Windows\SysWOW64\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
       )
       User = 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt' }
    # Transcripts go to the user's Documents - possibly moved into OneDrive (Known
    # Folder Move) - directly or, with policy transcription, in date subfolders.
    # Policy can also redirect them to a central folder (Windows PowerShell and PS 7);
    # System lists other places they are commonly found (SYSTEM runs, C:\PSTranscript).
    @{ Name = 'PowerShell Transcripts'; Group = 3
       System = @(
           'Windows\System32\*\PowerShell_transcript.*.txt'
           'Windows\SysWOW64\*\PowerShell_transcript.*.txt'
           'PSTranscript\20*\PowerShell_transcript.*.txt'
       )
       User = @(
           'Documents\PowerShell_transcript.*.txt'
           'Documents\20*\PowerShell_transcript.*.txt'
           'OneDrive*\Documents\PowerShell_transcript.*.txt'
           'OneDrive*\Documents\20*\PowerShell_transcript.*.txt'
       )
       RegDirs = @(
           @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Value = 'OutputDirectory'; Pattern = '**\PowerShell_transcript.*.txt' }
           @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription';     Value = 'OutputDirectory'; Pattern = '**\PowerShell_transcript.*.txt' }
       ) }
    # Recycle Bin metadata only ($I records; INFO2 on XP), no deleted-file content.
    @{ Name = 'Recycle Bin'; Group = 3; Volumes = 'All'; System = @(
        '$Recycle.Bin\*\$I*'
        '$Recycle.Bin\$I*'                                               # FAT/exFAT: no per-SID folders
        'RECYCLE*\**\INFO2'                                              # XP (RECYCLER / RECYCLED)
    ) }
    # User hives, plus the service accounts' hives: DEFAULT is the SYSTEM account's
    # (HKU\.DEFAULT / S-1-5-18), the others LocalService and NetworkService.
    @{ Name = 'Registry Hives (user)'; Group = 3; ExpectPresent = { $true }; ExpectLocked = { <# logged-on users' and service hives #> $true }; Logs = $true; FollowUp = 'User'   # users' hives, not the built-in service accounts'
       System = @(
           'Windows\System32\config\DEFAULT'
           'Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
           'Windows.old\Windows\System32\config\DEFAULT'
           'Windows.old\Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows.old\Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows.old\Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
       )
       User = @(
           'NTUSER.DAT'
           'AppData\Local\Microsoft\Windows\UsrClass.dat'
       ) }
    @{ Name = 'Startup Folders'; Group = 3
       System = 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\**\*'
       User   = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\**\*' }
    # Teams client logs only (sign-ins, calls, meetings); no message stores or caches.
    # New Teams (work/school), the Windows 11 built-in Teams, then classic Teams.
    @{ Name = 'Teams Logs'; Group = 3; User = @(
        'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*'
        'AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*'
        'AppData\Roaming\Microsoft\Teams\logs.txt'                              # classic Teams
    ) }
    # WER: only the .wer report metadata, never the crash dumps (bulk binary content).
    @{ Name = 'WER'; Group = 3
       System = 'ProgramData\Microsoft\Windows\WER\**\*.wer'
       User   = 'AppData\Local\Microsoft\Windows\WER\**\*.wer' }
    # Windows Timeline (Windows 10; dropped in Windows 11).
    @{ Name = 'Windows Timeline'; Group = 3; ExpectMissing = @(@{ When = { $hostInfo.Server }; Why = $gapReasons.Server }; @{ When = { $hostInfo.Build -ge 22000 }; Why = $gapReasons.WindowsVersion }); User = 'AppData\Local\ConnectedDevicesPlatform\**\ActivitiesCache.db*' }
)

# ============================= FUNCTIONS =============================

# --- Filesystem enumeration (low-level first) ---

# True if a folder (a DirectoryInfo from Get-Item or Get-ChildItem) is a
# junction or symbolic link. Links are never followed: on Windows they only
# duplicate real folders ("All Users", "Default User", the XP compatibility
# links such as "Local Settings" or "Application Data" inside profiles).
# PowerShell 5.1 leaves LinkType empty for a link that denies listing to
# everyone, as Windows' own compatibility links do, so a reparse point whose
# type can't be read and whose listing is denied counts as a link too. Other
# reparse points that can be listed (e.g. OneDrive cloud folders) are ordinary
# folders.
function Test-LinkItem {
    param($Item)
    $type = $Item.LinkType
    if ($type -eq 'Junction' -or $type -eq 'SymbolicLink') { return $true }
    if ($type -or -not ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $false }
    $entries = $null
    try {
        $entries = [System.IO.Directory]::EnumerateFileSystemEntries($Item.FullName).GetEnumerator()
        $null = $entries.MoveNext()
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $true
    } catch {
        return $false
    } finally {
        if ($entries) { try { $entries.Dispose() } catch {} }
    }
}

# True if Path is a junction or symbolic link (see Test-LinkItem). Cached, as the
# same folders are checked for many patterns.
function Test-FolderLink {
    param([string]$Path)
    if ($script:linkCache.ContainsKey($Path)) { return $script:linkCache[$Path] }
    $isLink = $false
    try {
        if (Test-NormalisedName -Path $Path) {
            # Get-Item would return the folder without the trailing dot or space.
            $item = New-Object System.IO.DirectoryInfo ('\\?\' + $Path)
            if ($item.Exists) { $isLink = Test-LinkItem -Item $item }
        } else {
            $isLink = Test-LinkItem -Item (Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
        }
    } catch {}
    $script:linkCache[$Path] = $isLink
    return $isLink
}

# An error's message on one line (some end with a line break), for the console
# and the log.
function Get-OneLineMessage {
    param($ErrorRecord)
    return (($ErrorRecord.Exception.Message -replace '\s*[\r\n]+\s*', ' ').Trim())
}

# Record a folder that exists but could not be listed (access denied, an I/O
# error), so what it holds counts as not accessible rather than missing. A
# folder that doesn't exist is no failure: that is what Missing means. Each
# failure goes into $script:listingFailures (Path, Reason), where Add-Artefact
# picks up the ones its patterns met.
function Add-ListingFailure {
    param([string]$Path, $ErrorRecords)
    foreach ($record in @($ErrorRecords)) {
        if (-not $record) { continue }
        if ($record.CategoryInfo.Category -eq 'ObjectNotFound') { continue }
        $reason = if ($record.CategoryInfo.Category -eq 'PermissionDenied') { 'access denied' } else { Get-OneLineMessage -ErrorRecord $record }
        $script:listingFailures.Add([pscustomobject]@{ Path = $Path; Reason = $reason })
        return
    }
}

# True if a name in Path ends with a dot or a space (e.g. 'dir.' or 'space ').
# PowerShell's listing normalises such a path to the name without them, so it
# lists another folder (or none): these folders are listed with .NET through
# \\?\ instead (Get-ExtendedChildPath).
function Test-NormalisedName {
    param([string]$Path)
    return ($Path -match '[. ](\\|$)')
}

# Full paths of the files (or, with -Directory, the subfolders other than links)
# in Path matching Filter, listed with .NET through \\?\, for a folder whose
# name PowerShell would normalise (Test-NormalisedName). A folder that can't be
# listed is recorded (Add-ListingFailure); where .NET refuses \\?\ (Framework
# before 4.6.2) the reason says the name can't be listed here.
function Get-ExtendedChildPath {
    param([string]$Path, [string]$Filter = '*', [switch]$Directory)
    try {
        $folder = New-Object System.IO.DirectoryInfo ('\\?\' + $Path)
        $items  = if ($Directory) { $folder.EnumerateDirectories($Filter) } else { $folder.EnumerateFiles($Filter) }
        foreach ($item in $items) {
            if ($Directory -and (Test-LinkItem -Item $item)) { continue }
            $item.FullName.Substring(4)   # without the \\?\ prefix
        }
    } catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        if ($inner -is [System.IO.DirectoryNotFoundException]) { return }
        $reason = if ($inner -is [System.NotSupportedException] -or $inner -is [System.ArgumentException]) {
            'its name ends in a dot or a space, which this .NET version cannot list'
        } elseif ($inner -is [System.UnauthorizedAccessException]) {
            'access denied'
        } else {
            Get-OneLineMessage -ErrorRecord $_
        }
        $script:listingFailures.Add([pscustomobject]@{ Path = $Path; Reason = $reason })
    }
}

# Full paths of the subfolders of Path matching Filter, skipping links (see
# Test-FolderLink). A folder that can't be listed is recorded (Add-ListingFailure).
function Get-ChildDirectory {
    param([string]$Path, [string]$Filter = '*')
    if (Test-NormalisedName -Path $Path) { return Get-ExtendedChildPath -Path $Path -Filter $Filter -Directory }
    $listingErrors = $null
    try {
        Get-ChildItem -LiteralPath $Path -Filter $Filter -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable listingErrors |
            Where-Object { -not (Test-LinkItem -Item $_) } |
            ForEach-Object { $_.FullName }
    } catch { $listingErrors = @($_) }
    Add-ListingFailure -Path $Path -ErrorRecords $listingErrors
}

# A folder path safe to list: a bare drive ('C:') means that drive's current
# directory to PowerShell, so it becomes the drive root ('C:\').
function Get-ListPath {
    param([string]$Path)
    if ($Path -match '^[A-Za-z]:$') { return $Path + '\' }
    return $Path
}

# A folder path with each folder name in its on-disk case (e.g. a pattern's
# '$Recycle.Bin' is '$RECYCLE.BIN' on a FAT drive), so zip entries keep the
# original paths. A name that can't be found is kept as given. Cached per path,
# so each folder is looked up once. Silent on failure: it only decides the case,
# and the listings that follow record a folder that can't be read.
function Get-DiskCasePath {
    param([string]$Path)
    $Path = $Path.TrimEnd('\')
    if ($script:caseCache.ContainsKey($Path)) { return $script:caseCache[$Path] }
    $result = $Path
    $cut = $Path.LastIndexOf('\')
    if ($cut -gt 0) {
        $parent = Get-DiskCasePath -Path $Path.Substring(0, $cut)
        $name   = $Path.Substring($cut + 1)
        $result = $parent + '\' + $name
        try {
            $match = Get-ChildItem -LiteralPath (Get-ListPath -Path $parent) -Filter $name -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $name } | Select-Object -First 1   # -eq: not a short-name (8.3) match
            if ($match) { $result = $parent + '\' + $match.Name }
        } catch {}
    }
    $script:caseCache[$Path] = $result
    return $result
}

# A folder and every folder below it, never following links (see Test-FolderLink).
function Get-DirectoryTree {
    param([string]$Path)
    $Path
    foreach ($d in (Get-ChildDirectory -Path (Get-ListPath -Path $Path))) { Get-DirectoryTree -Path $d }
}

# Expand a path pattern, relative to Root, into full file paths (none if absent).
# Segments are separated by '\'. The last segment is a file-name filter (wildcards
# allowed; a plain name matches just that file). A folder segment containing * or
# ? matches subfolders; '**' as the last folder segment means "anywhere below
# here" (recursive). Links are never followed (see Test-FolderLink). A folder
# that can't be listed is recorded (Add-ListingFailure). -Literal returns
# Root\Pattern unchecked, without listing it.
function Resolve-PathPattern {
    param([string]$Root, [string]$Pattern, [switch]$Literal)

    $base = $Root.TrimEnd('\')
    if ($Literal) { return ($base + '\' + $Pattern) }
    $base = Get-DiskCasePath -Path $base

    $segments = $Pattern -split '\\'
    $dirs     = @($base)
    $recurse  = $false
    foreach ($seg in ($segments | Select-Object -SkipLast 1)) {
        if     ($seg -eq '**')      { $recurse = $true }
        elseif ($seg -match '[*?]') { $dirs = @(foreach ($d in $dirs) { Get-ChildDirectory -Path (Get-ListPath -Path $d) -Filter $seg }) }
        else {
            $dirs = @(foreach ($d in $dirs) {
                $next = Get-DiskCasePath -Path ($d + '\' + $seg)
                if (-not (Test-FolderLink -Path $next)) { $next }
            })
        }
    }
    if ($recurse) { $dirs = @(foreach ($d in $dirs) { Get-DirectoryTree -Path $d }) }
    foreach ($d in $dirs) {
        if (Test-NormalisedName -Path $d) {
            Get-ExtendedChildPath -Path $d -Filter $segments[-1]
            continue
        }
        $listingErrors = $null
        try {
            Get-ChildItem -LiteralPath (Get-ListPath -Path $d) -Filter $segments[-1] -File -Force -ErrorAction SilentlyContinue -ErrorVariable listingErrors |
                ForEach-Object { $_.FullName }
        } catch { $listingErrors = @($_) }
        Add-ListingFailure -Path $d -ErrorRecords $listingErrors
    }
}

# --- Registry ---

# A registry value with environment variables expanded, or $null if the key or
# value is absent or unreadable.
function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $value = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($value) { [Environment]::ExpandEnvironmentVariables($value) }
    } catch {}
}

# Facts about the host for the OS line and the summary notes. The
# name and type come from CIM (Win32_OperatingSystem's caption is right for
# Windows 11) and the release (e.g. 23H2) from the registry; if CIM fails, the
# registry alone, correcting its ProductName, which still says "Windows 10" on
# Windows 11. Decisions use the build number and the server/workstation type,
# never the name, which is localised. A fact that can't be determined stays
# $null, and conditions treat $null as "not expected".
function Get-HostInfo {
    $cv   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $info = @{ Caption = $null; Version = $null; Build = $null
               Server = $null; DomainJoined = $null }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $info.Caption = $os.Caption.Trim()
        $info.Build   = [int]$os.BuildNumber
        $info.Server  = ($os.ProductType -ne 1)   # 1 = workstation, 2 = DC, 3 = server
    } catch {}
    try { $info.DomainJoined = [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
    try {
        $reg = Get-ItemProperty -LiteralPath $cv -ErrorAction Stop
        $info.Version = if ($reg.DisplayVersion) { $reg.DisplayVersion } else { $reg.ReleaseId }
        if (-not $info.Build)  { $info.Build = [int]$reg.CurrentBuild }
        if ($null -eq $info.Server -and $reg.InstallationType) { $info.Server = ($reg.InstallationType -notlike 'Client*') }
        if (-not $info.Caption -and $reg.ProductName) {
            $info.Caption = $reg.ProductName
            if ($info.Build -ge 22000) { $info.Caption = $info.Caption -replace 'Windows 10', 'Windows 11' }
        }
    } catch {}
    $info
}

# True if a row's expectation condition (a scriptblock using $hostInfo) holds.
# Missing or failing conditions count as "not expected".
function Test-Expectation {
    param($Condition)
    if (-not $Condition) { return $false }
    try { return [bool](& $Condition) } catch { return $false }
}

# The Why of the first ExpectMissing rule whose When holds, or $null if none does.
function Get-ExpectedReason {
    param($Rules)
    foreach ($r in @($Rules)) {
        if ($r -and (Test-Expectation -Condition $r.When)) { return $r.Why }
    }
    return $null
}

# Drive roots ('C:', 'D:') for a row's Volumes (see the artefact table): the
# system drive only by default, every ready local drive ('All'), or those
# formatted NTFS ('NTFS'). The system drive always comes first.
function Get-VolumeRoot {
    param([string]$Kind = 'System')
    if ($Kind -ne 'All' -and $Kind -ne 'NTFS') { return $sysDrive }
    foreach ($v in $script:volumes) {
        if ($Kind -eq 'All' -or $v.Format -eq 'NTFS') { $v.Root }
    }
}

# User profiles: every folder under each profile root, in $profileRoots order
# (deliberately not the registry's ProfileList). A root that is itself a link
# (Documents and Settings -> Users on current Windows) is resolved to its target,
# and only if that can be read and stays on the system drive, so no profile is
# listed twice.
# Links inside a root ("All Users", "Default User") are skipped by
# Get-ChildDirectory. Service accounts are not profiles: rows list their paths.
function Get-UserProfilePath {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $profileRoots) {
        try {
            $root = (Join-Path $sysDrive $r)
            $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
            if (Test-LinkItem -Item $item) {
                # A link whose target can't be read (Windows' compatibility link
                # behind its deny-list) or that leaves the drive is skipped.
                $target = @($item.Target)[0]
                if (-not $target -or $target -notlike "$sysDrive\*") { continue }
                $root = $target
            }
            if ($seen.Add($root.TrimEnd('\'))) { Get-ChildDirectory -Path $root }
        } catch {}
    }
}

# Counting unit for CountBy 'Folder': the folder a match sits in at the pattern's
# own depth (its folder segments before any '**'), counted from Root. E.g. the
# browser profile folder for 'User Data\*\History*', or the History folder for
# 'History\**\index.dat', however deep the file itself is.
function Get-PatternUnit {
    param([string]$Root, [string]$Pattern, [string]$Path)
    $folders = @($Pattern -split '\\' | Select-Object -SkipLast 1)
    $depth   = [array]::IndexOf($folders, '**')
    if ($depth -lt 0) { $depth = $folders.Count }
    $base = $Root.TrimEnd('\')
    if ($depth -eq 0) { return $base }
    $parts = @($Path.Substring($base.Length + 1) -split '\\')
    return $base + '\' + (($parts | Select-Object -First $depth) -join '\')
}

# --- Zip ---

# True if an error (or any exception inside it) is "disk full" (ERROR_DISK_FULL,
# ERROR_HANDLE_DISK_FULL), i.e. the zip can't grow - as opposed to a locked file.
function Test-DiskFull {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e) {
        if (($e.HResult -band 0xFFFF) -in 39, 112) { return $true }
        $e = $e.InnerException
    }
    return $false
}

# Copy one file straight into the zip, opening it with shared access so files
# held open by other processes (e.g. Edge History) can usually still be read.
# Returns $true (copied), $false (found but unreadable) or $null (already in zip).
# Two side effects, both recorded for the end of the run:
# - if the system drive fills up, it sets $script:diskFull so collection stops;
# - if the bytes copied differ from the source's size when it was opened (a live
#   file that changed, or a read that failed part-way, which leaves an
#   incomplete entry in the zip, as Create mode can't remove one), it adds the
#   file to $script:sizeDifferences (Path, Copied, SizeWhenOpened, ReadError).
function Add-FileToZip {
    param($Zip, [string]$Path)

    # C:\Users\bob\file.lnk -> C/Users/bob/file.lnk
    $entryName = ($Path -replace '^([A-Za-z]):', '$1') -replace '\\', '/'
    if (-not $script:added.Add($entryName)) { return $null }

    $src = $null
    $dst = $null
    $entryCreated   = $false
    $copied         = [long]0
    $sizeWhenOpened = $null
    # Opened through \\?\ always: .NET normalises a plain path, dropping a trailing
    # dot or space (report. would open report, another file) and limiting it to
    # 260 characters.
    $openPath = '\\?\' + $Path
    try {
        try {
            $src = [System.IO.File]::Open($openPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        } catch [System.NotSupportedException], [System.ArgumentException] {
            # .NET Framework before 4.6.2 refuses \\?\ paths. A plain path is safe
            # only if no name in it ends with a dot or a space; otherwise it would
            # open another file, so this one counts as not accessible.
            if (Test-NormalisedName -Path $Path) { throw }
            $openPath = $Path
            $src = [System.IO.File]::Open($openPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        }
        try { $sizeWhenOpened = $src.Length } catch {}
        $entry = $Zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Fastest)
        $entryCreated = $true
        # UTC: zip stores a zone-less date/time, so keep it in the always-UTC convention.
        try { $entry.LastWriteTime = [System.IO.File]::GetLastWriteTimeUtc($openPath) } catch {}
        $dst = $entry.Open()
        # Copied by hand rather than with CopyTo, to count the bytes.
        while (($read = $src.Read($script:copyBuffer, 0, $script:copyBuffer.Length)) -gt 0) {
            $dst.Write($script:copyBuffer, 0, $read)
            $copied += $read
        }
        $script:count++
        if ($null -ne $sizeWhenOpened -and $copied -ne $sizeWhenOpened) {
            $script:sizeDifferences.Add([pscustomobject]@{ Path = $Path; Copied = $copied; SizeWhenOpened = $sizeWhenOpened; ReadError = $null })
        }
        return $true
    } catch {
        if (Test-DiskFull -ErrorRecord $_) {
            $script:diskFull = $true
        } elseif ($entryCreated) {
            # The entry stays in the zip, incomplete: say so.
            $script:sizeDifferences.Add([pscustomobject]@{ Path = $Path; Copied = $copied; SizeWhenOpened = $sizeWhenOpened; ReadError = (Get-OneLineMessage -ErrorRecord $_) })
        }
        return $false   # locked / access denied, a read that failed part-way (or disk full: see above)
    } finally {
        # Closing can fail too (e.g. disk full while flushing the entry): never let it escape.
        if ($dst) { try { $dst.Dispose() } catch {} }
        if ($src) { try { $src.Dispose() } catch {} }
    }
}

# --- Output and run log ---

# Print a line and keep it in the run log beside the zip. Until the output folder
# is known the lines are buffered, then written out in one go (see MAIN). A log
# that can't be written never affects the run.
function Write-Line {
    param([string]$Text = '')
    Write-Output $Text
    if ($script:logPath) {
        try { [System.IO.File]::AppendAllText($script:logPath, $Text + "`r`n", $script:logEncoding) } catch {}
    } else {
        $script:logLines.Add($Text)
    }
}

# --- Progress, collection, summary ---

# Rough progress: print "[n/total] Collecting <artefact>" as each artefact starts,
# so an operator sees movement on a slow/busy host. No counts - just a heartbeat.
function Write-Stage {
    param([string]$Name)
    $script:stageNum++
    Write-Line -Text ("[{0:D2}/{1}] Collecting {2}" -f $script:stageNum, $script:stageTotal, $Name)
}

# Tally -> status string:
#   no candidates -> Missing; none read -> Not accessible; else "N collected[, M not accessible]"
function Format-Status {
    param([int]$Candidates, [int]$Collected, [int]$Failed)
    if     ($Candidates -eq 0) { 'Missing' }
    elseif ($Collected -eq 0)  { 'Not accessible' }
    elseif ($Failed -gt 0)     { "$Collected collected, $Failed not accessible" }
    else                       { "$Collected collected" }
}

# Collect one artefact row: resolve its patterns (system drive, then each user
# profile), stream every match into the zip as it is found, and set the row's one
# summary line. Each location is isolated: a failure skips only that location.
function Add-Artefact {
    param($Zip, [hashtable]$Artefact, [string[]]$UserProfile)

    Write-Stage -Name $Artefact.Name
    $tally = @{ Candidates = 0; Collected = 0; Failed = 0 }
    $units = @{}   # CountBy 'Folder': folder -> $true once any file in it was read

    $sources = @()
    foreach ($root in (Get-VolumeRoot -Kind $Artefact.Volumes)) {
        foreach ($p in $Artefact.System) { $sources += @{ Root = $root; Scope = 'System'; Pattern = $p } }
    }
    foreach ($rd in $Artefact.RegDirs) {
        $dir = Get-RegistryValue -Path $rd.Key -Name $rd.Value
        # Absolute local drive paths only (any letter): skips shares and relative paths.
        # Also skips the root of the system drive ($sysDrive, from %SystemDrive%), as a
        # recursive search would walk the whole drive; another drive's root is fine -
        # small partitions are sometimes set aside for transcripts.
        if ($dir -match '^[A-Za-z]:\\' -and $dir.TrimEnd('\') -ne $sysDrive) {
            $sources += @{ Root = $dir; Scope = 'System'; Pattern = $rd.Pattern }
        }
    }
    foreach ($u in $UserProfile) {
        foreach ($p in $Artefact.User) { $sources += @{ Root = $u; Scope = 'User'; Pattern = $p } }
    }

    # Folders this row's patterns couldn't list (see Add-ListingFailure), and
    # this row's copies that failed part-way: both always make the row an
    # unusual gap, even where a note would otherwise explain a lock.
    $unlistedFolders = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $partialCopiesBefore = @($script:sizeDifferences | Where-Object { $_.ReadError }).Count

    :sources foreach ($s in $sources) {
        try {
            $patterns = @($s.Pattern)
            if ($Artefact.Logs) { $patterns += $s.Pattern + '.LOG*' }   # hive first, then its logs
            foreach ($pattern in $patterns) {
                $failuresBefore = $script:listingFailures.Count
                $matchedFiles = @(Resolve-PathPattern -Root $s.Root -Pattern $pattern -Literal:([bool]$Artefact.Literal))
                for ($i = $failuresBefore; $i -lt $script:listingFailures.Count; $i++) {
                    [void]$unlistedFolders.Add($script:listingFailures[$i].Path)
                }
                foreach ($file in $matchedFiles) {
                    $ok = Add-FileToZip -Zip $Zip -Path $file
                    if ($script:diskFull) { $script:diskFullAt = $Artefact.Name; break sources }   # zip can't grow: stop
                    if ($null -eq $ok) { continue }   # already collected
                    if (-not $ok) {
                        $script:failed.Add([pscustomobject]@{
                            Path = $file; Scope = $s.Scope
                            Literal = [bool]$Artefact.Literal; GetFile = [bool]$Artefact.GetFile
                            FollowUp = $(if ($Artefact.FollowUp) { $Artefact.FollowUp } else { 'System' })
                        })
                    }
                    if ($Artefact.CountBy -eq 'Folder') {
                        $unit = Get-PatternUnit -Root $s.Root -Pattern $pattern -Path $file
                        if (-not $units.ContainsKey($unit)) { $units[$unit] = @{ Main = $null; Any = $false } }
                        $leaf = Split-Path -Path $file -Leaf
                        if (@($Artefact.Supporting | Where-Object { $leaf -like $_ }).Count -gt 0) {
                            $units[$unit].Any = $units[$unit].Any -or $ok
                        } else {
                            $units[$unit].Main = ($units[$unit].Main -eq $true) -or $ok
                        }
                    } else {
                        $tally.Candidates++
                        if ($ok) { $tally.Collected++ } else { $tally.Failed++ }
                    }
                }
            }
        } catch {}
    }

    if ($Artefact.CountBy -eq 'Folder') {
        # Collected if the main file was read; supporting files only decide when a
        # unit has no main file at all (e.g. a lone journal).
        $tally.Candidates = $units.Count
        $tally.Collected  = @($units.Values | Where-Object { $_.Main -eq $true -or ($null -eq $_.Main -and $_.Any) }).Count
        $tally.Failed     = $tally.Candidates - $tally.Collected
    }
    # Each folder that couldn't be listed counts as one item not accessible.
    $tally.Candidates += $unlistedFolders.Count
    $tally.Failed     += $unlistedFolders.Count
    $partialCopies = @($script:sizeDifferences | Where-Object { $_.ReadError }).Count - $partialCopiesBefore
    $status = Format-Status @tally
    $script:summary[$Artefact.Name] = $status
    $reason = if ($status -eq 'Missing') { Get-ExpectedReason -Rules $Artefact.ExpectMissing } else { $null }
    if ($reason) {
        $script:notes[$Artefact.Name] = "($reason)"
    } elseif ($status -like '*not accessible*' -and (Test-Expectation -Condition $Artefact.ExpectLocked)) {
        $requires = if ($Artefact.Requires) { $Artefact.Requires } else { 'NTFS parser' }
        $script:notes[$Artefact.Name] = "(requires $requires)"
    }
    # Unusual gaps for the Warnings section: an unexplained lock, or Missing where
    # the artefact should exist on this host. Missing with no expectation either
    # way (usage, configuration) is shown in the summary but not warned about.
    if ($unlistedFolders.Count -gt 0 -or $partialCopies -gt 0 -or
        (-not $script:notes.ContainsKey($Artefact.Name) -and
         (($status -like '*not accessible*') -or
          ($status -eq 'Missing' -and (Test-Expectation -Condition $Artefact.ExpectPresent))))) {
        [void]$script:unusual.Add($Artefact.Name)
    }
}

# --- Splitting ---

# Split a zip larger than PartSize, in place, into standard split volumes
# <zip>.001, .002, ... and return their paths (just the zip if it fits). Works
# from the end so the extra space needed is one part, never a second copy: the
# last part is copied out and cut off the zip, and so on, and what is left
# (the first part) is renamed to .001. On failure it throws, with
# $script:splitDamaged set once the zip has been cut (it is then unusable).
function Split-ZipFile {
    param([string]$Path, [long]$PartSize)
    $length = (Get-Item -LiteralPath $Path -Force).Length
    if ($length -le $PartSize) { return $Path }
    $count = [int][math]::Ceiling($length / $PartSize)
    $parts = @(for ($i = 1; $i -le $count; $i++) { '{0}.{1:D3}' -f $Path, $i })
    $zipStream = $null
    try {
        $zipStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        for ($i = $count; $i -ge 2; $i--) {
            $start = [long]($i - 1) * $PartSize
            $out = $null
            try {
                $out = [System.IO.File]::Open($parts[$i - 1], [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $zipStream.Position = $start
                $zipStream.CopyTo($out, 1MB)
                $out.Flush()
            } finally {
                if ($out) { try { $out.Dispose() } catch {} }
            }
            $script:splitDamaged = $true
            $zipStream.SetLength($start)
        }
    } finally {
        if ($zipStream) { try { $zipStream.Dispose() } catch {} }
    }
    [System.IO.File]::Move($Path, $parts[0])
    return $parts
}

# Remove output files; failures are ignored (the caller reports what is left).
function Remove-OutputFile {
    param([string[]]$Path)
    foreach ($p in $Path) { try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop } catch {} }
}

# --- Hashing ---

# The SHA-256 of a file as lower-case hex (as sha256sum writes it), computed in
# this process. Throws if the file can't be read.
function Get-FileSha256 {
    param([string]$Path)
    $stream = $null
    $hasher = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $digest = $hasher.ComputeHash($stream)
        return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        if ($hasher) { try { $hasher.Dispose() } catch {} }
        if ($stream) { try { $stream.Dispose() } catch {} }
    }
}

# --- Warnings ---

# Collect a warning for the Warnings section: anything the analyst should be wary
# of. Shown early (if known by then) and again with the end-of-run summary.
function Add-CollectorWarning {
    param([string]$Message)
    $script:warnings.Add($Message)
}

# Print the Warnings section: one line per warning, or "none" when -ShowNone.
function Write-CollectorWarning {
    param([switch]$ShowNone)
    if ($script:warnings.Count -eq 0) {
        if ($ShowNone) { Write-Line -Text 'Warnings: none' }
        return
    }
    Write-Line -Text 'Warnings:'
    foreach ($w in $script:warnings) { Write-Line -Text "  - $w" }
}

# =============================== MAIN ===============================

# Run log state (Write-Line): buffered until the output folder is known.
$script:logLines    = New-Object 'System.Collections.Generic.List[string]'
$script:logPath     = $null
$script:logEncoding = New-Object System.Text.UTF8Encoding($false)

# Banner first, before any status, so the version is the first thing printed.
# The blank line above it is console-only, to set it off from Live Response's
# transcript line; the run log starts with the banner.
Write-Output ''
Write-Line -Text "Live Response collector v$CollectorVersion"
Write-Line -Text ''
Write-Line -Text ("Host {0}, started {1}" -f $hostName, $runStart.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
$hostInfo = Get-HostInfo
$osName   = @($hostInfo.Caption, $hostInfo.Version | Where-Object { $_ }) -join ' '
if ($osName) { Write-Line -Text "OS $osName" }

# Script-scope state.
$script:added   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:count   = 0                                                    # total files written to the zip
$script:failed  = New-Object 'System.Collections.Generic.List[object]' # found but unreadable: Path, Scope, Literal, GetFile
$script:linkCache = @{}                                                # folder path -> is a junction/symlink (Test-FolderLink)
$script:caseCache = @{}                                                # folder path -> on-disk case (Get-DiskCasePath)
$script:listingFailures = New-Object 'System.Collections.Generic.List[object]'  # folders that exist but couldn't be listed: Path, Reason
$script:sizeDifferences = New-Object 'System.Collections.Generic.List[object]'  # copies whose bytes differ from the source's size when opened
$script:copyBuffer = New-Object byte[] (1MB)                                    # Add-FileToZip's copy buffer, allocated once
$script:diskFull  = $false                                             # set when the system drive fills up (Test-DiskFull)
$script:diskFullAt = ''                                                # artefact being collected when it did
$script:summary = [ordered]@{}                                         # artefact name -> status, in display order
$script:notes   = @{}                                                  # artefact name -> summary note for a gap that's normal here
$script:warnings = New-Object 'System.Collections.Generic.List[string]'     # Warnings section, in the order found
$script:unusual  = New-Object 'System.Collections.Generic.HashSet[string]'  # artefacts whose gap is worth a closer look

# Fix the run order once: group, then name ignoring non-alphanumerics. Collection,
# progress numbering and the summary all follow it. Lines start as 'Missing'.
$artefacts = @($artefacts | Sort-Object -Property { $_.Group }, { $_.Name -replace '[^A-Za-z0-9]', '' })
foreach ($a in $artefacts) { $script:summary[$a.Name] = 'Missing' }
$script:stageTotal = $artefacts.Count
$script:stageNum   = 0

# Local drives, for per-volume artefacts (Volumes = 'All' / 'NTFS'): every ready
# drive except network ones - fixed and removable alike - with its file system,
# the system drive first. Best effort: drives that aren't ready (no media,
# locked) are simply skipped.
$script:volumes = New-Object 'System.Collections.Generic.List[object]'
try {
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        try {
            if ($d.DriveType -eq [System.IO.DriveType]::Network -or
                $d.DriveType -eq [System.IO.DriveType]::NoRootDirectory) { continue }
            $root = $d.Name.TrimEnd('\')
            if ($d.IsReady) { $script:volumes.Add([pscustomobject]@{ Root = $root; Format = $d.DriveFormat }) }
        } catch {}
    }
} catch {}
if (-not ($script:volumes | Where-Object { $_.Root -eq $sysDrive })) {
    $script:volumes.Insert(0, [pscustomobject]@{ Root = $sysDrive; Format = 'NTFS' })   # never lose the system drive
}
$script:volumes = @($script:volumes | Sort-Object -Property { $_.Root -ne $sysDrive }, Root)
# The drives searched, so a skipped drive can't pass for one with nothing on it.
Write-Line -Text ('Drives ' + (@($script:volumes | ForEach-Object { '{0} ({1})' -f $_.Root, $_.Format }) -join ', '))

try {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
} catch {}

# Open the zip in the first output folder that works. A folder created here but
# then unusable (e.g. the sensor refuses writes) is removed again if still empty.
$zip = $null; $outDir = $null; $zipPath = $null
foreach ($candidate in $outDirs) {
    if (-not (Test-Path -LiteralPath (Split-Path -Path $candidate -Parent))) { continue }
    $existed = Test-Path -LiteralPath $candidate
    try {
        $null    = New-Item -ItemType Directory -Path $candidate -Force -ErrorAction Stop
        $zipPath = Join-Path $candidate $zipName
        $zip     = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
        $outDir  = $candidate
        break
    } catch {
        $zip = $null
        if (-not $existed) { try { Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop } catch {} }
    }
}
if (-not $zip) {
    Write-Line -Text ('Could not create the output zip in: ' + ($outDirs -join '; '))
    return
}

# Run log beside the zip, same name with .log: write what's been printed so far,
# then Write-Line appends.
$logPath = [System.IO.Path]::ChangeExtension($zipPath, '.log')
try {
    [System.IO.File]::WriteAllText($logPath, (($script:logLines | ForEach-Object { $_ + "`r`n" }) -join ''), $script:logEncoding)
    $script:logPath = $logPath
} catch {}

# Warnings known before collection starts, printed now so they're seen up front.
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsSystem) {
        Add-CollectorWarning -Message "Not running as SYSTEM but as $($identity.Name): files only SYSTEM can read are counted as not accessible."
    }
} catch {}
if ($null -eq $hostInfo.Build -or $null -eq $hostInfo.Server) {
    Add-CollectorWarning -Message "Host details could not be fully determined: summary notes and missing-artefact warnings may be incomplete."
}
if ($outDir -ne $outDirs[0]) {
    Add-CollectorWarning -Message "Output written to a fallback folder ($outDir), not the Defender sensor's Temp\Collections."
}
if ($script:warnings.Count -gt 0) {
    Write-Line -Text ''
    Write-CollectorWarning
}
Write-Line -Text ''

try {
    $userProfiles = @(Get-UserProfilePath)
    foreach ($a in $artefacts) {
        if ($script:diskFull) { break }
        try { Add-Artefact -Zip $zip -Artefact $a -UserProfile $userProfiles } catch {}
    }
} finally {
    if ($zip) { try { $zip.Dispose() } catch {} }   # writes the zip's index; can fail if the disk is full
}

# Disk full: the zip is partial (and its index may not have been written), so it
# is useless. Delete it, tell the analyst, and stop - they free space and re-run.
if ($script:diskFull) {
    Remove-OutputFile -Path $zipPath
    $zipFate = if (Test-Path -LiteralPath $zipPath) { "could not be deleted and is unusable: $zipPath" } else { 'was deleted' }
    Add-CollectorWarning -Message "Collection stopped while collecting $($script:diskFullAt): $sysDrive is full. The partial zip $zipFate. Free up space on $sysDrive and run the collector again."
    Write-Line -Text ''
    Write-CollectorWarning
    return
}

$bytes = $null
try { $bytes = (Get-Item -LiteralPath $zipPath -Force).Length } catch {}

# Split a large zip into volumes. If it fails before the zip was cut, the whole
# zip is kept (any volumes already written are removed); once cut, nothing usable
# is left, so everything goes and the analyst runs again - as for a full disk.
$outFiles = @($zipPath)
$script:splitDamaged = $false
try {
    $outFiles = @(Split-ZipFile -Path $zipPath -PartSize $zipPartSize)
} catch {
    $reason = if (Test-DiskFull -ErrorRecord $_) { "$sysDrive is full" } else { Get-OneLineMessage -ErrorRecord $_ }
    $written = @(for ($i = 1; $i -le 999; $i++) {
        $v = '{0}.{1:D3}' -f $zipPath, $i
        if (Test-Path -LiteralPath $v) { $v }
    })
    Remove-OutputFile -Path $written
    if ($script:splitDamaged) {
        Remove-OutputFile -Path $zipPath
        $left = @(@($zipPath) + $written | Where-Object { Test-Path -LiteralPath $_ })
        $fate = if ($left) { 'could not all be deleted and are unusable: ' + ($left -join '; ') } else { 'were deleted' }
        Add-CollectorWarning -Message "Splitting the zip into volumes failed part-way ($reason). The zip and its volumes $fate. Run the collector again."
        Write-Line -Text ''
        Write-CollectorWarning
        return
    }
    Add-CollectorWarning -Message "The zip could not be split into volumes ($reason) and was kept whole."
}
foreach ($f in $outFiles) {
    try {
        $size = (Get-Item -LiteralPath $f -Force).Length
        if ($size -gt 3GB) {
            Add-CollectorWarning -Message ("{0} is {1} GB, over getfile's 3 GB per-file limit." -f (Split-Path -Path $f -Leaf), [math]::Round($size / 1GB, 2))
        }
    } catch {}
}

# SHA-256 of every output file (the zip, or each volume), so the download can be
# checked against it. One that can't be calculated is a warning, never left out.
$outHashes = [ordered]@{}   # output file path -> lower-case SHA-256, or $null
foreach ($f in $outFiles) {
    $outHashes[$f] = $null
    try {
        $outHashes[$f] = Get-FileSha256 -Path $f
    } catch {
        Add-CollectorWarning -Message ("SHA-256 of {0} could not be calculated ({1}): the download can't be checked against it." -f (Split-Path -Path $f -Leaf), (Get-OneLineMessage -ErrorRecord $_))
    }
}

# Folders that couldn't be listed and copies that failed part-way, named under
# the summary (each folder once, with the first reason met).
$unlistedReport = [ordered]@{}   # folder path -> reason
foreach ($failure in $script:listingFailures) {
    if (-not $unlistedReport.Contains($failure.Path)) { $unlistedReport[$failure.Path] = $failure.Reason }
}
$partialCopyCount = @($script:sizeDifferences | Where-Object { $_.ReadError }).Count
if ($unlistedReport.Count -gt 0) {
    Add-CollectorWarning -Message ("{0} folder(s) could not be listed; what they hold is counted as not accessible (named under 'Folders not listed')." -f $unlistedReport.Count)
}
if ($partialCopyCount -gt 0) {
    Add-CollectorWarning -Message ("{0} copy(ies) failed part-way and are incomplete in the zip (named under 'Copies whose size differs')." -f $partialCopyCount)
}

# Unusual gaps (see Add-Artefact), in summary order - the ones worth a closer look.
$unusual = foreach ($name in $script:summary.Keys) {
    if ($script:unusual.Contains($name)) { "$name ($($script:summary[$name]))" }
}
if ($unusual) { Add-CollectorWarning -Message ('Unusual gaps: ' + (@($unusual) -join '; ') + '.') }

# --- Output: warnings, summary, zip location, and runnable retrieval commands ---

Write-Line -Text ''
Write-CollectorWarning -ShowNone

Write-Line -Text ''
Write-Line -Text 'Artefact summary:'
# Three columns: name, status, and a note where the gap is normal for this host
# (the reason it's missing, or "(requires NTFS parser)" for locked files). Name and status widths follow the longest entry, so everything lines up.
$nameWidth   = ($script:summary.Keys   | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
$statusWidth = ($script:summary.Values | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
foreach ($name in $script:summary.Keys) {
    $note = if ($script:notes.ContainsKey($name)) { $script:notes[$name] } else { '' }
    Write-Line -Text ((("  {0,-" + $nameWidth + "} {1,-" + $statusWidth + "} {2}") -f $name, $script:summary[$name], $note).TrimEnd())
}

if ($unlistedReport.Count -gt 0) {
    Write-Line -Text ''
    Write-Line -Text 'Folders not listed (what they hold is counted as not accessible):'
    foreach ($folder in $unlistedReport.Keys) { Write-Line -Text ("  {0}: {1}" -f $folder, $unlistedReport[$folder]) }
}
if ($script:sizeDifferences.Count -gt 0) {
    Write-Line -Text ''
    Write-Line -Text 'Copies whose size differs from the source when it was opened:'
    foreach ($difference in $script:sizeDifferences) {
        $opened = if ($null -ne $difference.SizeWhenOpened) { "$($difference.SizeWhenOpened) bytes when opened" } else { 'size when opened unknown' }
        $line   = "  {0}: {1} bytes copied, {2}" -f $difference.Path, $difference.Copied, $opened
        if ($difference.ReadError) { $line += "; read failed, the zip entry is incomplete ($($difference.ReadError))" }
        Write-Line -Text $line
    }
}

$zipSize = if ($null -ne $bytes) { " ($([math]::Round($bytes / 1MB, 2)) MB)" } else { '' }

Write-Line -Text ''
Write-Line -Text "Collected $script:count files total$zipSize"
# Labels on their own line and bare commands below (the paths are long and wrap),
# so each command can be copied as-is.
if ($outFiles.Count -gt 1) {
    Write-Line -Text "Retrieve the zip, split into $($outFiles.Count) volumes, with:"
} else {
    Write-Line -Text 'Retrieve the zip with:'
}
foreach ($f in $outFiles) { Write-Line -Text "getfile `"$f`"" }
# In sha256sum's format ("<hash>  <name>"), so the lines can be checked with
# sha256sum -c once the files are downloaded.
Write-Line -Text $(if ($outFiles.Count -gt 1) { 'SHA-256 of each volume:' } else { 'SHA-256 of the zip:' })
foreach ($f in $outFiles) {
    $leaf = Split-Path -Path $f -Leaf
    if ($outHashes[$f]) { Write-Line -Text ("{0}  {1}" -f $outHashes[$f], $leaf) }
    else                { Write-Line -Text ("not calculated  {0}" -f $leaf) }
}
if ($script:logPath) {
    Write-Line -Text 'Retrieve the run log with:'
    Write-Line -Text "getfile `"$($script:logPath)`""
}

# Follow-up getfile commands for files this script found but couldn't read and
# the Defender sensor can retrieve directly - outcome-based: only reads that
# actually failed, in collection order (so metafiles first). Metafiles are listed
# only if flagged GetFile, with no Test-Path (PowerShell can't reliably see them);
# other files must still exist. Kept lean: each row's FollowUp scope only
# (machine-wide by default; for user hives, the users' own, not the built-in
# service accounts'), and no transaction logs (inferred from the hive).
$followups = New-Object 'System.Collections.Generic.List[string]'
foreach ($f in $script:failed) {
    if ($f.Literal) {
        if ($f.GetFile) { $followups.Add($f.Path) }
        continue
    }
    if ($f.Scope -ne $f.FollowUp)       { continue }
    if ($f.Path -match '\.LOG\d*$')     { continue }
    if (Test-Path -LiteralPath $f.Path) { $followups.Add($f.Path) }
}
if ($followups.Count -gt 0) {
    # Bare commands under a title, so the block can be copied and pasted as-is.
    Write-Line -Text ''
    Write-Line -Text 'Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):'
    foreach ($p in $followups) { Write-Line -Text "getfile `"$p`"" }
}
