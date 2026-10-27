# Changelog

Notable changes to `collector.ps1`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.2.1 - 2026-10-27

### Changed
- The size on the "Collected N files" line is labelled as the zip's
  (`MB compressed`).

## 2.2.0 - 2026-10-27

### Added
- A warning naming user profiles that the registry's ProfileList places
  outside the folders searched for profiles (they are not searched), or saying
  that ProfileList couldn't be read.
- `not collected` rows in `collection.csv`, and the *Not collected* status in
  the summary, for artefacts a run that stopped to keep the reserve didn't
  reach.

### Changed
- A run that stops to keep the free-space reserve keeps the zip of what it
  collected: finished with `collection.csv`, read back and named in the
  Warnings as a partial collection, with no `getfile` line and no SHA-256 (it
  was deleted). The file being copied is `incomplete`; the artefact it stopped in
  is noted "(the run stopped here)".
- `getfile` lines are printed only for a complete output: the whole zip or
  every volume.
- Splitting: each volume's length on disk is checked before it is cut off the
  zip; a volume or the final rename that fails is tried once more after
  2 seconds; if that fails, the split is undone and the zip, read back again,
  is kept whole. Only a split that can't be undone deletes the output (it
  always did once the zip had been cut).
- The "(requires NTFS parser)" note applies only when at least one file
  failed as the expected lock does (a sharing violation; access denied for
  the NTFS metafiles) and every file that couldn't be opened did; any other
  failure is an unusual gap.
- An artefact whose collection fails as a whole reads *Failed* in the summary
  (was *Missing*).
- Error text in the warnings, the lists under the summary and
  `collection.csv`'s Detail is the underlying error's own message, without
  PowerShell's `Exception calling "..." with "N" argument(s):` wrapper.

### Fixed
- A failed split deleted every `<zip>.NNN` file beside the zip, including any
  this run hadn't created; it now deletes only its own.
- A full disk while splitting was reported as the system drive being full; it
  names the output drive.

## 2.1.0 - 2026-10-24

### Added
- The closed zip is read back (entry count, `collection.csv` last) before it
  is split, hashed or offered for `getfile`.
- A free-space reserve (1 GiB, CONFIG): collection stops, as for a full disk,
  before the output drive would go below it; a split starts only if a volume
  fits above it.
- Files whose content isn't on the disk (OneDrive cloud-only, offline) are not
  read, so nothing is downloaded: `not local` in `collection.csv`, counted as
  not accessible, and warned about.
- `artefact failed` row in `collection.csv` for an artefact whose collection
  fails as a whole.
- A closing `Finished <UTC>` line in the console and run log.
- Warnings when the run log can't be created or the output drive's free space
  can't be read; one console line when the run log stops being writable.

### Changed
- The `getfile` follow-up heading reads "could not be read by PowerShell"
  (was "locked from PowerShell").
- A drive whose file system can't be read shows as `unknown` (was assumed
  NTFS).

### Fixed
- A failure while closing a zip entry or the zip itself (e.g. disk full while
  writing the index) was ignored: the entry was recorded as collected, and a
  zip that couldn't be opened was hashed and offered for `getfile`. The entry
  is now `incomplete`; a zip that can't be finished is deleted, with a
  warning, as for a full disk.
- A profile root that exists but can't be read was skipped silently; it is
  now a folder not listed.
- On a full disk the partial zip couldn't be deleted: its file stayed open
  until the run ended, kept the drive full, and the write attempted at exit
  started Windows Error Reporting (`wermgr.exe`, a report in the WER queue).
  The file is now closed and the zip deleted.

## 2.0.0 - 2026-10-22

The zip's layout changes: `collection.csv` joins the drive folders at its
root, and empty files and file symbolic links are no longer in it.

### Added
- `collection.csv` at the zip's root: one row per file collected or found but
  not readable - artefact, outcome, source path, zip entry, size, bytes
  copied, SHA-256 of the bytes written, the file's own created, modified and
  accessed times (UTC), and the error for a failure - and one per folder that
  couldn't be listed, with the reason.

### Changed
- Empty (0-byte) files are left out of the zip, the record and every count.
- File symbolic links are not followed, and are left out of the zip, the
  record and every count.
- The printed `getfile` commands leave out only registry transaction logs
  (`.LOG1`/`.LOG2`); other locked files, ESE logs included, are listed.
- "Unusual gaps" lists one artefact per line.
- Code restructured for readability: full-word names, results returned
  instead of script state, no script-wide error suppression. No change to
  what is collected beyond the lines above.

## 1.5.0 - 2026-10-22

### Added
- The SHA-256 of the zip, or of each volume, is printed under its `getfile`
  lines and kept in the run log, in `sha256sum` format.
- Copies whose size differs from the source's size when opened are named under
  the summary, with the bytes copied.

### Fixed
- A folder that exists but can't be listed was counted as Missing; it now
  counts as Not accessible, is warned about and is named under the summary.
- A copy that failed part-way stayed in the zip, incomplete, with nothing to
  say which entry; it is now warned about and named under the summary.
- A file whose name ends with a dot or a space was opened as its namesake
  without them (e.g. `report.` as `report`), so its entry held another file's
  content; every file is now opened through `\\?\`.
- Files in a folder whose name ends with a dot or a space (e.g. `dir.`) were
  silently left out: PowerShell listed the folder without them instead. Such
  folders are now listed through `\\?\`.
- Windows' compatibility links that deny listing (`Default User`, `All Users`,
  `Documents and Settings`) weren't recognised as links, so files under
  `Default User` were collected twice; they are no longer followed.

## 1.4.0 - 2026-10-13

### Added
- A zip over 1 GiB is split in place into standard split volumes
  (`.zip.001`, `.002`, ...), each retrieved with its own `getfile`.

### Removed
- Delete-at-reboot of the output folder. The collector starts no child
  processes (`csc.exe` is no longer run).

## 1.3.0 - 2026-10-13

### Added
- Recycle Bin and NTFS metafiles are collected (or listed for `getfile`) from
  every local drive - fixed or removable, NTFS, FAT or exFAT - not just the
  system drive. Drives that can't be read are skipped.
- A "Drives" line lists the drives searched and their file systems.

### Changed
- Zip entry paths keep each folder name's on-disk case (e.g. `$RECYCLE.BIN`),
  not the case written in the artefact table.

## 1.2.1 - 2026-10-13

### Changed
- Warnings list a missing artefact only if it should exist on the host (e.g.
  event logs, or Prefetch on a workstation), not artefacts that may simply be
  absent, such as PowerShell transcripts.

## 1.2.0 - 2026-10-13

### Added
- Warnings section, shown at the start if known by then and again before the
  summary: unusual gaps, not running as SYSTEM, fallback output folder, zip
  over the 3 GB `getfile` limit, cleanup not queued, full disk.
- Run log: the console output is also written to `<HOSTNAME>_<timestamp>Z.log`
  beside the zip, with a `getfile` command for it at the end.

### Changed
- Summary notes now say why a gap is normal for the host, e.g. "(normal for
  Windows Server)", "(not on this Windows version)", and "(requires NTFS
  parser)" for normally locked files, instead of "(not unusual)".
- "Recycle Bin ($I, INFO2)" renamed "Recycle Bin".
- The `getfile` list now includes logged-on users' locked hives (`NTUSER.DAT`,
  `UsrClass.dat`) instead of the built-in service accounts' hives.

### Fixed
- No `getfile` command is printed for `$LogFile`: Live Response rejects it as
  an empty file.

## 1.1.0 - 2026-10-12

### Added
- OS name and release printed after the banner.
- Summary column marking Missing or Not accessible statuses that are normal for
  the host (e.g. Prefetch on servers, legacy-only artefacts, live hives) as
  `(not unusual)`, so unusual gaps stand out.

### Changed
- Amcache, AppCompat PCA and Syscache merged into one "Application
  Compatibility" line (Syscache and RecentFileCache are Amcache's pre-Windows 8
  predecessors).
- The zip is now written under the Defender for Endpoint
  sensor's Temp folder,
  `ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp\Collections\`,
  falling back to a `LiveResponseCollector` folder in `Windows\SystemTemp` or
  the account's temp folder, instead of `%SystemDrive%\LiveResponse\`. The
  printed `getfile` path changes accordingly.

## 1.0.1 - 2026-10-12

### Fixed
- A full system drive now stops collection, deletes the partial (unusable) zip
  and says to free space and run again, instead of reporting every remaining
  file as not accessible.
- Recursive searches no longer follow junctions or symbolic links.
- Browser History counts a profile as collected only if its main database was
  read, not just its journal or logs.
- A policy transcription folder at the system drive's root is skipped instead
  of searching the whole drive.
- Repeat runs no longer queue already-queued files for deletion again;
  `%SystemDrive%` has a fallback; paths of 260+ characters can be opened.

### Changed
- Script header is now PowerShell comment-based help (`Get-Help`).

## 1.0.0 - 2026-10-12

### Added
- Legacy forms of existing artefacts, listed after their current form: `.evt`,
  `setupapi.log`, `.job` and `SchedLgU.txt`, Recycle Bin `INFO2`, XP profile
  paths (`Documents and Settings`), XP restore-point hives and shortcuts, older
  Defender logs, legacy browser history (Firefox `downloads.sqlite`, Opera 12,
  Safari for Windows), and the previous install in `Windows.old`.
- Amcache line (with `RecentFileCache.bcf`), Syscache, Windows Timeline, XP
  restore-point logs, SCCM client logs, OneDrive metadata (settings and logs),
  Group Policy (local and cached domain GPOs), User Access Logging (SUM), Teams
  logs, and IE / legacy Edge history (WebCache, `index.dat`).

### Changed
- Amcache moved out of "Registry Hives (system)" into its own line; "EVTX"
  renamed "Event Logs"; "Recycle Bin ($I)" renamed "Recycle Bin ($I, INFO2)".
- Summary name column sized to the longest artefact name.
- Junctions and symbolic links are skipped by link type, so other reparse
  points (e.g. OneDrive cloud folders) are no longer skipped.

## 0.16.1 - 2026-10-12

### Changed
- Summary line "File History" renamed "File History Catalogs".

## 0.16.0 - 2026-10-12

### Added
- Defender logs (Support logs, detection history), AppCompat PCA, BITS
  database and .NET CLR usage logs.
- Service-account artefacts: `DEFAULT`, systemprofile, LocalService and
  NetworkService hives; SYSTEM's PowerShell history, scheduled jobs, CLR logs
  and Chrome history.
- History of other maintained browsers: Edge and Chrome Beta/Dev/Canary,
  Chromium, Brave, Vivaldi, Opera, Yandex, Arc, Coc Coc, QQ, 360, Wave,
  Prisma Access, Supermium.
- RegBack hives; CustomDestinations JumpLists; Office recent, desktop and Start
  Menu shortcuts; PowerShell scheduled jobs; `SysWOW64\Tasks`; SRUM ESE logs;
  more transcript locations.

### Changed
- EVTX limited to `*.evtx`; firewall logs include rotated `pfirewall.log.old`;
  PowerShell history covers every PSReadLine host (`*_history.txt`).
- User profiles are again the folders under `<SystemDrive>\Users`; the 0.15.0
  ProfilesDirectory lookup is removed.

## 0.15.0 - 2026-10-10

### Added
- PowerShell transcripts from OneDrive-redirected Documents (Known Folder
  Move), from dated subfolders (policy transcription), and from a Group Policy
  transcription `OutputDirectory` on a local drive (Windows PowerShell and
  PowerShell 7).

### Changed
- User profiles are enumerated under the ProfileList `ProfilesDirectory`
  (falls back to `<SystemDrive>\Users`).

## 0.14.0 - 2026-10-10

### Changed
- Artefacts are defined in one table; collection and progress lines now follow
  the summary order.
- Each artefact location is handled independently, so a failure skips only
  that location.
- Zip entry timestamps are written in UTC (previously host local time).
- The host name and UTC start time are printed after the version banner.
- Changelog moved from the script header to this file.

## 0.13.5 - 2026-10-10

### Fixed
- Delete-on-reboot cleanup never took effect: `MoveFileEx` now receives a true
  null destination.

### Changed
- Licence changed from MIT to 0BSD; SPDX identifier added.

## 0.13.4 - 2026-10-09

First version in this repository.

### Changed
- `getfile` follow-ups for `$MFT` and `$LogFile` are printed only if the read
  actually failed.

## 0.1.0 - 0.13.3 (before the repository, undated)

- **0.13.3** - Changed: user profiles are the folders under `\Users`; service
  profiles under `\Windows` are excluded.
- **0.13.2** - Added: `getfile` follow-ups for locked machine-wide files.
  Changed: zip size shown on the "Collected" line.
- **0.13.1** - Changed: all paths anchored to the system drive.
- **0.13.0** - Changed: paths resolved from the environment (non-`C:`
  installs); UTC timestamp in the zip name; approved-verb function names.
- **0.12.2** - Changed: structural tidy, no behaviour change.
- **0.12.1** - Added: per-artefact progress line.
- **0.12.0** - Added: registry transaction logs (`.LOG1`/`.LOG2`) for every
  hive.
- **0.11.0** - Added: File History catalogs.
- **0.10.0** - Added: SetupAPI device-install logs, Windows Firewall log.
- **0.9.0** - Added: `SECURITY` hive, Scheduled Tasks, Startup folders, WER
  report metadata, `$LogFile`.
- **0.8.2** - Changed: end of run prints only runnable commands.
- **0.8.1** - Changed: summary in a fixed three-group order; files streamed
  into the zip in one pass.
- **0.8.0** - Added: Chrome and Firefox history, counted per browser profile.
- **0.7.0** - Added: `$MFT` and `$UsnJrnl:$J` as summary placeholders, with a
  `getfile` command for `$MFT`.
- **0.6.0** - Added: system and user registry hives; zip size.
- **0.5.1** - Added: per-artefact status summary.
- **0.5.0** - Added: EVTX, Prefetch, SRUM, PowerShell history and transcripts.
- **0.4.0** - Added: delete-on-reboot cleanup. Changed: output folder renamed
  to `C:\LiveResponse`.
- **0.3.0** - Changed: zip compression set to Fastest.
- **0.2.0** - Changed: one fixed, hidden output folder instead of one per run.
- **0.1.0** - Initial collector: Recycle Bin `$I`, LNK, JumpLists, Edge
  history.
