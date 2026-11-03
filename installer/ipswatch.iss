; IPS Watch installer (Inno Setup 6). Built by build.ps1:
;   ISCC.exe /DAppVersion=<version from Cargo.toml> installer\ipswatch.iss
; Per-user install (no admin rights), like the app's own data, secrets and autostart.
; Settings and the event database live in %APPDATA%\ipswatch and are kept on uninstall.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F1E2B9C-4D7A-4E3B-9A5C-1B2D3E4F5A60}
AppName=IPS Watch
AppVersion={#AppVersion}
AppVerName=IPS Watch {#AppVersion}
AppPublisher=IPS Watch
AppComments=Capture OPNsense IPS (Suricata) alerts and flag potential unwanted access
DefaultDirName={localappdata}\Programs\IPS Watch
DefaultGroupName=IPS Watch
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=IPSWatch-Setup-{#AppVersion}
SetupIconFile=..\assets\ipswatch.ico
UninstallDisplayIcon={app}\IPSWatch.exe
UninstallDisplayName=IPS Watch
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Upgrading closes the installed copy (only processes using files in {app}) and restarts it.
CloseApplications=force
RestartApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "..\target\release\IPSWatch.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\ipswatch-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\IPS Watch"; Filename: "{app}\IPSWatch.exe"
Name: "{group}\Uninstall IPS Watch"; Filename: "{uninstallexe}"
Name: "{autodesktop}\IPS Watch"; Filename: "{app}\IPSWatch.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\IPSWatch.exe"; Description: "Start IPS Watch"; Flags: nowait postinstall skipifsilent

[Code]
const
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';

{ Stop only IPS Watch copies running from this install folder. }
procedure StopInstalledCopy();
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -Command "Get-Process IPSWatch,ipswatch-cli -ErrorAction SilentlyContinue | ' +
    'Where-Object { $_.Path -like ''' + ExpandConstant('{app}') + '\*'' } | Stop-Process -Force"',
    '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Cmd: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopInstalledCopy();
    { Remove "start with Windows" only if it points at this install (not a copy elsewhere). }
    if RegQueryStringValue(HKCU, RunKey, 'IPSWatch', Cmd) and
       (Pos(Lowercase(ExpandConstant('{app}\')), Lowercase(Cmd)) > 0) then
      RegDeleteValue(HKCU, RunKey, 'IPSWatch');
  end;
end;
