#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
[Setup]
AppId={{A28FE18A-E343-4D01-BBF5-2BC58608F1D2}
AppName=Multi VPN
AppVersion={#AppVersion}
AppPublisher=addsubmuldiv
AppPublisherURL=https://github.com/addsubmuldiv/multi_vpn
DefaultDirName={autopf}\MultiVPN
DefaultGroupName=Multi VPN
DisableProgramGroupPage=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#ifdef InstallerSmokeTest
OutputDir=..\build\installer-smoke
#else
OutputDir=..\dist\installers
#endif
OutputBaseFilename=MultiVPN-{#AppVersion}-windows-x64-setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\MultiVPN.exe
Compression=lzma2
SolidCompression=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\MultiVPN\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Multi VPN"; Filename: "{app}\MultiVPN.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Multi VPN"; Filename: "{app}\MultiVPN.exe"; WorkingDir: "{app}"

[Run]
#ifdef InstallerSmokeTest
Filename: "{app}\MultiVPN.exe"; Parameters: "--self-test --self-test-report ""{app}\postinstall-smoke.json"""; Flags: postinstall runascurrentuser
#else
Filename: "{app}\MultiVPN.exe"; WorkingDir: "{app}"; Description: "Launch Multi VPN"; Flags: nowait postinstall skipifsilent runascurrentuser
#endif
