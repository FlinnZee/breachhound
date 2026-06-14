; Inno Setup script for BreachHound.
; Build:  ISCC.exe installer\breachhound.iss   (run from the repo root)
; Output: dist\breachhound-setup-<version>.exe

#define AppName "BreachHound"
#define AppVersion "0.1.0"
#define AppPublisher "TK NiRMAL"
#define AppURL "https://github.com/FlinnZee/breachhound"
#define AppExe "breachhound-gui.exe"

[Setup]
AppId={{6F3B1E2A-9C4D-4B7E-A1F2-7C0D9E5A4B31}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir={#SourcePath}..\dist
OutputBaseFilename=breachhound-setup-{#AppVersion}
SetupIconFile={#SourcePath}..\cmd\breachhound-gui\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
LicenseFile={#SourcePath}..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#SourcePath}..\dist\breachhound-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}..\cmd\breachhound-gui\assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
