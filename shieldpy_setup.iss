; ShieldPy 玄盾卫士 安装脚本 (Inno Setup 6)
; 编译: ISCC.exe shieldpy_setup.iss

#define MyAppName "ShieldPy 玄盾卫士"
#define MyAppNameEN "ShieldPy"
#define MyAppVersion "1.0.55"
#define MyAppPublisher "ShieldPy"
#define MyAppExeName "ShieldPy.exe"

[Setup]
AppId={{5A2B9C4D-1E3F-4A5B-8C6D-2E7F8A9B0C1D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\ShieldPy
DefaultGroupName=ShieldPy 玄盾卫士
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; 以最高可用权限运行安装程序（提升到管理员）
PrivilegesRequiredOverridesAllowed=dialog
SetupIconFile=shield_icon.ico
UninstallDisplayIcon={app}\ShieldPy.exe
UninstallDisplayName={#MyAppName}
OutputDir=Output
OutputBaseFilename=ShieldPy_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageAlphaFormat=premultiplied
ArchitecturesInstallIn64BitMode=x64compatible
; 确保安装到 64 位系统时使用真实 Program Files
ArchitecturesAllowed=x64compatible
MinVersion=10.0

[Languages]
; 若存在中文语言文件则启用；否则删除本行使用英文向导
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"; Flags: unchecked

[Files]
Source: "..\dist\ShieldPy.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; ---------- 右键菜单注册（HKLM，安装时写入，卸载时自动删除） ----------
[Registry]
; 1) 文件夹（目录）右键
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""

; 2) 文件夹空白处右键
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%V"""

; 3) 所有文件右键
Root: HKLM; Subkey: "Software\Classes\*\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"
Root: HKLM; Subkey: "Software\Classes\*\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""

; 4) 磁盘驱动器右键
Root: HKLM; Subkey: "Software\Classes\Drive\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""

; ---------- 安装完成后启动 ----------
[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 {#MyAppName}"; Flags: nowait postinstall skipifsilent
