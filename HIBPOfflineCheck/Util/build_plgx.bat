@echo off

set PluginRoot=%~dp0..
set KeePassExe=%PluginRoot%\Lib\KeePass.exe
Set BuildPath=%PluginRoot%\Bin
set OutputPath=%BuildPath%\plgx

if not exist %OutputPath% mkdir %OutputPath%

echo Copying source to output folder: %OutputPath%
xcopy /Y %PluginRoot%\..\HIBPOfflineCheck.sln %OutputPath%\
xcopy /Y %PluginRoot%\HIBPOfflineCheck.csproj %OutputPath%\
xcopy /Y %PluginRoot%\HIBPOfflineCheckExt.cs %OutputPath%\
xcopy /Y %PluginRoot%\HIBPOfflineCheckOptions.cs %OutputPath%\
xcopy /Y %PluginRoot%\HIBPOfflineCheckOptions.Designer.cs %OutputPath%\
xcopy /Y %PluginRoot%\HIBPOfflineCheckOptions.resx %OutputPath%\
xcopy /Y %PluginRoot%\HIBPOfflineColumnProv.cs %OutputPath%\
xcopy /Y %PluginRoot%\ProgressDisplay.cs %OutputPath%\
xcopy /Y %PluginRoot%\ProgressDisplay.Designer.cs %OutputPath%\
xcopy /Y %PluginRoot%\ProgressDisplay.resx %OutputPath%\
xcopy /Y %PluginRoot%\Options.cs %OutputPath%\
xcopy /Y %PluginRoot%\Properties\AssemblyInfo.cs %OutputPath%\Properties\
xcopy /Y %PluginRoot%\Resources\Nuvola\B48x48_KOrganizer.png %OutputPath%\Resources\Nuvola\
xcopy /Y %PluginRoot%\Properties\Resources.Designer.cs %OutputPath%\Properties\
xcopy /Y %PluginRoot%\Properties\Resources.resx %OutputPath%\Properties\
xcopy /Y %PluginRoot%\BitStorage.cs %OutputPath%\
xcopy /Y %PluginRoot%\BloomFilter.cs %OutputPath%\
xcopy /Y %PluginRoot%\CreateBloomFilter.Designer.cs %OutputPath%\
xcopy /Y %PluginRoot%\CreateBloomFilter.cs %OutputPath%\
xcopy /Y %PluginRoot%\CreateBloomFilter.resx %OutputPath%\

echo Creating PLGX: '%KeePassExe% --plgx-create "%OutputPath%"'
%KeePassExe% --plgx-create "%OutputPath%"

move /Y "%BuildPath%\plgx.plgx" %BuildPath%\HIBPOfflineCheck.plgx

rmdir /S /Q "%OutputPath%\"