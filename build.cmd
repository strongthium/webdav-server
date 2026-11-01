@echo off
rem Builds webdav-server into public\: build.cmd [-Bump major^|minor^|patch^|revision] [-Version w.x.y.z] [-SkipTests]
rem See build.ps1 for the options.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
exit /b %ERRORLEVEL%
