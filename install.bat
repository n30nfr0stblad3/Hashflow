@echo off
REM Hashflow Windows installer - Normie Mode
REM Run this file (double-click) to install Hashflow.
setlocal
chcp 65001 >nul

echo ============================================
echo   Hashflow installer for Windows
echo ============================================
echo.

REM --- 1. Python check ---
where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% neq 0 (
        echo [1/4] Python not found - downloading installer...
        powershell -Command "Start-Process 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -Wait"
        echo Please re-run this file after Python finishes installing.
        pause
        exit /b 1
    )
    set "PY=py"
) else (
    set "PY=python"
)

REM --- 2. Get Hashflow ---
echo [2/4] Getting Hashflow...
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo Installing git...
    winget install -e --id Git.Git --accept-source-agreements --accept-package-agreements || echo Please install git manually and re-run.
)
if not exist "%USERPROFILE%\Hashflow" (
    git clone -b arena/01a095da-hashflow https://github.com/n30nfr0stblad3/Hashflow.git "%USERPROFILE%\Hashflow" || git clone https://github.com/n30nfr0stblad3/Hashflow.git "%USERPROFILE%\Hashflow"
)
cd /d "%USERPROFILE%\Hashflow"

REM --- 3. Install ---
echo [3/4] Installing Hashflow...
%PY% -m pip install --upgrade pip
%PY% -m pip install -e .

REM --- 4. xmrig ---
echo [4/4] Downloading xmrig miner...
%PY% -m hashflow install

REM --- Desktop shortcut ---
echo Set oWS = WScript.CreateObject^("WScript.Shell"^) > "%TEMP%\hf.lnk.vbs"
echo sLinkFile = "%USERPROFILE%\Desktop\Hashflow.lnk" >> "%TEMP%\hf.lnk.vbs"
echo Set oLink = oWS.CreateShortcut^(sLinkFile^) >> "%TEMP%\hf.lnk.vbs"
echo oLink.TargetPath = "cmd.exe" >> "%TEMP%\hf.lnk.vbs"
echo oLink.Arguments = "/k cd /d %USERPROFILE%\Hashflow && hashflow start" >> "%TEMP%\hf.lnk.vbs"
echo oLink.WindowStyle = 1 >> "%TEMP%\hf.lnk.vbs"
echo oLink.Description = "Hashflow Monero Miner" >> "%TEMP%\hf.lnk.vbs"
echo oLink.Save >> "%TEMP%\hf.lnk.vbs"
cscript //nologo "%TEMP%\hf.lnk.vbs" >nul 2>nul
del "%TEMP%\hf.lnk.vbs" >nul 2>nul

echo.
echo ============================================
echo   DONE! Double-click "Hashflow" on Desktop.
echo ============================================
echo.
echo First time? The setup wizard will ask for:
echo   - your Monero wallet address
echo   - a nickname
echo   - how much CPU to use
echo.
echo Dashboard: http://localhost:8080
pause
