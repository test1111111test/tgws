@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo === BUILD LINUX (amd64, static) ===
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0

go build -o tgws ./cmd

if %errorlevel% neq 0 (
    echo.
    echo BUILD FAILED
    pause
    exit /b 1
)

echo.
echo OK: tgws (linux/amd64, static)
echo Copy to Ubuntu: scp tgws user@host:~/
pause