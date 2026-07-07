@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title CyberScope v7.9.x - GitHub Uploader

echo ================================================================
echo   CyberScope v7.9.x - GitHub Uploader
echo ================================================================
echo.

cd /d "%~dp0"
set "ROOT=%cd%"
echo Running from: %ROOT%
echo.

echo [1/5] Checking Git...
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed.
    pause
    exit /b 1
)
echo Git OK.
echo.

echo [2/5] Cleaning any leaked secrets...
if exist "backend\.env" del /f /q "backend\.env" 2>nul
if exist "backend\.jwt_secret" del /f /q "backend\.jwt_secret" 2>nul
if exist "frontend\.env" del /f /q "frontend\.env" 2>nul
if exist ".env" del /f /q ".env" 2>nul
echo Done.
echo.

echo [3/5] Please provide your GitHub info:
echo.
set /p "GIT_USER=Enter your GitHub username: "
set /p "GIT_EMAIL=Enter your GitHub email: "
set /p "REPO_URL=Enter repo URL (https://github.com/USER/REPO.git): "
echo.
echo User:   %GIT_USER%
echo Email:  %GIT_EMAIL%
echo Repo:   %REPO_URL%
echo.
pause

echo [4/5] Initializing git...
if not exist ".git" git init -b main
if errorlevel 1 git init

git config user.email "%GIT_EMAIL%"
git config user.name "%GIT_USER%"

git add .
git commit -m "Initial commit - CyberScope v7.9.x"
echo.

echo [5/5] Pushing to GitHub...
git remote remove origin >nul 2>&1
git remote add origin %REPO_URL%
git branch -M main
git push -u origin main --force
if errorlevel 1 (
    git pull origin main --rebase --allow-unrelated-histories
    git push -u origin main --force
)
echo.
echo DONE! Check your repo at: %REPO_URL%
pause
