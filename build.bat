@echo off
if "%1"=="" (
    echo Usage: build.bat ^<bin^>
    exit /b 1
)

cargo build --release --bin %1
if errorlevel 1 exit /b 1

if exist "src\ffi\%1.rs" (
    cargo rustc --release --lib --crate-type cdylib
)
