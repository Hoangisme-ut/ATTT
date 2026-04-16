@echo off
REM ============================================================
REM Build script for Digital Signature Demo
REM Creates a single .exe file in the dist/ folder
REM ============================================================

echo ======================================
echo   Building Digital Signature Demo
echo ======================================
echo.

REM Install dependencies
pip install pycryptodome pyinstaller

echo.
echo Building .exe ...
echo.

REM We build this as a GUI-first desktop application.
REM Normal users double-click the .exe and see the GUI directly.
REM The --noconsole flag hides the black terminal window.
pyinstaller ^
    --onefile ^
    --noconsole ^
    --name "DigitalSignatureDemo" ^
    --add-data "app;app" ^
    --hidden-import "app.gui.main_window" ^
    --hidden-import "app.cli.cli_app" ^
    --hidden-import "app.core.engine" ^
    --hidden-import "app.services.crypto_service" ^
    --hidden-import "app.services.keystore_service" ^
    --hidden-import "app.services.storage_service" ^
    main.py

echo.
echo ======================================
echo   Build complete!
echo   Output: dist\DigitalSignatureDemo.exe
echo ======================================
pause
