@echo off
REM Reassemble jadx-1.5.0-all.jar from chunks
echo Reassembling jadx-1.5.0-all.jar from chunks...
if exist jadx-1.5.0-all.jar del jadx-1.5.0-all.jar
echo Appending part000...
copy /B jadx-1.5.0-all.jar.part000 + jadx-1.5.0-all.jar /Y > nul 2>&1
echo Appending part001...
copy /B jadx-1.5.0-all.jar.part001 + jadx-1.5.0-all.jar /Y > nul 2>&1
echo Appending part002...
copy /B jadx-1.5.0-all.jar.part002 + jadx-1.5.0-all.jar /Y > nul 2>&1
echo Done! Verifying checksum:
certutil -hashfile jadx-1.5.0-all.jar SHA256 | findstr /V "hash" | findstr /V "CertUtil" > tmp_hash.txt
set /p ACTUAL_HASH=<tmp_hash.txt
set EXPECTED_HASH=c1290292e17ff6dcaa030d38b9173794
echo.
if "%ACTUAL_HASH%" == "%EXPECTED_HASH%" (
  echo SUCCESS: Checksum matches!
  del tmp_hash.txt
) else (
  echo WARNING: Checksum mismatch. File may be corrupted.
  echo Expected: %EXPECTED_HASH%
  echo Actual:   %ACTUAL_HASH%
)
