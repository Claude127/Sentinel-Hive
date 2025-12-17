@echo off
echo ========================================
echo SURVEILLANCE AUTOMATIQUE COWRIE
echo ========================================
echo.
echo Installation de la dependance watchdog si necessaire...
pip install watchdog
echo.
echo Demarrage de la surveillance...
echo.
python sentinelModel/watch_and_analyze.py
pause
