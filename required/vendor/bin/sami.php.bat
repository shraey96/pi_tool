@ECHO OFF
setlocal DISABLEDELAYEDEXPANSION
SET BIN_TARGET=%~dp0/../sami/sami/sami.php
php "%BIN_TARGET%" %*
