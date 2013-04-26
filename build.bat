@REM
@REM This is the top-level build script for Quest-PuTTY.  It requires
@REM that the mkfiles.pl script has already been run in the source directory.
@REM Object files are written to %builddir% which defaults to a path 
@REM under %TEMP%.
@REM $Id$
@REM

@REM *Never* decrease QMINOR value. See discussion below
@set QMAJOR=0
@set QMINOR=3
@set REVISION=0
@IF EXIST ".svn\entries" (
    cscript /nologo svnversion.js >%TEMP%\revision.txt
    set /p REVISION= <%TEMP%\revision.txt
    del %TEMP%\revision.txt
)

@REM The _q<n> part should start new from n=1 for each PuTTY release
@set VERSION=0.60_q1.%REVISION%
@set NAME=Quest-PuTTY
@set MSISUFFIX=

@echo ---- Building %NAME%-%VERSION%

@REM Notes on the MSI package version number
@REM
@REM The pkg version number for Quest-PuTTY is now the Quest version 
@REM split into four parts as reqired by Quest ministandard #37.
@REM
@REM   major.minor.patch.build
@REM
@REM   When breaking (cli) interfaces:           increment major
@REM   When adding features/extending interface: increment minor
@REM
@REM (None of these numbers should exceed 32767.) We do not
@REM use the PuTTY version number in the package version metadata,
@REM but we do preserve it in the package's name. This is because
@REM Quest-PuTTY is a pretty much a separate product to Tatham's PuTTY.
@REM The build number should be derived from the revision number.

@set /a revisionhi=%REVISION% / 32768
@set /a revisionlo=%REVISION% %% 32768
set MSIVERSION=%QMAJOR%.%QMINOR%.%revisionhi%.%revisionlo%

@if not defined builddir  set builddir=%TMP%/putty/
@set srcdir=%CD%/

@REM path %PATH%;C:\MinGW\bin
@REM path %PATH%;C:\Program Files\HTML Help Workshop
@set htmlhelpinc=-I\"C:\Program Files\HTML Help Workshop/include/\"
@set multimon=-DNO_MULTIMON

@set make=mingw32-make
@set WIXDIR=C:\Progra~1\WiX\
@set debug=
@REM set debug=-DDEBUG

@REM Look for a file called localconf.bat that can override settings
@if exist "localconf.bat" (
@echo Loading localconf.bat ...
call localconf.bat
)

@set MSINAME=%NAME%-%VERSION%%MSISUFFIX%

@if not "%1" == "" goto %1

:all
@echo ---- Create output directories
md "%builddir%"
@md "%builddir%charset"
@md "%builddir%halibut"
@md "%builddir%\putty"
@md "%builddir%\putty\windows"
@md "%builddir%\putty\doc"

:charset
@echo ---- Build charset library
%make% -C %builddir%charset -f %srcdir%charset/Makefile.quest  ^
	CC=gcc srcdir=%srcdir%charset/
@if %errorlevel% gtr 0 goto :EOF

:halibut
@echo ---- Build halibut documentation tool
%make% -C %builddir%halibut -f %srcdir%halibut/Makefile.quest  ^
	CC=gcc srcdir=%srcdir%halibut/
@if %errorlevel% gtr 0 goto :EOF

:help
@echo ---- Build PuTTY help/documentation
%make% -C %builddir%putty/doc -f %srcdir%putty/doc/Makefile ^
	putty.chm putty.html ^
	srcdir=%srcdir%putty/doc/ ^
	HALIBUT=%builddir%halibut/halibut.exe ^
        VERSION=%VERSION%
@REM if %errorlevel% gtr 0 goto :EOF

:build
@echo ---- Build PuTTY executables
%make% -C %builddir%putty/windows -f %srcdir%putty/windows/Makefile.cyg ^
	VER=-DRELEASE=%VERSION% ^
	srcdir=%srcdir%putty/windows/ ^
	XFLAGS="-DSSPI_MECH -DFORCE_POLICY %multimon% %debug% %htmlhelpinc%"
@if %errorlevel% gtr 0 goto :EOF

:msi
@echo ---- Create installable package
%make% -C %builddir%putty/windows -f %srcdir%putty/windows/Makefile.wix ^
	VERSION=%VERSION% ^
	srcdir=%srcdir%putty/windows/ ^
	MSIVERSION=%MSIVERSION% ^
	WIXDIR=%WIXDIR% ^
	MSI=%builddir%%MSINAME%
@if %errorlevel% gtr 0 goto :EOF

:sign
@echo ---- Signing package
signtool sign /a ^
	/n "Quest Software" ^
        /du "http://rc.quest.com/topics/putty" ^
	%builddir%%MSINAME%.msi
@REM if %errorlevel% gtr 0 goto :EOF

@echo.
@echo ---- Quest-PuTTY %VERSION% is now ready.
goto :EOF

:clean
@echo ---- Cleaning
del /q /s "%builddir:~0,-1%"
