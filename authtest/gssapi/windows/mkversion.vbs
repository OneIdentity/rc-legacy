' This script generates the version number constant in the file version.c
'
' It reads the configure.ac file from the parent directory,
' and extracts the version number that follows the "AC_INIT(" line,
' for example "1.0.0."
' 

Const ForReading = 1, ForWriting = 2
Dim fso, cf, vc, r, m
'Dim l as String = ""
'dim version as string

conf_ac = "..\..\configure.ac"
vers_c = "version.c"

Set fso = CreateObject("Scripting.FileSystemObject")
Set regex = CreateObject("VBScript.RegExp")

Set cf = fso.OpenTextFile(conf_ac, ForReading, True)

version = ""
do while not cf.atEndOfStream
    l = cf.ReadLine
    if InStr(l, "AC_INIT(") > 0 then
	l = cf.ReadLine
	regex.Global = True
	regex.Pattern = "\[([0-9.]*)\.]"
	Set m = regex.Execute(l)
	Set match = m(0)
	version = match.SubMatches(0)
        WScript.Echo "Got version: " & version
	exit do
    end if
loop
cf.Close

if version = "" then
    Err.raise 65535, None, ("Could not find version string in " & conf_ac)
    WScript.Quit 1
end if

Set vc = fso.OpenTextFile(vers_c, ForWriting, True)
vc.WriteLine("#include " & chr(34) & "version.h" & chr(34))
vc.WriteLine("const char version[] = " & chr(34) & version & chr(34) & ";")
vc.Close

