
Quest PuTTY
===========

Quest PuTTY is a derivative of Simon Tatham's PuTTY, an open-source Secure
Shell (SSH) client for Microsoft Windows.

    http://rc.quest.com/topics/putty/	- Quest PuTTY home page
    http://www.chiark.greenend.org.uk/~sgtatham/putty/ - PuTTY home page

Features added to baseline PuTTY
--------------------------------

 * GSSKEX host authentication using SSPI
 * gssapi-with-mic and gssapi-keyex user authentication using SSPI
 * able to initialise authentication username with windows username
 * able to provide dialog password prompts when using PLINK
 * Group Policy support for some security options
 * transfer bandwidth limiting for PSCP

 Please see CHANGES.txt for detailed change history.

Installation options
--------------------

 * PuTTY executables (plink.exe, putty.exe, etc) can be run 'standalone',
   i.e. without a package being installed. Quest Software recommends that
   the MSI package be installed where possible.

 * The directory to create shortcuts in can be chosen during installation
   by overriding the SHORTCUTFOLDER property. This is done from a Command
   Prompt, like so:

     C:\> MSIEXEC /i Quest-Putty.msi SHORTCUTFOLDER="C:\Documents and Settings\All Users\Start Menu\Programs\Quest PuTTY"

   Alternatively, a transform file (.MST) can be used.

Building from source
--------------------
 Please see the file BUILDING.txt for details on compiling Quest PuTTY.

Licence
-------
 Please see the file putty/LICENCE for licence conditions.

