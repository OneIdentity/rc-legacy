# Resource Central Legacy Code
Location of legacy resource central code that is no longer being actively developed by One Identity

* [Authentication test tools](README.md#authentication-test-tools)
* [CoolKey](README.md#cool-key)
* [GDM Smartcard](README.md#gnome-smartcard-login)
* [gvasjoin](README.md#gvasjoin)
* [ktedit](README.md#ktedit)

# [Authentication test tools](#authentication-test-tools)
This is a package of tools useful for testing the various authentication aspects of Quest Authentication Services (QAS) for Unix, Windows and Java platforms.

## Unix tools
### gss-client, gss-server, gss-dump
  Generate and consume GSS-API tokens to exercise authentication systems. You run gss-client in one window, and gss-server in another,     then cut-and-paste the printed BASE64 encoded tokens between each other. Detailed information about the visible GSS state is             displayed. Credential names, name types and security levels can be varied as command-line options. The gss-dump tool can be used to     display the content of tokens; it uses wireshark's dissectors to do this.
### kuserok
  Tests the krb5_kuserok() interface to [QAS](http://www.quest.com/Authentication-Services/) which permits unix account access to Kerberos principals.
### pamtest
  Tests the system PAM (Pluggable Authentication Module) interface. Permits specifying the application name, user name, response strings   (or live prompting), tty, host etc. Detailed information about the upcall information and errors available via the PAM interface are     displayed. Includes simulation of the OpenSSH privsep behaviour, where part of the PAM exchange is performed in a separate process.
### lamtest
  (AIX systems only) Tests the system LAM interface, calling all of AIX's authenticate() and friends.
### Windows tools
  client.exe, server.exe
  The win32 package contains Microsoft SSPI equivalents of the Unix gss-client and gss-server tools described above. Includes             documentation for testing interoperability between Windows and Unix, Java or even Windows-to-Windows.
### Java tools
  Client, Server
  The JGSS equivalent of the Unix **gss-client** and **gss-server tools**. These tools and documentation can be found in the gssapi/java   directory of the source package. Includes configuration documentation for use with Sun's Kerberos implementation, or [Quest Single       Sign-on for Java (VSJ).](http://www.quest.com/Single-Sign-On-for-Java/)
  
# [Cool Key](#cool-key)
CoolKey is an open-source PKCS#11 smartcard library that can recognise CAC (Common Access Card).

Quest Software provides binary and source packages of the CoolKey 1.1.0 library for Red Hat Enterprise Linux 4 and 5 with fixes that allow it to work with our Quest Authentication Services Smartcard product:

[Red Hat Bug #245529](https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=245529) - coolkey hangs in C_Initialize() if pthreads library is not linked
Future releases of CoolKey from Red Hat should include this fix.

## Installation Instructions
Installation of coolkey requires the pcsc-lite package. Under Red Hat Enterprise Linux this is available from Red Hat through the "Red Hat Certificate System" channel.

# [Gnome Smartcard Login](#gnome-smartcard-login)
[GDM](http://www.gnome.org/projects/gdm/) is a graphical login program for Linux. Typically, it allows login via username and password.

Login using a smartcard is possible, but there is currently no automatic detection of smartcard insertion and removal. Intuitively, a user would expect that if a smartcard is inserted while a "Username:" prompt is displayed, then GDM would recognize the insertion and (eventually) the user would be asked for a PIN. Similarly, a user would expect that if a smartcard is removed while a "PIN:" prompt is displayed, then GDM would cancel the PIN request and restart the login process.

Quest has modified GDM so that smartcard insertion and deletion are recognized. The solution consists of two packages:

### [quest-gdm](./gdm/gdm-2.6.0.5)
A modified version of GDM that allows for the loading of a "PAM prompt plugin". The plugin is activated whenever PAM requests a prompt (such as "Username:" or "PIN:") during authentication. The normal prompt is still displayed, but the plugin may perform internal communication with the GDM process that simulates user entry at that prompt. For architectural reasons, no plugins are provided with this version of GDM.

### [quest-gdm-plugins](./gdm-plugins)
A collection of PAM prompt plugins for the modified version of GDM above, which monitor smartcard events. Two plugins are provided: a plugin based on the [PKCS#11 interface](http://www.rsasecurity.com/rsalabs/node.asp?id=2133), and a plugin based on the [PC/SC interface](http://pcsclite.alioth.debian.org/pcsc-lite/). The PKCS#11 plugin is considered more stable and should be used with PAM applications that use PKCS#11 to communicate with the smartcard (such as the PAM smartcard module provided with [Quest Authentication Services (QAS)](http://www.quest.com/Authentication-Services/)). The PC/SC plugin is experimental and should not be used with PAM applications that use PKCS#11.

## Installation Instructions
Install the quest-gdm and gdm-plugins packages with your platform's normal package management tools:

## Linux (RPM)
```
# rpm -e gdm
# rpm -ivh gdm-2.6.0.5-6.quest.1.rhel4.i386.rpm
# rpm -ivh gdm-plugins-0.1.0.rhel4.i386.rpm
```

## Post-Installation Instructions
After installing the quest-gdm and gdm-plugins packages, you will need to do the following steps:

1. Modify the GDM configuration file (typically */etc/X11/gdm/gdm.conf* or */etc/X11/gdm/gdm.conf.factory*) so that GDM will load a prompt plugin. The *PromptPlugin* setting of the *[greeter]* section of the configuration file must be set to the full path of the required PAM prompt plugin. It is recommended that the PKCS#11 plugin should be used with [Quest Authentication Services (QAS)](http://www.quest.com/Authentication-Services/):
    ```
    [greeter]
    ...
    PromptPlugin=/usr/lib/gdm/plugins/libpromptpkcs11.so
    ```
2. Modify the configuration file (if any) for the prompt plugin. For the PKCS#11 plugin, this will mean specifying the location of the vendor's PKCS#11 library in */etc/X11/gdm/plugins/pkcs11.conf*:
    ```
    [pkcs11]
    library=/usr/lib/libpkcs11.so # change as required
    ```
1. As root, restart GDM:
    ```
    # /usr/sbin/gdm-restart
    ```
    (or, alternatively, hit ctrl-alt-backspace)

# [gvasjoin](#gvasjoin)
gvasjoin is a Gtk+ program that wraps vastool to experiment with GUI tools for Active Directory integration. It needs Glade 2 to compile.
  [gvasjoin-0.1.tar.gz](../../releases/tag/gvasjoin-0.1)


# [ktedit](#ktedit)
**Note:** *ktedit* has been superceded by _**vastool ktutil**_ and  _**ktutil**_ commands, available since Quest Authentication Services 3.1.

*ktedit* is a small tool for editing keytab files.

*ktedit* grew out of my need to scriptably change principal names associated with keys, so it has functions to do that. It has some of the functionality of ktutil, and vastool ktlist. A unique feature is the copy command.

The tool is provided here because it can come in handy when creating service principal aliases.

## Usage
Follows is a brief synopsis of the useful commands in ktedit-1.1. They are also described in more detail in its manual page.

__copy *key-pattern new-principal*__
    Duplicates keytab entries, replacing their principal name. Useful for manually creating aliases.
  
__delete *key-pattern*__
  Deletes entries.
  
__dump__
  Dumps keytab in text form, suitable for undump
  
__list__
  Prints keytab contents
  
__undump [-r]__
  Appends or replaces a keytab with keys read from a text stream

## Compiling
If you are on a system with rpm, you can build ktedit directly using rpmbuild -tb. Otherwise, unpack the source distribution, run configure and then make.

You may need the vasdev package installed to build ktedit.

## Known issues
> **Warning: krb5_keytype_to_string: Program lacks support for key type**
> This harmless message arises in earlier versions of Quest Authentication Services because the addition of the DES-MD5 cipher was not given an internal name. Instead, ktedit will display the cipher type in its numeric form (3). You can safely ignore this message
