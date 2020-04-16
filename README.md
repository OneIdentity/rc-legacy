# Resource Central Legacy Code
Location of legacy resource central code that is no longer being actively developed by One Identity


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
