# Resource Central Legacy Code
Location of legacy resource central code that is no longer being actively developed by One Identity

* [Authentication test tools](README.md#authentication-test-tools)
* [CoolKey](README.md#cool-key)
* [GDM Smartcard](README.md#gnome-smartcard-login)
* [gvasjoin](README.md#gvasjoin)
* [ktedit](README.md#ktedit)
* [MySQl with SASL](README.md#mysql-with-sasl)
* [Pluggable GSSAPI](README.md#pluggable-gssapi)
* [PHP-VAS](README.md#php-vas)

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

# [MySQL with SASL](#mysql-with-sasl)

This is an experiment to add SASL authentication, security and authorization to the MySQL wire protocol. It is in a very alpha stage. It may even turn into gssapi only to fix principal name meanings.

## Notes on kerberizing MySQL
There is existing support for SSL and compression, which can be leveraged to fit with SASL framing.

* When the client connects to the server, the server sends a protocol packet, and the client will quit if it doesn't exactly understand the protocol version PROTOCOL_VERSION (defined in configure.in as 10)
* The file sql/net_serv.cc contains the low-level packet i/o routines. There is a 'compressed' packet protocol and an uncompressed packet protocol.
```
+------------+---------+
| net-header | payload |
+------------+---------+

+------------+-------------+---------+
| net-header | comp-header | payload |
+------------+-------------+---------+
```
In both, the 4-byte net-header consists of
```
            +------+------+------+--------+
net-header: | len0 | len1 | len2 | pkt_nr |
            +------+------+------+--------+
```
where len is the number of bytes in the the packet (including all headers), and pkt_nr is an 8-bit sequence number that increments by one for each packet.
```
             +-------+-------+-------+
comp-header: | clen0 | clen1 | clen2 |
             +-------+-------+-------+
```
where clen is the length of the packet after decompression.

Compression is negotiated in the first packet exchange.

MySQL has a virtual network I/O abstraction. This exists apparently to support SSL, but would be the right place to support GSSAPI. (See the vio directory and include/violite.h)

### Authentication
The function CLI_MYSQL_REAL_CONNECT in client.c contains all the hairy client logic to connect, authenticate and negotiate compression. On the server side, the function check_connection() in sql_parse.cc constructs the first packet and checks the reply. These are the ideal places to insert GSSAPI negotiation. Format of the first packet (server -> client)
```
28 00 00 - packet length (40 bytes)
00       - packet sequence number (first packet is 0)
0a       - protocol version (10)
332e 3233 2e35 3800 - "3.23.58\0" (server version)
c1020000 - thread ID 0x2c1 
512e 3047 565a 4277 00 - "Q.0GVZBw\0" 8-char '323' scramble code
2c20     - 2 bytes of server_capabilities (see CLIENT_* below)
0802 0000 0000 0000 0000 0000 0000 0000 
         - 16 bytes of optional capability code:
           1st byte is server language
           2nd+3rd bytes are server status word (lsb)
           rest appear reserved
xxx...   - remainder of packet is further 12 bytes of
           scramble code when 4.1 authentication is used.
```
Flags used when negotiating capabilities (capability code):

```
#define CLIENT_LONG_PASSWORD     0x0001    /* new more secure passwords */
#define CLIENT_FOUND_ROWS        0x0002    /* Found instead of affected rows */
#define CLIENT_LONG_FLAG         0x0004    /* Get all column flags */
#define CLIENT_CONNECT_WITH_DB   0x0008    /* One can specify db on connect */
#define CLIENT_NO_SCHEMA         0x0010    /* Don't allow database.table.column */
#define CLIENT_COMPRESS          0x0020    /* Can use compression protocol */
#define CLIENT_ODBC              0x0040    /* Odbc client */
#define CLIENT_LOCAL_FILES       0x0080    /* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE      0x0100    /* Ignore spaces before '(' */
#define CLIENT_PROTOCOL_41       0x0200    /* New 4.1 protocol */
#define CLIENT_INTERACTIVE       0x0400    /* This is an interactive client */
#define CLIENT_SSL               0x0800    /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE    0x1000    /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS      0x2000    /* Client knows about transactions */
#define CLIENT_RESERVED          0x4000    /* Old flag for 4.1 protocol  */
#define CLIENT_SECURE_CONNECTION 0x8000    /* New 4.1 authentication */
#define CLIENT_MULTI_STATEMENTS  0xffff    /* Enable/disable multi-stmt support */
#define CLIENT_MULTI_RESULTS    131072  /* Enable/disable multi-results */
#define CLIENT_REMEMBER_OPTIONS (((ulong) 1) << 31)
```
Format of first reply packet (client -> server)
```
if PROTOCOL_41 is *not* set:
   xxxx     - 16-bit client flag showing what options are supported
   xxxxxx   - 24-bit maximum packet size
otherwise (PROTOCOL_41):

   xxxxxxxx - 32-bit client flag showing options supported
   xxxxxxxx - 32-bit maximum packet size
   xx       - 8-bit charset selector
   pad      - 27 bytes of nul padding to make packet 32 bytes long.
```
Immediately after this packet is sent, SSL will commence (if CLIENT_SSL of the client flag is set).

(This client behaviour seems to be the same in mysql 5.0 alpha)

* The server keeps the current user & host in the THD class (see *sql/sql_class.h*)
* The ACL mechanisms provide for matching of users by wildcards. user@host. This may have to be changed if we want to specify principals (eg john@COMPANY.COM). I think the best way is to extend the GRANT ... REQUIRE syntax so that you can write
GRANT ALL PRIVILEGES ON test.* TO 'user'@'realm' REQUIRE GSSAPI;
Such user ACLs are stored in class ACL_USER in *sql/sql_acl.h*, and make use of the SSL_type enum defined in *include/violite.h*

# [Pluggable GSSAPI](#pluggable-gssapi)
PGSSAPI allows administrators to selectively plug vendor GSSAPI libraries into applications, without having to re-compile the application each time.
## What problem is this solving?
Security software such as Kerberos usually implement the standard Generic Security Services Application Programming Interface (GSSAPI) which is a high-level security interface independent of any particular security system. This is great for application writers because their product's design is not tied to any one particular security system.

However, when the product is finally compiled and distributed, it must be 'linked' to a particular GSSAPI provider library (e.g. from Heimdal, MIT Kerberos or [Quest Authentication Services (QAS)](http://www.quest.com/Authentication-Services/)). The linkage couples the deployed application to a particular vendor library making it difficult to use of any other vendor's security software either as a replacement, or in tandem.

Quest Software's Pluggable GSSAPI (PGSSAPI) library is a 'meta' GSSAPI library that simply combines and dispatches GSS operations to external GSSAPI libraries in a simple and configurable manner. PGSSAPI appears to the application as a normal GSSAPI library, so application code does not need not be modified to make use it.

## Isn't this already done by Sun's mechglue?
PGSSAPI differs from Sun's mechglue in that PGSSAPI can load and dispatch full multi-mechanism libraries, instead of to specialised single-mechanism DSOs. This means that existing vendor GSS shared libraries can be used without modification.

Unlike mechglue, PGSSAPI can dispatch GSS calls to different libraries depending on the name of the application being invoked, or other parameters. Mechglue's configuration is relatively inflexible.

PGSSAPI's design is also capable of supporting mechglue modules.

##Is PGSSAPI for application developers, or for operating system vendors?
Both. PGSSAPI was developed for two common use-cases:

* As distributable C source code that can be compiled directly into GSSAPI applications by the application developer, and controlled by application configuration data, or
* As a system-provided, dynamically-linked library under the control of the system administrator, with configuration integrated into the operating system platform.
In the event that both the system and the application use PGSSAPI, then PGSSAPI will happily nest.

# [php-vas](#php-vas)
This project is in alpha status. The following information indicates both existing and planned functionality.

*php-vas* is a connector between [PHP](http://www.php.net/), a popular web development platform, and [Quest Authentication Services (QAS)](http://www.quest.com/Authentication-Services/). *php-vas* provides a PHP interface to the Quest Authentication Services developer API that lets you build web applications that use Microsoft's Active Directory for authentication, and for querying and management of enterprise user, computer and service information.

## Supported platforms
*php-vas* is supported on all platforms that support both PHP 4 (or later) and Quest Authentication Services 3.0 (or later). These include, but are not limited to, Linux, Solaris, HP-UX and AIX.

## Documentation
Documentation for these bindings is found in .php source files used by [doxygen](http://www.stack.nl/~dimitri/doxygen/index.html). These files are included in the full php-vas source download below as well as in preformatted form for both HTML and manpage use in the documentation tarball if you cannot or do not wish to install doxygen and build the documentation yourself.

## Requirements
You will need the following:

* Some familiarity with building Linux/Unix software
* [PHP](http://www.php.net/downloads.php) and its SDK (often installed on Linux as *php-devel* or *php-dev*)
* Quest Authentication Services SDK (found on the Quest Authentication Services installation CD under the SDK directory)
* A 'C' compiler and related toolchain (gcc, make, etc.)
* [doxygen](http://www.stack.nl/~dimitri/doxygen/download.html#latestsrc) (optional)
* GNU auto tools (autoconf, automake) (optional)

The most important tool is *phpize*, found in the PHP SDK. More detailed information can found in the [README](./php-vas/README) file in the php-vas source package.

## Licensing
The php-vas bindings and their source code are licensed freely for use and modification. However, most of the module's functionality derives from [Quest Authentication Services](http://www.quest.com/Authentication-Services/), which requires separate, per-user licensing.

## Other resources
Active Directory, LDAP and PHP programming threads on [DevShed™ Forums](http://forums.devshed.com/forumdisplay.php?f=76)
