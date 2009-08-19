
This is a Windows client for SSPI.  It requires Windows XP SP2 or later.

It comes in two parts: a client and a server. The two communicate via Base64-encoded tokens on their standard input and output.
The intention is that you cut-and-paste the tokens yourself.  Actually, whenever a set of tokens is printed by either client.exe or server.exe, the token is also 'Copied' into the system clipboard, so you can right-click in a command window and choose Paste.

If you are testing compatibility with the GSSAPI implementations for Java or Uunix, then you will need to specify the "-f conf" flag.

For another good SSPI testing tool find the "SSPI workbench", which is mirrored on the internet.
