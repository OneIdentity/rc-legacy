----------------------------------------------------------------
    Interoperability test programs for the Microsoft SSPI
----------------------------------------------------------------

  Quest Software, Inc.   http://rc.quest.com/topics/authtest/

Overview

  These programs can be used to:

   - test the installed authentication SSP mechanism features
   - test server "impersonation" of delegated credentials
   - test interoperability of SSPI with a GSSAPI library
   - examine and try installed security service providers

  There are two programs: a client and a server. The two authenticate to each
  other by printing BASE64-encoded "tokens" terminated by a period (.) to
  their standard output, and reading similar formatted tokens from their 
  standard input. 
  
  Typically you run each in a separate console and cut-and-paste the tokens
  from one to the other. For your convenience, the tokens are automatically
  copied into the clipboard when printed, so all you need to do is 
  right-click in each console window and choose Paste (or type Alt-Space, E, P).

  Some care has been taken with error handling, so problem diagnosis may be
  easier. 

  Authentication parameters are specified by command line options. Run 
  "client -?" or "server -?" for usage.

Requirements

  Windows XP SP2 or later.

GSSAPI interoperability 

  If you are testing GSSAPI interoperability with Java or Unix (see parent
  directory), then you should specify the "-f conf" flag to the windows 
  client or server or you will see an error about bad sequence numbers.

  Note that a GSSAPI server accepts delegated credentials automatically,
  but the Windows SSPI server process must be given "-f deleg" explicitly.

Example

  1. Start two console windows: 
       Start -> Programs -> Accessories -> Command prompt
  2. Use the CD command in each to change the working directory to where you
     copied the client.exe and server.exe executables.
  3. In one window run "client", and in the other run "server".
  4. At which ever one prints an "input:" paste the content of the clipboard
     (Right-click, Paste). That program will output a new message token (and it
     will be automatically copied into the clipboard)
  5. Change to the other window and paste that new token. That program will
     also print a new token, and put it in the clipboard.
  6. Repeat until both programs have finished.

Scope of operation

  The server first calls AcquireCredentials(), then AcceptSecurityContext().
  Similarly, the client calls AcquireCredentials() followed by
  InitializeSecurityContext(). Both repeatedly call AcceptSecurityContext() or
  InitializeSecurityContext() until an SSPI security context is negotiated.

  If credentials were delegated from client to server, the server then
  attempts to impersonate the client, by using ImpersonateSecurityContext(),
  and it displays the result security properties. It also tries to acquire
  fresh credentials as the impersonated user. Finally, it reverts the
  impersonation by calling RevertSecurityContext().
  
  With the established security context, the server then tries to send a
  message, encrypted into a token with EncryptMessage(). The client recieves
  it, decrypts it with DecryptMessage() and displays what it got. 

  Lastly, the client sends its own encrypted message to the server.

Command line options

  Both client and server take similar command-line options:

     client [-c] [-f flags] [-p pkg] [target [initiator]]
     server [-c] [-f flags] [-p pkg] [target]

     client -l
     server -l

  The target argument is the principal name that the server runs as, while
  initiator is the principal name of the client. Both default to the special
  string "NULL". "NULL" is converted to a NULL pointer before being passed
  to InitializeSecurityContext() AcceptSecurityContext(), and indicates that
  the security package should use a default principal (if any).

  The -c option enables confidentiality in packets. This is an analogue option
  for the unix client and server. Without the -c option, the fQOP parameter
  to EncryptMessage is set to SECQOP_WRAP_NO_ENCRYPT, which is effectively
  an integrity operation.

  The -f option modifies the fContextReq parameter to InitializeSecurityContext
  and AcceptSecurityContext. Please see the MSDN documentation on those
  functions for the precise meaning of the fContextReq flag.

  The -p option specifies which security package to use. You can list available
  security packages with the -l option (described next). If not specified, the 
  security package defaults to "Negotiate".

  The -l option lists the available security packages then exits. Please
  see the MSDN documentation on the SecPkgInfo structure for the meaning of
  the attributes displayed.

Related software

  An alternative and good SSPI testing tool is the "SSPI workbench".
