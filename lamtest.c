/* (c) 2006 Quest Software, Inc. All rights reserved. */
/*
 * A test program for AIX authentication and LAM modules. 
 * This simply calls the following functions in order:
 *
 *   authenticate()
 *   passwdexpired()
 *   loginrestrictions()
 *   loginsuccess()
 *
 * Usage:  lamtest [options] [username]
 *   -m mode           Specifies authentication mode (login,rlogin,su,daemon).
 *                     [The default mode is "rlogin".]
 *   -p password       Initial response to use (i.e. password).  [def: none]
 *   -l                Log result with loginsuccess/loginfailed. [no]
 *   -h hostname       Specify the hostname to log. [none]
 *   -t tty            Port (TTY) name to log. [none]
 *
 * David.Leonard@quest.com 
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/audit.h>	/* removes compiler warning from usersec.h */
#include <usersec.h>
#include <login.h>
#include <unistd.h>
#include <errno.h>
#include "authtest.h"

static char *str(const char *s);
static char *readline(const char *prompt);

/*
 * Returns a string, quoted and with control characters escaped.
 * Callers should free the result, but.. well, this is just a test program.
 */
static char *
str(s)
	const char *s;
{
	int slen;
	const char *t;
	char *s2, *t2;

	if (!s) 
	    return "NULL";
	for (t = s, slen = 0; *t; t++)
	    if (*t == '\n' || *t == '\r' || *t == '\t' || 
		*t == '\'' || *t == '\"' || *t == '\\')
			slen += 2;
	    else if (*t < '\x20' || *t >= '\x7f')
			slen += 4;
	    else
			slen++;
	s2 = malloc(slen + 3);
	t2 = s2;
	*t2++ = '\"';
	for (t = s; *t; t++)
	    switch (*t) {
		case '\n': *t2++ = '\\'; *t2++ = 'n'; break;
		case '\r': *t2++ = '\\'; *t2++ = 'r'; break;
		case '\t': *t2++ = '\\'; *t2++ = 't'; break;
		case '\'': *t2++ = '\\'; *t2++ = '\''; break;
		case '\"': *t2++ = '\\'; *t2++ = '\"'; break;
		case '\\': *t2++ = '\\'; *t2++ = '\\'; break;
		default: if (*t < '\x20' || *t >= '\x7f') {
			*t2++ = '\\';
			*t2++ = 'x';
			*t2++ = "0123456789abcdef"[(*t >> 4) & 0x0f];
			*t2++ = "0123456789abcdef"[(*t >> 0) & 0x0f];
		} else
			*t2++ = *t;
	    }
	*t2++ = '\"';
	*t2 = '\0';
	return s2;
}

/* Reads a line from stdin, strips newlines. */
static char *
readline(prompt)
	const char *prompt;
{
	char buf[1024];
	char *s;

	printf("%s", prompt);
	fflush(stdout);
	s = fgets(buf, sizeof buf, stdin);
	if (s) {
		int slen = strlen(s);
		if (slen > 0 && s[slen-1] == '\n')
			s[slen-1] = 0;
		s = strdup(s);
	}
	return s;
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	char *username = NULL;
	char *hostname = NULL;
	char *message;
	char *response = NULL;
	char *tty = NULL;
	int reenter;
	int mode = S_RLOGIN;
	int ch;
	int error = 0;
	int logresult = 0;
	int failreason = AUDIT_FAIL;
	char *nocred[] = {NULL};

        authtest_init();

	while ((ch = getopt(argc, argv, "h:lm:p:t:")) != -1)
	    switch (ch) {
	    case 'h':
		hostname = optarg;
		break;
	    case 'l':
		logresult = 1;
		break;
	    case 'm':
		if (strcmp(optarg, "login") == 0) mode = S_LOGIN;
		else if (strcmp(optarg, "su") == 0) mode = S_SU;
		else if (strcmp(optarg, "daemon") == 0) mode = S_DAEMON;
		else if (strcmp(optarg, "rlogin") == 0) mode = S_RLOGIN;
		else {
		   fprintf(stderr, 
			"error: mode must be one of: login su daemon rlogin\n");
		   error = 1;
		}
		break;
	    case 'p':
		response = optarg;	/* initial auth response */
		break;
	    case 't':
		tty = optarg;
		break;
	    default:
		error = 1;
	    }

	if (optind < argc)
	    username = argv[optind++];
	
	if (error || optind < argc) {
	    fprintf(stderr, "usage: %s [-l] [-m mode] [-p passwd]"
			    " [-t tty] [-h host] [username]\n",
		argv[0]);
	    exit(1);
	}

	if (geteuid() != 0) 
	    debug("warning: not running as root");

	if (!username) {
	    username = readline("username: ");
	    if (!username)
		exit(1);
	}

	/*
	 * 1. authenticate
	 */

	reenter = 1;
	while (reenter) {
		debug("calling authenticate(%s, %s,,)",
			str(username), response ? "<response>" : "NULL");
		error = authenticate(username, response, &reenter, &message);
		if (error) {
		    debug("  authenticate() -> %d [errno %d]", error, errno);
		    perror("authenticate");
		    failreason = AUDIT_FAIL_AUTH;
		    goto fail;
		}
		debug("  authenticate() -> %d; reenter=%d message=%s",
			error, reenter, str(message));
		if (reenter) {
		    response = getpass(message);
		    if (!response)
			goto fail;
		}
	}

	/*
	 * 2. passwdexpired
	 */

	message = NULL;
	debug("calling passwdexpired(%s,)", str(username));
	error = passwdexpired(username, &message);
	if (error == -1) {
	    debug("  passwdexpired() -> %d [errno %d]", error, errno);
	    perror("passwdexpred");
	    goto fail;
	}
        debug("  passwdexpired() -> %d [%s]", error,
	    error == 0 ? "password is valid":
	    error == 1 ? "password expired; user must change":
	    error == 2 ? "password expired; sysadmin must change":
			 "?");
	if (message) {
	    debug("  passwdexpired() return message %s", str(message));
	    printf("%s\n", message);
	}
	if (error == 1) {
	    debug("changing password");
            reenter = 1;
            response = NULL;
            while (reenter) {
                debug("calling chpass(%s, %s,,)",
			str(username), response ? "<response>" : "NULL");
		error = chpass(username, response, &reenter, &message);
		debug("  chpass() -> %d; reenter=%d message=%s",
			error, reenter, str(message));
		if (error) {
		    debug("  chpass() -> %d [errno %d]", error, errno);
                    if (error < 0) {
                        perror("chpass");
                        failreason = AUDIT_FAIL_AUTH;
                        goto fail;
                    }
                    if (error == 2) {
                        failreason = AUDIT_FAIL;
                        goto fail;
                    }
                    debug("restarting chpass loop");
                    reenter = 1;
                    response = NULL;
                    continue;
                }
		if (reenter) {
                    if (message == NULL) {
                        debug_err("Got NULL msg from chpass()");
                        continue;
                    }
		    response = getpass(message);
		    if (!response)
			goto fail;
		}
            }
	} else if (error == 2) {
	    debug("Exiting because password expired and unchangable");
	    exit(0);
	}

	/*
	 * 3. loginrestrictions
	 */

	message = NULL;
	debug("calling loginrestrictions(%s, %s, %s, )",
		str(username),
		mode == S_LOGIN ? "S_LOGIN" :
		mode == S_SU ? "S_SU" : 
		mode == S_DAEMON ? "S_DAEMON" : 
		mode == S_RLOGIN ? "S_RLOGIN" : 
		"?",
		str(tty));
	error = loginrestrictions(username, mode, tty, &message);
	if (error != 0) {
		debug("  loginrestrictions() -> %d [errno %d]", error, errno);
		if (message) {
		    debug("  loginrestrictions returns message %s",
			str(message));
		    fprintf(stderr, "Login restricted: %s\n", message);
		}
		perror("loginrestrictions");
		goto fail;
	}
	debug("  loginrestrictions() -> %d [success]", error);

	/*
	 * 4. loginsuccess
	 */

	printf("Authenticated as %s\n", str(username));

	if (logresult) {
	    debug("calling loginsuccess(%s, %s, %s,)",
		str(username), str(hostname), str(tty));
	    message = NULL;
	    error = loginsuccess(username, hostname, tty, &message);
	    if (error != 0) {
		debug("  loginsuccess() -> %d [errno %d]", error, errno);
		perror("loginsuccess");
		exit(1);
	    }
	    debug("  loginsuccess() -> %d [success]", error);
	    if (message) {
		debug("  loginsuccess returned message %s", str(message));
	        printf("%s\n", message);
	    }
	}

#if 0
	/*
	 * 5. setpcred
	 */

	debug("calling setpcred(%s, [])", str(username));
	error = setpcred(username, nocred);
	if (error != 0) {
	    debug("  setpcred() -> %d [errno %d]", error, errno);
	    perror("setpcred");
	} else
	    debug("  setpcred() -> %d [success]", error);
#endif

	exit(0);

fail:
	/*
	 * 6. loginfailed
	 */

	if (logresult) {
	    debug("calling loginfailed(%s, %s, %s, %s)",
		str(username), str(hostname), str(tty),
		failreason == AUDIT_FAIL ? "AUDIT_FAIL" : 
		failreason == AUDIT_FAIL_AUTH ? "AUDIT_FAIL_AUTH" : 
		"?");
	    error = loginfailed(username, hostname, tty, failreason);
	    if (error) {
		    debug("  loginfailed() -> %d [errno %d]",
			error, errno);
		    perror("loginfailed");
	    } else
		debug("  loginfailed() -> %d [success]", error);
	}
	exit(1);
}
