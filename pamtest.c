/* (c) 2006 Quest Software, Inc. All rights reserved. */
/*
 * Pam testing tool
 * David Leonard
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <security/pam_appl.h>
#include "authtest.h"

/*-----------------------------------
 * PEM error codes
 */
#define ERRDECL(n) { n, #n }
static struct err { 
    int error; const char *desc; 
} errors[] = {
    ERRDECL(PAM_SUCCESS),
    ERRDECL(PAM_OPEN_ERR),
    ERRDECL(PAM_SYMBOL_ERR),
    ERRDECL(PAM_SERVICE_ERR),
    ERRDECL(PAM_SYSTEM_ERR),
    ERRDECL(PAM_BUF_ERR),
    ERRDECL(PAM_CONV_ERR),
    ERRDECL(PAM_PERM_DENIED),
    ERRDECL(PAM_MAXTRIES),
    ERRDECL(PAM_AUTH_ERR),
    ERRDECL(PAM_NEW_AUTHTOK_REQD),
    ERRDECL(PAM_CRED_INSUFFICIENT),
    ERRDECL(PAM_AUTHINFO_UNAVAIL),
    ERRDECL(PAM_USER_UNKNOWN),
    ERRDECL(PAM_CRED_UNAVAIL),
    ERRDECL(PAM_CRED_EXPIRED),
    ERRDECL(PAM_CRED_ERR),
    ERRDECL(PAM_ACCT_EXPIRED),
    ERRDECL(PAM_AUTHTOK_EXPIRED),
    ERRDECL(PAM_SESSION_ERR),
    ERRDECL(PAM_AUTHTOK_ERR),
    ERRDECL(PAM_AUTHTOK_LOCK_BUSY),
    ERRDECL(PAM_AUTHTOK_DISABLE_AGING),
    ERRDECL(PAM_NO_MODULE_DATA),
    ERRDECL(PAM_IGNORE),
    ERRDECL(PAM_ABORT),
    ERRDECL(PAM_TRY_AGAIN),
    { -1, NULL }
};

/* Standout codes to distinguish PAM conversation from debugging */

char **responses;

/*------------------------------------------------------------
 * getpass()
 * 
 * On some platforms, getpass() is totally broken.
 */
#if __hpux
# define getpass mygetpass
#include <termios.h>

struct termios gp_tsave;
void (*gp_ssave)(int);

void
gp_restore()
{
    tcsetattr(fileno(stdin), TCSADRAIN, &gp_tsave);
    (void)signal(SIGINT, gp_ssave);
}

void
gp_sigint(int sig)
{
    gp_restore();
    kill(getpid(), SIGINT);
}

void
gp_noecho()
{
    struct termios tnew;

    if ((gp_ssave = signal(SIGINT, gp_sigint)) == SIG_ERR) {
	perror("signal");
	exit(1);
    }
    tcgetattr(fileno(stdin), &gp_tsave);
    memcpy(&tnew, &gp_tsave, sizeof tnew);
    tnew.c_lflag &= ~(ECHO|ISIG);
    tcsetattr(fileno(stdin), TCSADRAIN, &tnew);
}

char *
getpass(char *prompt)
{
    static char buf[256];
    char *s;

    printf("%s", prompt);
    fflush(stdout);
    gp_noecho();
    s = fgets(buf, sizeof buf, stdin);
    gp_restore();
    putchar('\n');
    return s;
}

#endif

/*------------------------------------------------------------
 * Unprivileged process. Forks a child process, drops privileges,
 * and sets up a pipe file on which printf/scanf will work.
 * Privileged caller calls privsep_start(), and if it returns
 * true performs the unprivileged code, writes a result to the
 * privsep_pipe FILE* and then calls _exit(0). If the function
 * returns false, then the caller should read from privsep_pipe
 * (it may return EOF) and then privsep_end() to clean up.
 */
#include <sys/types.h>
#include <signal.h>

FILE *privsep_pipe;
pid_t privsep_child;
uid_t privsep_uid = 1;

int
privsep_start()
{
    int pipefd[2];

    if (pipe(pipefd) < 0) {
	perror("pipe");
	exit(1);
    }
/*    if (signal(SIGCHLD, SIG_IGN) < 0)
	perror("signal"); */

    debug("[starting privsep]");
    if ((privsep_child = fork()) < 0) {
	perror("fork");
	exit(1);
    }
    if (privsep_child == 0) {
	close(pipefd[0]);
	privsep_pipe = fdopen(pipefd[1], "w");
	if (!privsep_pipe) {
	    perror("fdopen");
	    exit(1);
	}
	if (setreuid(privsep_uid, privsep_uid) < 0)
	    perror("setreuid");
	debug("[uid=%d euid=%d]", getuid(), geteuid());
	return 1;
    } else {
	close(pipefd[1]);
	privsep_pipe = fdopen(pipefd[0], "r");
	if (!privsep_pipe) {
	    perror("fdopen");
	    exit(1);
	}
	return 0;
    }
}

void
privsep_end()
{
    int status;

    if (privsep_child == 0) {
	fclose(privsep_pipe);
	_exit(0);
    } else {
	if (waitpid(privsep_child, &status, 0) < 0) {
	    perror("waitpid");
	    exit(1);
	}
	debug("[ending privsep]");
	if (WIFEXITED(status)) {
	    if (WEXITSTATUS(status) != 0) 
		fprintf(stderr, "[unpriv child exit %d]\n", 
			WEXITSTATUS(status));
	} else if (WIFSIGNALED(status))
	    fprintf(stderr, "[unpriv child killed %d]\n", WTERMSIG(status));
	else
	    fprintf(stderr, "[unpriv child unknown status]\n");
    }
    fclose(privsep_pipe);
}


/*------------------------------------------------------------
 * PAM logging and error printing
 */

/* Returns the string representation of a PAM error code */
static const char *
mypam_strerror(pam_handle_t *pamh, int error) {
    struct err *err;
    static char sbuf[128];
    for (err = errors; err->desc; err++)
	if (err->error == error)
	    return err->desc;
    snprintf(sbuf, sizeof sbuf, "error %d\n", error);
    return sbuf;
}

static void
mypam_log1(const char *expr)
{
    fprintf(stderr, "%s[%s: %s", col_SO, expr, col_SE);
}
static int
mypam_log2(pam_handle_t *pamh, int result)
{
    fprintf(stderr, "%s-> %s]%s\n", col_SO,
            mypam_strerror(pamh, result), col_SE);
    return result;
}

#define LOG(pamh, pamexpr) (mypam_log1(#pamexpr), mypam_log2(pamh, pamexpr))

/* Invoke a PAM function, and die unless it is the expected result */
#define CHECK_EXPECT(pamh, pamexpr, expectedresult) do { \
    int pam_err; \
    pam_err = LOG(pamh, pamexpr); \
    if (pam_err != (expectedresult)) { \
	debug_err("[" __FILE__ ":%d: " #pamexpr \
		" did not return %s]", __LINE__, \
                mypam_strerror(pamh, expectedresult)); \
	exit(1); \
    } \
} while(0)

#define CHECK(pamh, pamexpr) CHECK_EXPECT(pamh, pamexpr, PAM_SUCCESS)

#if __sun__ || __hpux
# define ITEM_TYPE void **
#else
# define ITEM_TYPE const void **
#endif

#define GETITEM(pamh, item_type) do { \
    char *value = NULL; \
    int pam_err; \
    fprintf(stderr, "%s item %s = ", col_SO, #item_type); \
    pam_err = pam_get_item(pamh, item_type, (ITEM_TYPE)&value); \
    if (pam_err == PAM_SUCCESS) { \
       if (value) \
           fprintf(stderr, "'%s'%s\n", value, col_SE); \
       else \
           fprintf(stderr, "(null)%s\n", col_SE); \
    } else \
       fprintf(stderr, "error: %s%s\n", mypam_strerror(pamh, pam_err), \
               col_SE); \
} while (0)

/*------------------------------------------------------------
 * Generalised PAM conversation function
 */
int
convfn(int n, struct pam_message **m, struct pam_response **r, void *data)
{
    int i, l;
    char buf[1024], *s;

    /* fprintf(stderr, "conv: m=%p r=%p *r=%p\n", m, r, r?*r:0); */
    debug("[conversation start, %d message%s]",  n, n == 1 ? "" : "s");

    /* I hope someone frees this */
    *r = (struct pam_response *)malloc(n * sizeof (struct pam_response));

    for (i = 0; i < n; i++) {
	switch (m[i]->msg_style) {
	    case PAM_PROMPT_ECHO_OFF:
		debug("{style=prompt_echo_off}");
		if (responses && *responses) {
		    s = *responses++;
		    printf("%s%s%s%s\n", m[i]->msg, 
                            col_SO_INP, s, col_SE);
		} else
		    s = getpass(m[i]->msg);
		if (!s) { fprintf(stderr, "eof from getpass()\n"); exit(1); }
		r[i]->resp = strdup(s);
		break;
	    case PAM_PROMPT_ECHO_ON:
		debug("{style=prompt_echo_on}%s", m[i]->msg);
		if (responses && *responses) {
		    s = *responses++;
		    printf("%s%s%s\n", col_SO_INP, s, col_SE);
		} else
		    s = fgets(buf, sizeof buf, stdin);
		if (!s) { fprintf(stderr, "eof from fgets()\n"); exit(1); }
		l = strlen(s);
		r[i]->resp = strdup(s);
		if (l > 0 && s[l-1] == '\n')
		    r[i]->resp[l-1] = '\0';
		break;
	    case PAM_ERROR_MSG:
		debug("{style=error_msg}");
                printf("%s\n", m[i]->msg);
		break;
	    case PAM_TEXT_INFO:
		debug("{style=text_info}");
                printf("%s\n", m[i]->msg);
		break;
	    default:
		fprintf(stderr, "Bad conversation message style %d\n",
				m[i]->msg_style);
		exit(1);
	}
    }
    debug("[conversation end]");
    return PAM_SUCCESS;
}

/*------------------------------------------------------------
 * main
 */

int
main(int argc, char *argv[])
{
    int ch;
    int error = 0;
    const char *name = "pamtest";
    const char *user = NULL;
    pam_handle_t *pamh;
    struct pam_conv conv = { convfn,  NULL };
    int sflag = 0;
    int rflag = 0;
    int pflag = 0;

    authtest_init();

    while ((ch = getopt(argc, argv, "n:p:rsu:")) != -1) 
	switch (ch) {
	    case 'n': name = optarg; break;
	    case 'p': privsep_uid = atoi(optarg); 
		      pflag = 1; break;
	    case 's': sflag = 1; break;  /* skip authentication */
	    case 'u': user = optarg; break;
	    case 'r': rflag = 1; break;
	    default: error = 1;
	}
    if (!rflag && argc != optind)
	error = 1;
    if (error) {
	fprintf(stderr, 
		"usage: %s [-s] [-n appname] [-p uid] [-u user] "
		"[-r resp ...]\n",
		argv[0]);
	exit(1);
    }
    if (rflag)
	responses = argv + optind;

    if (geteuid() != 0)
	debug("Warning: unprivileged (euid=%d)", geteuid());

    debug("[user=%s]", user ? user : "(null)");
    debug("[name=%s]", name);

    pamh = NULL;
    CHECK(pamh, pam_start(name, user, &conv, &pamh));

    if (pflag && !privsep_start()) {
	int ok;
	if (fscanf(privsep_pipe, "%u", &ok) < 1) 
	    ok = -1;
	privsep_end();
	if (ok != 1) {
	    fprintf(stderr, "[unpriv child failed: %d]\n", ok);
	    exit(1);
	}
	goto end_privsep;
    }

    if (sflag)
	debug("[-s: skipping pam_authenticate]");
    else
	CHECK(pamh, pam_authenticate(pamh, 0));
    error = LOG(pamh, pam_acct_mgmt(pamh, 0));
    if (error == PAM_NEW_AUTHTOK_REQD)
	CHECK(pamh, pam_chauthtok(pamh, 0));
    else if (error != PAM_SUCCESS)
	exit(1);
    if (pflag) {
	fprintf(privsep_pipe, "1");
	privsep_end();
    } 

end_privsep:

    CHECK(pamh, pam_open_session(pamh, 0));

    debug("session opened");

    GETITEM(pamh, PAM_USER);
    GETITEM(pamh, PAM_SERVICE);
    GETITEM(pamh, PAM_TTY);
    GETITEM(pamh, PAM_RHOST);

    CHECK(pamh, pam_close_session(pamh, 0));
    CHECK(pamh, pam_end(pamh, PAM_SUCCESS));

    exit(0);
}
