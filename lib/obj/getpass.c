/* (c) 2006 Quest Software, Inc. All rights reserved. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

/* Redefine getpass so that system declarations are ignored */
#define getpass getpass_ignored

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <termios.h>

#undef getpass

/* 
 * On some platforms, getpass() is missing or totally broken.
 */

static struct termios gp_tsave;
static void (*gp_ssave)(int);

static void
gp_restore()
{
    tcsetattr(fileno(stdin), TCSADRAIN, &gp_tsave);
    (void)signal(SIGINT, gp_ssave);
}

static void
gp_sigint(int sig)
{
    gp_restore();
    kill(getpid(), SIGINT);
}

static void
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
    if (s && *s) {
	int len = strlen(s);
	if (s[len - 1] == '\n')
	    s[len - 1] = 0;
    }
    return s;
}
