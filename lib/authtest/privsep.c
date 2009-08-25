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
#include <pwd.h>
#include <security/pam_appl.h>
#include "authtest.h"

/*------------------------------------------------------------
 * Unprivileged process. Forks a child process, drops privileges,
 * and sets up a pipe file on which printf/scanf will work.
 * Privileged caller calls privsep_start(), and if it returns
 * true performs the unprivileged code, writes a result to the
 * privsep_pipe FILE* and then calls _exit(0). If the function
 * returns false, then the caller should read from privsep_pipe
 * (it may return EOF) and then privsep_end() to clean up.
 */

static FILE *privsep_pipe;
static pid_t privsep_child = -1;

/*
 * Forks an unprivileged subprocess.
 * Returns 1 in the unprivileged child
 * Returns 0 in the privileged parent
 * Exits on failure.
 */
int
privsep_fork(int privsep_uid)
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
	return PRIVSEP_CHILD;
    } else {
	close(pipefd[1]);
	privsep_pipe = fdopen(pipefd[0], "r");
	if (!privsep_pipe) {
	    perror("fdopen");
	    exit(1);
	}
	return PRIVSEP_PARENT;
    }
}

/* Sends a value to the privileged parent and exits */
void
privsep_exit(int ret)
{
    if (privsep_child != 0) {
	debug_err("privsep_exit not called in child");
	exit(1);
    }
    fprintf(privsep_pipe, "%u", ret);
    fclose(privsep_pipe);
    _exit(0);
}

/* Waits for the unprivileged child */
int
privsep_wait()
{
    int status, ret;

    if (fscanf(privsep_pipe, "%u", &ret) < 1) 
	ret = -1;

    if (waitpid(privsep_child, &status, 0) < 0) {
	perror("waitpid");
	exit(1);
    }
    if (WIFEXITED(status)) {
	if (WEXITSTATUS(status) != 0) 
	    debug("[unpriv child exit %d]", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status))
	debug_err("[unpriv child killed %d]", WTERMSIG(status));
    else
	debug_err("[unpriv child unknown status 0x%x]", status);
    fclose(privsep_pipe);
    debug("[ending privsep]");
    return ret;
}

/* privsep_send() */
/* privsep_recv() */
