
#if HAVE_CONFIG_H
#include <config.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "wait4.h"

#if !HAVE_WAIT4 && HAVE_WAITPID && HAVE_GETRUSAGE
pid_t
wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
    int error;
    pid_t rpid;

    rpid = waitpid(pid, status, options);
    if (rpid == -1)
	return (-1);
    error = getrusage(RUSAGE_CHILDREN, rusage);
    if (error)
	return (-1);
    return rpid;
}
#endif
