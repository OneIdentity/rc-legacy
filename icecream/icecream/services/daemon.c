
#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include "daemon.h"

#if !HAVE_DAEMON
int
daemon (int nochdir, int noclose)
{
  int fd;

  switch ( fork() ) {
  case -1:
    return (-1);
  case 0:
    break;
  default:
    _exit(0);
  }

  if (setsid() == -1)
    return (-1);

  if (!nochdir)
    (void)chdir("/");

  if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) 
    {
      (void)dup2(fd, 0);
      (void)dup2(fd, 1);
      (void)dup2(fd, 2);
      if (fd > 2)
	(void)close (fd);
    }
  return (0);
}
#endif
