/* (c) 2006, Quest Software, Inc. All rights reserved. */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "inet_pton.h"

int
inet_pton(int af, const char *src, void *dst)
{
    in_addr_t addr;

    if (af != AF_INET) {
	errno = EAFNOSUPPORT;
	return -1;
    }
    if ((addr = inet_addr(src)) == -1)
	return 0;
    memcpy(dst, &addr, sizeof addr);
    return 1;
}
