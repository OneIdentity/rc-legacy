/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2003
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: powermgt_generic.c 2261 2006-12-02 17:27:10Z rousseau $
 */

/**
 * @file
 * @brief This handles power management routines.
 */

#include "config.h"
#include "pcsclite.h"
#include "powermgt_generic.h"

/*
 * Check for platforms that have their own specific support.
 * It's more easy and flexible to do it here, rather than
 * with automake conditionals in src/Makefile.am.
 * No, it's still not a perfect solution design wise.
 */

#if !defined(__APPLE__)

ULONG PMRegisterForPowerEvents(void)
{
  return 0;
}

#endif
