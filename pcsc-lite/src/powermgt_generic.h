/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2002
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: powermgt_generic.h 2151 2006-09-06 20:02:47Z rousseau $
 */

/**
 * @file
 * @brief This handles power management routines.
 */

#ifndef __powermgt_generic_h__
#define __powermgt_generic_h__

#ifdef __cplusplus
extern "C"
{
#endif


/*
 * Registers for Power Management callbacks
 */

ULONG PMRegisterForPowerEvents(void);


#ifdef __cplusplus
}
#endif

#endif
