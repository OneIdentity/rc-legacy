/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: dyn_generic.h 2265 2006-12-03 13:17:42Z rousseau $
 */

/**
 * @file
 * @brief This abstracts dynamic library loading functions.
 */

#ifndef __dyn_generic_h__
#define __dyn_generic_h__

#ifdef __cplusplus
extern "C"
{
#endif

	int DYN_LoadLibrary(void **, char *);
	int DYN_CloseLibrary(void **);
	int DYN_GetAddress(void *, void **, const char *);

#ifdef __cplusplus
}
#endif

#endif
