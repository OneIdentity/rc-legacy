/*
 * Header file for reading lexical config files.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id: configfile.h 2331 2007-01-11 16:54:51Z rousseau $
 */

#ifndef __configfile_h__
#define __configfile_h__

#ifdef __cplusplus
extern "C"
{
#endif

	int DBGetReaderList(const char *readerconf, SerialReader **caller_reader_list);

#ifdef __cplusplus
}
#endif

#endif							/* __configfile_h__ */
