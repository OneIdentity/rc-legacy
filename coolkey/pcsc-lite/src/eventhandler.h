/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2004
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: eventhandler.h 2544 2007-05-23 14:19:45Z rousseau $
 */

/**
 * @file
 * @brief This handles card insertion/removal events, updates ATR,
 * protocol, and status information.
 */

#ifndef __eventhandler_h__
#define __eventhandler_h__

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Define an exported public reader state structure so each
	 * application gets instant notification of changes in state.
	 */
	typedef struct pubReaderStatesList
	{
		LONG readerID;
		char readerName[MAX_READERNAME];
		DWORD readerState;
		LONG readerSharing;
		DWORD dummy;

		UCHAR cardAtr[MAX_ATR_SIZE];
		DWORD cardAtrLength;
		DWORD cardProtocol;
	}
	READER_STATE, *PREADER_STATE;

	LONG EHInitializeEventStructures(void);
	LONG EHSpawnEventHandler(PREADER_CONTEXT);
	LONG EHDestroyEventHandler(PREADER_CONTEXT);

#ifdef __cplusplus
}
#endif

#endif							/* __eventhandler_h__ */
