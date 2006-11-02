/* GDM - The Gnome Display Manager
 * Copyright (C) 1999, 2000 Martin K. Petersen <mkp@mkp.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_appl.h>

#include <winscard.h>

#include <gdm_prompt_plugin.h>
#include <gdm_prompt_config.h>

#define GET_FUNCTIONS_SYM    "C_GetFunctionList"

/* Copied from gdm.h */
#define STX 0x2                 /* Start of txt */

#ifndef NDEBUG 
#define log(format, args...) \
        syslog(LOG_DEBUG, "[GDM_PROMPT_PKCS11] " format , ##args)
#else
#define log(format, args...) 
#endif

/** Structure containing functions from PC/SC API */
typedef struct {
    /* Creates a communication context to the PC/SC Resource Manager */
    LONG (*SCardEstablishContext)(DWORD dwScope,
                                  LPCVOID pvReserved1,
                                  LPCVOID pvReserved2,
                                  LPSCARDCONTEXT phContext);

    /* List the available readers */
    LONG (*SCardListReaders)(SCARDCONTEXT hContext,
                             LPCTSTR mszGroups,
                             LPTSTR mszReaders,
                             LPDWORD pcchReaders);

    /* Wait for status change in readers */
    LONG (*SCardGetStatusChange)(SCARDCONTEXT hContext,
                                 DWORD dwTimeout,
                                 LPSCARD_READERSTATE_A rgReaderStates,
                                 DWORD cReaders);

    /* Cancel a PC/SC operation */
    LONG (*SCardCancel)(SCARDCONTEXT hContext);

    /* Destroys a communication context to the PC/SC Resource Manager */
    LONG (*SCardReleaseContext)(SCARDCONTEXT hContext);
} SCardFunctionList;

typedef struct {
  SCardFunctionList fns;  /**< The PC/SC function list */
  SCARDCONTEXT hContext;  /**< PC/SC context handle */
  int prompt_type;        /**< The PAM prompt type */
  int _running;           /**< Should PC/SC thread keep running? */
  pthread_mutex_t mutex;  /**< Mutex for accessing flags */
  const char *reader;     /**< Reader (if any) to watch */
} pcsc_data_t;

static pthread_t G_thread = (pthread_t) 0;

/** Determine if PC/SC thread should keep running */
static int pcsc_thread_running(pcsc_data_t *pcsc)
{
    int running;

    pthread_mutex_lock(&pcsc->mutex);
    running = pcsc->_running;
    pthread_mutex_unlock(&pcsc->mutex);

    return running;
}

/** Start the PC/SC thread */
static void pcsc_thread_start(pcsc_data_t *pcsc)
{
    pthread_mutex_lock(&pcsc->mutex);
    pcsc->_running = 1;
    pthread_mutex_unlock(&pcsc->mutex);
}

/** Stop the PC/SC thread */
static void pcsc_thread_stop(pcsc_data_t *pcsc)
{
    pthread_mutex_lock(&pcsc->mutex);
    pcsc->_running = 0;
    pthread_mutex_unlock(&pcsc->mutex);
}

/** Initialize the PC/SC library */
static LONG pcsc_lib_initialize(pcsc_data_t *pcsc)
{
    LONG rv = SCARD_S_SUCCESS;

    pthread_mutex_lock(&pcsc->mutex);
    if (pcsc->_running && pcsc->hContext == 0)
    {
        rv = pcsc->fns.SCardEstablishContext(SCARD_SCOPE_USER,
                                             NULL,
                                             NULL,
                                             &pcsc->hContext);
    }
    pthread_mutex_unlock(&pcsc->mutex);

    return rv;
}

/** Finalize the PC/SC library */
static void pcsc_lib_finalize(pcsc_data_t *pcsc)
{
    pthread_mutex_lock(&pcsc->mutex);
    if (pcsc->_running && pcsc->hContext != 0)
    {
        pcsc->fns.SCardCancel(pcsc->hContext);
        pcsc->fns.SCardReleaseContext(pcsc->hContext);
        pcsc->hContext = 0;
    }
    pthread_mutex_unlock(&pcsc->mutex);
}

/** Get specified symbol from the module
 *
 * @param module the module loaded via dlopen(). Must not be NULL.
 *
 * @param name the name of the symbol to obtain friom the module. Must
 * not be NULL.
 *
 * @param p_symbol pointer to hold the symbol found in the module. Must
 * not be NULL.
 *
 * @return 1 if the symbol was obtained, 0 otherwise.
 */
static int get_symbol(void *module, const char *name, void **p_symbol)
{
    void *symbol = NULL;

    if ((symbol = dlsym(module, name)) == NULL)
    {
        log("Failed to load symbol '%s'", name);
        return 0;
    }

    *p_symbol = symbol;

    return 1;
}

static int configure_pcsc(pcsc_data_t *pcsc)
{
    const char *lib = NULL;
    const char *reader = NULL;
    void *handle = NULL;
    int rval = 1;

    log("Getting config from file '%s'", PCSC_PLUGIN_CONFIG_FILE);

    /* Get the PC/SC library from the configuration */
    lib = gdm_prompt_config_get_string(PCSC_PLUGIN_CONFIG_FILE,
                                       "pcsc/library");
    if (lib == NULL || strcmp(lib, "") == 0)
    {
        log("No PC/SC library defined");
        rval = 1;
        goto FINISH;
    }

    /* Load the library */
    dlerror();
    if ((handle = dlopen(lib, RTLD_NOW)) == NULL)
    {
        log("Failed to load PC/SC library '%s': %s", lib, dlerror());
        goto FINISH;
    }
    log("Loaded token library '%s'", lib);

    /* Get the functions from the library */
    if (!get_symbol(handle, "SCardEstablishContext",
                    (void **) &pcsc->fns.SCardEstablishContext) ||
        !get_symbol(handle, "SCardReleaseContext",
                    (void **) &pcsc->fns.SCardReleaseContext) ||
        !get_symbol(handle, "SCardCancel",
                    (void **) &pcsc->fns.SCardCancel) ||
        !get_symbol(handle, "SCardListReaders",
                    (void **) &pcsc->fns.SCardListReaders) ||
        !get_symbol(handle, "SCardGetStatusChange",
                    (void **) &pcsc->fns.SCardGetStatusChange))
    {
        goto FINISH;
    }

    /* Check if a reader has been specified */
    reader = gdm_prompt_config_get_string(PCSC_PLUGIN_CONFIG_FILE,
                                          "pcsc/reader");
    if (reader != NULL)
    {
        /* Copy the reader name */
        if ((pcsc->reader = strdup(reader)) == NULL)
        {
            log("Memory error copying reader name");
            goto FINISH;
        }
    }

    /* Success */
    rval = 0;

FINISH:
    /* Clean up on error */
    if (rval != 0 && handle != NULL)
    {
        dlclose(handle);
    }

    return rval;
}

static void pcsc_data_free(pcsc_data_t *pcsc)
{
    if (pcsc != NULL)
    {
        if (pcsc->reader != NULL)
        {
            free((void *) pcsc->reader);
        }
        pthread_mutex_destroy(&pcsc->mutex);
        free(pcsc);
    }
}

static pcsc_data_t *pcsc_data_alloc(void)
{
    pcsc_data_t *pcsc = NULL;

    if ((pcsc = calloc(1, sizeof(*pcsc))) == NULL)
    {
        log("Memory allocation failure");
        goto FINISH;
    }
    pthread_mutex_init(&pcsc->mutex, NULL);

    if (configure_pcsc(pcsc) != 0)
    {
        pcsc_data_free(pcsc);
        pcsc = NULL;
        goto FINISH;
    }


FINISH:
    return pcsc;

}

#define IS_SET(state,flag) (((state) & (flag)) == (flag))

static char *get_state_string(int state)
{
    char buf[256];
    char *s = buf;

    sprintf(s, "{");
    if (IS_SET(state, SCARD_STATE_IGNORE)) { s = strcat(s, " IGNORE"); }
    if (IS_SET(state, SCARD_STATE_CHANGED)) { s = strcat(s, " CHANGED"); }
    if (IS_SET(state, SCARD_STATE_UNKNOWN)) { s = strcat(s, " UNKNOWN"); }
    if (IS_SET(state, SCARD_STATE_UNAVAILABLE)) { s = strcat(s, " UNAVAILABLE"); }
    if (IS_SET(state, SCARD_STATE_EMPTY)) { s = strcat(s, " EMPTY"); }
    if (IS_SET(state, SCARD_STATE_PRESENT)) { s = strcat(s, " PRESENT"); }
    if (IS_SET(state, SCARD_STATE_ATRMATCH)) { s = strcat(s, " ATRMATCH"); }
    if (IS_SET(state, SCARD_STATE_EXCLUSIVE)) { s = strcat(s, " EXCLUSIVE"); }
    if (IS_SET(state, SCARD_STATE_INUSE)) { s = strcat(s, " INUSE"); }
    if (IS_SET(state, SCARD_STATE_MUTE)) { s = strcat(s, " MUTE"); }
    if (IS_SET(state, SCARD_STATE_UNPOWERED)) { s = strcat(s, " UNPOWERED"); }
    s = strcat(s, " }");

    return ((s = strdup(s)) != NULL) ? s : "<unknown>";
}

static int
GetReaderListInfo (pcsc_data_t *pcsc,
                   char **pReaderList,
                   unsigned long *pReaderListSize,
                   int *pReaderCount,
                   SCARD_READERSTATE **pStates)
{
    char *szReaderList = NULL;
    unsigned long ReaderListSize = 0;
    int iReaderCount = 0;
    SCARD_READERSTATE *ReaderStates = NULL;

    long lRetVal = 0;
    char *TempReaderList = NULL;

    int i;

    if (pcsc == NULL || pcsc->hContext == 0)
    {
        return -1;
    }

    /* Waiting for reader availability */
    log("Waiting for status change ...");
    lRetVal = pcsc->fns.SCardGetStatusChange(pcsc->hContext, 
                                             INFINITE , 
                                             NULL, 
                                             0);
    if ( lRetVal != SCARD_S_SUCCESS )
    {
        log("SCardGetStatusChange() failed: 0x%04lX", lRetVal);
        return -1;
    }

    /* Timed out */
    if (!pcsc_thread_running(pcsc))
    {
        /* Don't worry, we are exiting in the caller */
        return -2;
    }


    /* We have reader.  Get reader list size now. */
    ReaderListSize = 0;
    lRetVal = pcsc->fns.SCardListReaders(pcsc->hContext, 
                                         NULL, 
                                         NULL, 
                                         &ReaderListSize);
    if(lRetVal != SCARD_S_SUCCESS)
        return -1;

    szReaderList = malloc (ReaderListSize * sizeof (char));
    memset (szReaderList, 0, (ReaderListSize * sizeof (char)));
    lRetVal = pcsc->fns.SCardListReaders (pcsc->hContext, 
                                          NULL, 
                                          szReaderList, 
                                          &ReaderListSize);
    if (lRetVal != SCARD_S_SUCCESS)
    {
        /* hmm. readers list has changed too fast ?! */
        free (szReaderList);
        return -1;
    }

    TempReaderList = szReaderList;
    iReaderCount = 0;
    while (TempReaderList[0] != '\0')
    {
        iReaderCount++;
        TempReaderList += strlen (TempReaderList) + 1;
    }

    log("There are %d readers available", iReaderCount);

    ReaderStates = (SCARD_READERSTATE *) malloc (sizeof (SCARD_READERSTATE) *
        iReaderCount);
    memset (ReaderStates, 0, sizeof (SCARD_READERSTATE) * iReaderCount);
    TempReaderList = szReaderList;
    for (i = 0;
        i < iReaderCount;
        i++, TempReaderList += strlen (TempReaderList) + 1)
    {
        ReaderStates[i].szReader = TempReaderList;
        ReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
        ReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
    }

    *pReaderList = szReaderList;
    *pReaderListSize = ReaderListSize;
    *pReaderCount = iReaderCount;
    *pStates = ReaderStates;

    return 0;
}

static int
CompareReaderList ( char *szReaderList1,
                   int nLength1,
                   char *szReaderList2,
                   int nLength2 )
{


    if(nLength1 == 0 || nLength2 == 0 || nLength1 != nLength2 )
        return -1;

    if (szReaderList1 == NULL && szReaderList2 == NULL)
        return 0;

    if (szReaderList1 != NULL && szReaderList2 == NULL)
        return 1;

    if (szReaderList1 == NULL && szReaderList2 != NULL)
        return -1;

    return memcmp( szReaderList1, szReaderList2, nLength1 );
}

static int
UpdateReaderStates (SCARD_READERSTATE *pReaderStates,
                    int ReaderCount,
                    SCARD_READERSTATE *pCurrentReaderStates,
                    int CurrentReaderCount)
{
    int i = 0;
    int j = 0;

    if (pReaderStates == NULL || pCurrentReaderStates == NULL)
        return -1;

    for (i = 0; i < ReaderCount; i++)
    {
        for (j = 0; j < CurrentReaderCount; j++)
        {
            if (strcmp (pReaderStates[i].szReader, pCurrentReaderStates[j].szReader) == 0)
            {
                pReaderStates[i].dwCurrentState = pCurrentReaderStates[j].dwCurrentState;
                pReaderStates[i].dwEventState = pCurrentReaderStates[j].dwEventState;
                break;
            }
        }
    }

    return 0;
}

static int notify_token_inserted(pcsc_data_t *pcsc, const char *name)
{
    int rval = 0;

    log("Token inserted into reader '%s'", name);

    /* Check that reader is suitable */
    if (pcsc->reader != NULL && strcmp(pcsc->reader, name) != 0)
    {
        log("Ignoring event: required reader is '%s'", pcsc->reader);
        goto FINISH;
    }

    /* Check that prompt type is suitable */
    if (pcsc->prompt_type != PAM_PROMPT_ECHO_ON)
    {
        log("Ignoring insertion events");
        goto FINISH;
    }

    /* Write empty string to stdout */
    printf("%c\n", STX);
    fflush(stdout);

    /* Success */
    rval = 1;

FINISH:
    return rval;
}

static int notify_token_removed(pcsc_data_t *pcsc, const char *name)
{
    int rval = 0;

    log("Token removed from reader '%s'", name);

    /* Check that reader is suitable */
    if (pcsc->reader != NULL && strcmp(pcsc->reader, name) != 0)
    {
        log("Ignoring event: required reader is '%s'", pcsc->reader);
        goto FINISH;
    }

    /* Check that prompt type is suitable */
    if (pcsc->prompt_type != PAM_PROMPT_ECHO_OFF)
    {
        log("Ignoring removal events");
        goto FINISH;
    }

    /* Write empty string to stdout */
    printf("%c\n", STX);
    fflush(stdout);

    /* Success */
    rval = 1;

FINISH:
    return rval;
}

static void *monitor_pcsc_thread(void *p)
{
    char *szMasterReaderList = NULL;
    unsigned long MasterReaderListSize = 0;
    int iMasterReaderCount = 0;
    SCARD_READERSTATE *pMasterStates = NULL;

    char *szReaderList = NULL;
    unsigned long ReaderListSize = 0;
    int iReaderCount = 0;
    SCARD_READERSTATE *pStates = NULL;

    int i;

    LONG lRetVal;
    int ExitVal = 0;
    pcsc_data_t *pcsc = NULL;

    pcsc = (pcsc_data_t *) p;

    log("Starting PC/SC thread, event = %s",
        (pcsc->prompt_type == PAM_PROMPT_ECHO_ON)
            ? "token insertion"
            : "token removal");

    /* Initialize the PC/SC context */
    if ((lRetVal = pcsc_lib_initialize(pcsc)) != SCARD_S_SUCCESS)
    {
        goto FINISH;
    }

    if (GetReaderListInfo(pcsc, 
                          &szMasterReaderList,
                          &MasterReaderListSize,
                          &iMasterReaderCount,
                          &pMasterStates) != 0)
    {
        pcsc->fns.SCardReleaseContext(pcsc->hContext);
        goto FINISH;
    }

    /* Loop until told to stop, or matching token event occurs */
    while (pcsc_thread_running(pcsc))
    {
        log("Waiting on status change ...");
        lRetVal = pcsc->fns.SCardGetStatusChange (pcsc->hContext, 
                                                  INFINITE,
                                                  pMasterStates, 
                                                  iMasterReaderCount);
        if (lRetVal != SCARD_S_SUCCESS)
        {
            log("SCardGetStatusChange() failed: 0x%0lX", lRetVal);
        }

        if (lRetVal == SCARD_E_INVALID_VALUE ||
            lRetVal == SCARD_E_INVALID_HANDLE ||
            lRetVal == SCARD_E_READER_UNAVAILABLE)
        {
            ExitVal = 4;
            break;
        }

        if (lRetVal == SCARD_S_SUCCESS)
        {
            for (i = 0; i < iMasterReaderCount; i++)
            {
                log("reader %s:", pMasterStates[i].szReader);
                log("  current state = %s",
                    get_state_string(pMasterStates[i].dwCurrentState));
                log("  event state   = %s",
                       get_state_string(pMasterStates[i].dwEventState));

                if ((pMasterStates[i].dwEventState &
                    (SCARD_STATE_CHANGED | SCARD_STATE_PRESENT)) ==
                    (SCARD_STATE_CHANGED | SCARD_STATE_PRESENT))
                {
                    const char *name = pMasterStates[i].szReader;
                    if (notify_token_inserted(pcsc, name) == 1)
                    {
                        goto FINISH;
                    }
                }
                else if (((pMasterStates[i].dwEventState &
                    (SCARD_STATE_CHANGED | SCARD_STATE_EMPTY)) ==
                    (SCARD_STATE_CHANGED | SCARD_STATE_EMPTY)) ||
                    ((pMasterStates[i].dwEventState &
                    (SCARD_STATE_CHANGED | SCARD_STATE_UNKNOWN)) ==
                    (SCARD_STATE_CHANGED | SCARD_STATE_UNKNOWN)))
                {
                    const char *name = pMasterStates[i].szReader;
                    if (notify_token_removed(pcsc, name) == 1)
                    {
                        goto FINISH;
                    }
                }

                pMasterStates[i].dwCurrentState = pMasterStates[i].dwEventState;            }
        }

        if (GetReaderListInfo(pcsc, 
                              &szReaderList,
                              &ReaderListSize,
                              &iReaderCount,
                              &pStates) != 0)
        {
            ExitVal = 2;
            break;
        }
        if (CompareReaderList(szMasterReaderList,
                              MasterReaderListSize, 
                              szReaderList,
                              ReaderListSize) == 0)
        {
            free (pStates);
            free (szReaderList);
        }
        else
        {
            UpdateReaderStates(pStates, iReaderCount, 
                               pMasterStates, iMasterReaderCount);
            free (pMasterStates);
            free (szMasterReaderList);
            szMasterReaderList = szReaderList;
            MasterReaderListSize = ReaderListSize;
            iMasterReaderCount = iReaderCount;
            pMasterStates = pStates;
        }

        szReaderList = NULL;
        ReaderListSize = 0;
        iReaderCount = 0;
        pStates = NULL;
    }

FINISH:
    /* Cleanups */
    if (pMasterStates != NULL) free (pMasterStates);
    if (szMasterReaderList != NULL) free (szMasterReaderList);

    /* Finalize PCKS#11 library if required */
    pcsc_lib_finalize(pcsc);

    /* Note that PC/SC thread has stopped */
    pcsc_thread_stop(pcsc);

    /* Exit the thread */
    log("Exitting PC/SC thread %ld", pthread_self());
    pthread_exit(NULL);

    return NULL;
}

int gdm_prompt_plugin_start(gdm_prompt_plugin_t *module, int prompt_type)
{
    pcsc_data_t *pcsc = NULL;
    int rval = 1;

    /* Pre-condition checks */
    if (module == NULL)
    {
        log("No 'module' parameter provided");
        goto FINISH;
    }

    /* start thread */
    if (G_thread == (pthread_t) 0)
    {
        pthread_attr_t attrs;

        /* Create a PC/SC object */
        if ((module->data = pcsc = pcsc_data_alloc()) == NULL)
        {
            goto FINISH;
        }
        pcsc->prompt_type = prompt_type;

        /* Note that PC/SC thread has started */
        pcsc_thread_start(pcsc);

        /* Start token monitoring thread */
        pthread_attr_init(&attrs);
        if (pthread_create(&G_thread, &attrs, monitor_pcsc_thread, pcsc) != 0)
        {
            goto FINISH;
        }
    }

    /* Success */
    rval = 0;

FINISH:
    return rval;
}

int gdm_prompt_plugin_stop(gdm_prompt_plugin_t *module)
{
    int rval = 1;

    /* Pre-condition checks */
    if (module == NULL)
    {
        log("No 'module' parameter provided");
        goto FINISH;
    }
    if (module->data == NULL)
    {
        log("No 'module->data' parameter provided");
        goto FINISH;
    }

    log("Request made to stop PC/SC thread %ld", G_thread);

    /* End thread */
    if (G_thread != (pthread_t) 0)
    {
        /* Get PC/SC object */
        pcsc_data_t *pcsc = module->data;

        /* Finalize the PC/SC library -- this will abort any other thread
           that is waiting on slot events */
        pcsc_lib_finalize(pcsc);

        /* Tell PC/SC thread to stop */
        pcsc_thread_stop(pcsc);

        /* Wait for PC/SC thread to die */
        pthread_join(G_thread, NULL);

        G_thread = (pthread_t) 0;
    }

    /* Success */
    rval = 0;

FINISH:
    return rval;
}

