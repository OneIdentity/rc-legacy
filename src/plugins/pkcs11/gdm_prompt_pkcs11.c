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
#include <dlfcn.h>
#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

#include "pkcs11_defs.h"
#include <pkcs11.h>

#include <gdm_prompt_plugin.h>
#include <gdm_prompt_config.h>

/** The symbol in the loaded PKCS#11 library for obtaining the list of
 * functions. */
#define GET_FUNCTIONS_SYM    "C_GetFunctionList"

/* Copied from gdm.h */
#define STX 0x2                 /* Start of txt */

typedef struct {
  CK_FUNCTION_LIST *fns;  /**< The PKCS#11 function list */
  int prompt_type;        /**< The PAM prompt type */
  int _initialized;       /**< Has PKCS#11 library been initialized? */
  int _running;           /**< Should PKCS#11 thread keep running? */
  pthread_mutex_t mutex;  /**< Mutex for accessing flags */
} pkcs11_data_t;

static pthread_t G_thread = (pthread_t) 0;

#if 1
#define log(format, args...) \
	syslog(LOG_DEBUG, "[GDM_PROMPT_PKCS11] " format , ##args)
#else
#define log(format, args...) \
	printf("[GDM_PROMPT_PKCS11] " format , ##args); printf("\n")
#endif

/** Get the run state of the PKCS#11 thread */
static int pkcs11_thread_is_running(pkcs11_data_t *pkcs11)
{
    int running;

    pthread_mutex_lock(&pkcs11->mutex);
    running = pkcs11->_running;
    pthread_mutex_unlock(&pkcs11->mutex);

    return running;
}

/** Set the run state of the PKCS#11 thread */
static void pkcs11_thread_set_running(pkcs11_data_t *pkcs11, int running)
{
    pthread_mutex_lock(&pkcs11->mutex);
    pkcs11->_running = running;
    pthread_mutex_unlock(&pkcs11->mutex);
}

/** Initialize the PKCS#11 library */
static CK_RV pkcs11_lib_initialize(pkcs11_data_t *pkcs11)
{
    CK_RV rv = CKR_OK;

    pthread_mutex_lock(&pkcs11->mutex);
    if (pkcs11->_running && !pkcs11->_initialized)
    {
        rv = pkcs11->fns->C_Initialize(NULL);
        pkcs11->_initialized = 1;
    }
    pthread_mutex_unlock(&pkcs11->mutex);

    return rv;
}

/** Finalize the PKCS#11 library */
static void pkcs11_lib_finalize(pkcs11_data_t *pkcs11)
{
    pthread_mutex_lock(&pkcs11->mutex);
    if (pkcs11->_running && pkcs11->_initialized)
    {
        pkcs11->fns->C_Finalize(NULL);
        pkcs11->_initialized = 0;
    }
    pthread_mutex_unlock(&pkcs11->mutex);
}

/** Handle a PKCS#11 event. 
 *
 * @return 0 if the PKCS#11 event was ignored
 *         1 if the PKCS#11 event was handled
 *         -1 if an error occurred
 */
static int handle_event(pkcs11_data_t *pkcs11, CK_SLOT_ID slot)
{
    CK_SLOT_INFO info;
    CK_RV rv;
    int rval = -1;

    /* Get information about the slot */
    if ((rv = pkcs11->fns->C_GetSlotInfo(slot, &info)) != CKR_OK)
    {
        log("Failed to get PKCS#11 slot info: 0x%02lX", rv);
        goto FINISH;
    }

    rval = 0;

    if (info.flags & CKF_TOKEN_PRESENT)
    {
        log("Token present event");
        if (pkcs11->prompt_type == PAM_PROMPT_ECHO_ON)
        {
            printf("%c\n", STX);
            fflush(stdout);
            rval = 1;
        }
    }
    else
    {
        log("Token removed event");
        if (pkcs11->prompt_type == PAM_PROMPT_ECHO_OFF)
        {
            printf("%c\n", STX);
            fflush(stdout);
            rval = 1;
        }
    }

FINISH:
    log("Token event: %s", 
        (rval == 0) ? "ignored" : (rval == 1) ? "handled" : "error");

    return rval;
}

static int wait_for_slot(pkcs11_data_t *pkcs11)
{
    CK_ULONG num_slots;
    CK_RV rv;
    int rval = 1;

    /* How many slots are present? */
    if (pkcs11->fns->C_GetSlotList(CK_FALSE, NULL, &num_slots) != CKR_OK)
    {
        log("Failed to get PKCS#11 slots: 0x%02lX", rv);
        goto FINISH;
    }

    if (pkcs11_thread_is_running(pkcs11) && num_slots == 0)
    {
        log("No PKCS#11 slots available. Resetting PKCS#11 library "
            "until a slot is found");
    }

    /* If there's no slots, reinitialize and get slot count again */
    while (pkcs11_thread_is_running(pkcs11) && num_slots == 0)
    {
        /* Stop library */
        pkcs11_lib_finalize(pkcs11);

        /* Check if still running */
        if (!pkcs11_thread_is_running(pkcs11))
        {
            break;
        }

        /* Wait for a while before restarting PKCS#11 library. */
        sleep(1);

        /* Start library again */
        if ((rv = pkcs11_lib_initialize(pkcs11)) != CKR_OK)
        {
            goto FINISH;
        }

        /* Check if still running */
        if (!pkcs11_thread_is_running(pkcs11))
        {
            break;
        }

        /* Get the number of slots */
        if (pkcs11->fns->C_GetSlotList(CK_FALSE, NULL, &num_slots) != CKR_OK)
        {
            log("Failed to get PKCS#11 slots: 0x%02lX", rv);
            goto FINISH;
        }
    }
    /* Assert: either a slot exists or told to stop running */

    if (pkcs11_thread_is_running(pkcs11) && num_slots > 0)
    {
        log("PKCS#11 slots available: %ld", num_slots);
    }

    /* Success */
    rval = 0;

FINISH:
    return rval;
}

/* Function implementing the PKCS#11 thread. 
 *
 * Performs the following steps:
 * 
 * 1. Initializes the PKCS#11 library;
 * 2. Performs the following loop while the thread is allowed to run: 
 *    2.1 Wait until a slot is available
 *    2.2 Wait until the required event occurs on a slot
 * 3. Finalize the PKCS#11 library
 *
 * Note that if the parent thread calls C_Finalize(), this will terminate the 
 * C_WaitForSlotEvent() function in this thread.
 */
static void *pkcs11_thread(void *p)
{
    pkcs11_data_t *pkcs11 = NULL;
    CK_RV rv;

    /* Get the PKCS#11 object */
    pkcs11 = (pkcs11_data_t *) p;

    log("Starting thread %ld, event = %s",
        pthread_self(),
        (pkcs11->prompt_type == PAM_PROMPT_ECHO_ON)
               ? "token insertion"
               : "token removal");

    /* Initialize PKCS#11 library */
    if ((rv = pkcs11_lib_initialize(pkcs11)) != CKR_OK)
    {
        goto FINISH;
    }

    /* Loop until told to stop, or matching token event occurs */
    while (pkcs11_thread_is_running(pkcs11))
    {
        CK_SLOT_ID slot;

        /* Wait until a slot is available or told to stop running */
        if (wait_for_slot(pkcs11) != 0)
        {
            break;
        }

        /* Check that thread should still run */
        if (!pkcs11_thread_is_running(pkcs11))
        {
            break;
        }

        /* Block until a slot event */ 
        log("Blocking until an event ... ");
        rv = pkcs11->fns->C_WaitForSlotEvent(0, &slot, NULL);
        log("C_WaitForSlotEvent() = %ld", rv);

        /* A slot event occurred */
        if (rv == CKR_OK)
        {
            /* Stop if token event handled or an error occurs */
            if (handle_event(pkcs11, slot) != 0)
            {
                break;
            }
        }
        /* Waiting was cancelled by calling C_Finalize */
        else if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
        {
            log("Waiting for PKCS#11 slot event cancelled");
            break;
        }
        /* No event occurred -- should not get heer but handle anyweay */
        else if (rv == CKR_NO_EVENT)
        {
            log("No slot event found");
            break;
        }
        /* Error occurred */
        else
        {
            log("Error waiting for slot event: %ld", rv);
            break;
        }
    }

FINISH:
    /* Finalize PCKS#11 library if required */
    pkcs11_lib_finalize(pkcs11);

    /* Note that PKCS#11 thread has stopped */
    pkcs11_thread_set_running(pkcs11,0);

    /* Exit the thread */
    log("Stopping thread %ld", pthread_self());
    pthread_exit(NULL);

    return NULL;
}

/** Configure the PKCS#11 object. This will examine the configuration to
 * get the location of the PKCS#11 library to load, load the library and
 * obtain a function list.
 */
static int configure_pkcs11(pkcs11_data_t *pkcs11)
{
    const char *lib = NULL;
    void *handle = NULL;
    CK_C_GetFunctionList get_function_list = NULL;
    CK_RV rv;
    int rval = 1;

    /* Get the PKCS#11 library from the configuration */
    log("Getting config from file '%s'", PKCS11_PLUGIN_CONFIG_FILE);
    lib = gdm_prompt_config_get_string(PKCS11_PLUGIN_CONFIG_FILE,
                                      "pkcs11/library");
    if (lib == NULL || strcmp(lib, "") == 0)
    {
        log("No PKCS#11 library defined");
        rval = 1;
        goto FINISH;
    }

    /* Load the library */
    dlerror();
    if ((handle = dlopen(lib, RTLD_NOW)) == NULL)
    {
        log("Failed to load PKCS#11 library '%s': %s", lib, dlerror());
        goto FINISH;
    }
    log("Loaded token library '%s'", lib);

    /* Get the C_GetFunctionList symbol from the module */
    get_function_list = (CK_C_GetFunctionList) dlsym(handle, GET_FUNCTIONS_SYM);
    if (get_function_list == NULL)
    {
        log("Failed to get symbol '%s' from PKCS#11 library", 
            GET_FUNCTIONS_SYM);
        goto FINISH;
    }

    /* Get the function list */
    if ((rv = (*get_function_list)(&pkcs11->fns)) != CKR_OK)
    {
        log("Failed to get function list from PKCS#11 library");
        goto FINISH;
    }
    
    /* Success */
    rval = 0;

FINISH:
    return rval;
}

/** Free a PKCS#11 data object */
static void pkcs11_data_free(pkcs11_data_t *pkcs11)
{
    if (pkcs11 != NULL)
    {
        /* Destroy the mutex */
        pthread_mutex_destroy(&pkcs11->mutex);
    }
    free(pkcs11);
}

/** Allocate a PKCS#11 data object */
static pkcs11_data_t *pkcs11_data_alloc(void)
{
    pkcs11_data_t *pkcs11 = NULL;

    if ((pkcs11 = calloc(1, sizeof(*pkcs11))) == NULL)
    {
        log("Memory allocation failure");
        goto FINISH;
    }

    /* Create the mutex that controls access to the PKCS#11 state */
    pthread_mutex_init(&pkcs11->mutex, NULL);
       
    /* Configure the PKCS#11 object */
    if (configure_pkcs11(pkcs11) != 0)
    {
        pkcs11_data_free(pkcs11);
        pkcs11 = NULL;
        goto FINISH;
    }

FINISH:
    return pkcs11;
}

/** Start the PKCS#11 prompt plugin */
int gdm_prompt_plugin_start(gdm_prompt_plugin_t *module, int prompt_type)
{
    pkcs11_data_t *pkcs11 = NULL;
    int rval = 1;

    /* Pre-condition checks */
    if (module == NULL)
    {
        log("No 'module' parameter provided");
        goto FINISH;
    }

    /* Start thread, if required */
    if (G_thread == (pthread_t) 0)
    {
        pthread_attr_t attrs;

        /* Create a PKCS#11 object */
        if ((module->data = pkcs11 = pkcs11_data_alloc()) == NULL)
        {
            goto FINISH;
        }
        pkcs11->prompt_type = prompt_type;

        /* Note that PKCS#11 thread has started */
        pkcs11_thread_set_running(pkcs11, 1);

        /* Start token monitoring thread */
        pthread_attr_init(&attrs);
        if (pthread_create(&G_thread, &attrs, pkcs11_thread, pkcs11) != 0)
        {
            goto FINISH;
        }
    }
   
    /* Success */
    rval = 0;

FINISH:
    /* Memory cleanups */
    if (rval != 0 && pkcs11 != NULL)
    {
        pkcs11_data_free(pkcs11);
    }

    return rval;
}

/** Stop the PKCS#11 plugin */
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

    /* End thread, if it is running */
    if (G_thread != (pthread_t) 0)
    {
        /* Get PKCS#11 object */
        pkcs11_data_t *pkcs11 = module->data;

        log("Request made to stop PKCS#11 thread %ld", G_thread);

        /* Finalize the PKCS#11 library -- this will abort any other thread
           that is waiting on slot events */
        pkcs11_lib_finalize(pkcs11);

        /* Tell any PKCS#11 thread to stop */
        pkcs11_thread_set_running(pkcs11, 0);

        /* Wait for PKCS#11 thread */
        pthread_join(G_thread, NULL);

        /* Free the PKCS#11 data */
        pkcs11_data_free(pkcs11);
        module->data = NULL;

        G_thread = (pthread_t) 0;
    }

    /* Success */
    rval = 0;

FINISH:
    return rval;
}

