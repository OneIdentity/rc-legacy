<?php

/**
 ** PHP Extension for Quest VAS.
 **
 ** Copyright (c) 2006 and 2007 Quest Software, Inc.
 **
 **/

/**
 * Vintela Authentication Service (VAS) API
 *
 * VAS API Version 4.0
 *
 * Copyright (c) 2006 and 2007 Quest Software, Inc. All Rights Reserved.
 *
 * This header file is distributed as part of the Vintela Authentication
 * Services (VAS) distribution governed by the Vintela Authentication
 * Services (VAS) Software End User License Agreement (the "EULA").
 * This header file is part of the "Licensed Software" licensed to a
 * Licensee under the EULA. The Licensee may use information learned
 * from this file to develop software applications that use the libvas
 * library of VAS as permitted by the EULA, and for no other purpose.
 * If you are not the Licensee under the EULA, then you do not have any
 * license to use this file or any information in it.
 *
 **/

/* NOTE:  This header file contains comment markups that are used with
 *        the Doxygen (generated) documentation system
 */


/** @file
 * Provides PHP functions for interacting with Microsoft domain controllers
 * including Active Directory LDAP access, Kerberos authentication, and user
 * logon functionality.
 *
 * The VAS API provides simplified interfaces for using Kerberos to
 * authenticate against Active Directory, and using LDAP to access
 * information. All of the complexity of discovering Active Directory
 * domain controllers, LDAP SASL binds, processing LDAP results, and
 * Kerberos/GSSAPI function calls are hidden from the caller. The LDAP
 * and Kerberos version 5 implementations are in libvas.so. There is no
 * need to link in a separate LDAP or Kerberos library. This version
 * of libvas is not binary compatible with the libvas from the VAS
 * 2.x product series.
 *
 **/

/** @cond UNDOC **/
global $VAS_LOADED__;
if ( $VAS_LOADED__ ) return;
$VAS_LOADED__ = true;

/* if our extension has not been loaded, do what we can */
if ( ! extension_loaded( "php_vas" ) )
{
	if ( ! dl( "php_vas.so" ) )
        return;
}
/** @endcond **/

/**
 * Get the last error code from the VAS subsystem
 *
 * @return  A VAS error code. This is an instance of the vas_err enumeration.
 **/
function vas_err()
{
  return vas_err_internal();
}

/**
 * Get the last minor status code from the GSS subsystem
 *
 * @return  A VAS GSS minor status code.
 **/
function vas_err_minor()
{
  return vas_err_minor_internal();
}

/**
 * True if $code is a GSS Error.
 *
 * @param code Error code returned by a GSS API.
 * @return true if code represents an error.
 */
function GSS_ERROR( $code )
{
  return $code & ( ( 0377 << 24 ) | ( 0377 << 16 ) );
}

/**
 * CVAS_LDAPMod represents a modification changes associated with an LDAP
 * operation.
 *
 * Note the following:
 *
 *    If you specify LDAP_MOD_DELETE in the mod_op field and you remove all
 *    values in an attribute, the attribute is removed from the entry.
 *
 *    If you specify LDAP_MOD_DELETE in the mod_op field and NULL in the
 *    mod_values field, the attribute is removed from the entry.
 *
 *    If you specify LDAP_MOD_REPLACE in the mod_op field and NULL in the
 *    mod_values field, the attribute is removed from the entry.
 *
 *    If you specify LDAP_MOD_REPLACE in the mod_op field and the attribute
 *    does not exist in the entry, the attribute is added to the entry.
 *
 *    If you specify LDAP_MOD_ADD in the mod_op field and the attribute
 *    does not exist in the entry, the attribute is added to the entry.
 */
class VASObj_LDAPMod
{
    /** Constructor for CVAS_LDAPMod.
     * After construction, you should call CVAS_LDAPMod::add_value to
     * add values if you have any.
     * @param op Value for the mod_op field.
     * @param type Value for the mod_type field.
     */
    function VASObj_LDAPMod( $op, $type )
    {
        $this->mod_op = $op;
        $this->mod_type = $type;
    }

    /** Add a value to the list of values in this object.
     * @param value Value to add to the mod_values list.
     */
    function add_value( $value )
    {
        $this->mod_values[] = $value;
    }
    /** The operation to be performed on the attribute and the type of data
     * specified as the attribute values. This field can have one of the
     * following values:
     *    LDAP_MOD_ADD adds a value to the attribute.
     *    LDAP_MOD_DELETE removes the value from the attribute.
     *    LDAP_MOD_REPLACE replaces all existing values of the attribute.
     *
     * In addition, if you are specifying binary values in the mod_bvalues
     * field, you should use the bitwise OR operator ( | ) to combine
     * LDAP_MOD_BVALUES with the operation type. For example:
     *    mod->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES
     *
     * Note that if you are using the structure a call to ldap_add() the
     * mod_op field be zero unless unless you are adding binary values
     * and need to specify LDAP_MOD_BVALUES).
     */
    var $mod_op;

    /** The attribute type that you want to add, delete, or replace the values
     * of (for example,  sn  or  telephoneNumber ).
     */
    var $mod_type;

    /** An array of string values to assign to the attribute. */
    var $mod_values;
};

/**
 * Accessable class designed for web-type applications to access
 * Active Directory resources through VAS.
 **/
class VASObj
{
    /** @protectedsection **/
    var $ctx;          /*!< The vas_ctx_t resource created in default
                            constructor */
    var $id;           /*!< The vas_id_t resource if id_alloc() has been
                            called */

    var $attrs;        /*!< The vas_attrs_t resource used by attrs_find and
                            vals_get_* */
    var $ld;           /*!< The LDAP resource so that we can reuse the same
                            bound handle */
    var $first_result; /*!< Used in attrs_find / attrs_next_result loops */
    var $vaserror;     /*!< Used to keep track of errors from VAS API calls */
    /** @publicsection **/
    /**
     * Default constructor for CVAS.
     *
     * @return none
     *
     *    vas_err() returns:
     *    - VAS_ERR_SUCCESS on success or one of the following error codes:
     *    - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
     *    - VAS_ERR_NO_MEMORY       - Memory allocation failed
     **/
    function VASObj()
    {
        $this->ctx = vas_ctx_alloc();
        $this->id = null;

        $this->attrs = null;
        $this->ld = null;

        $this->first_result = false;
        $this->vaserror = VAS_ERR_SUCCESS;
    }

    /**
     * Get the current error string from the context.
     **/
    function get_error_string()
    {
        return vas_err_get_string( $this->ctx, 1 );
    }

    /**
     * Get the current error string from the context.
     **/
    function get_error_code()
    {
        return vas_err_get_code($this->ctx);
    }

    /**
     * Authenticate a user for this CVAS instance.
     *
     * @param username  The username to authenticate.
     * @param password  The clear-text password for the specified identity.
     *
     * @return  null
     *
     *          vas_err() returns:
     *          - VAS_ERR_SUCCESS on success or one of the following error codes:
     *          - VAS_ERR_KRB5            - Kerberos specific error
     *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
     *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
     *          - VAS_ERR_CONFIG          - Unable to determine default_realm.
     *          - VAS_ERR_CRED_NEEDED   - Credentials are NOT established
     *          - VAS_ERR_CRED_EXPIRED  - Credentials are expired.
     **/
    function authenticate( $username, $password )
    {
        /* Allocate the id with the user principal name. This will create a
         * base structure that we can use for authentication later. */
        $this->id = vas_id_alloc( $this->ctx, $username);
        if ( vas_err() != VAS_ERR_SUCCESS )
        {
            return;
        }

        /* Use the id to determine if credentials already exist and if they are
         * valid. If a call to vas_id_cred_establish has been made, if the
         * current user logged in using the VAS PAM module, or if the id is a
         * result of a delegated SPENGO or GSSAPI authentication then the id
         * should already be valid and no authentication is needed. */
        if ( vas_id_is_cred_established( $this->ctx, $this->id )
                == VAS_ERR_CRED_NEEDED )
        {
            /* The call to vas_id_is_cred_established will create an error on
             * the context stack so we should clear it since it was expected */
            vas_err_clear( $this->ctx );

            /* Establish the credential using one of the
             * vas_id_establish_cred_TYPE calls. In this case we use password
             * and will pass the password in for the id. The credflags is a
             * flag which allows you to decide what is done with the credential
             * once it is valid. The VAS_ID_FLAG_USE_MEMORY_CCACHE flag will
             * cause credential to be destroyed once the id is freed. The
             * VAS_ID_FLAG_KEEP_COPY_OF_CRED flag will cause the credential to
             * be stored to the users cache and not require the user to
             * authenticate again unless the cache is cleared. */

            vas_id_establish_cred_password( $this->ctx, $this->id,
                    VAS_ID_FLAG_USE_MEMORY_CCACHE, $password );
        }
    }

    /**
     * Search for the values of a named attributes on a user resource. Normally
     * authenticate() is called before find() to identify a user, else an
     * anonymous search is performed.
     *
     * @param uri       The URI that identifies the server that will be bound
     *                  to. For more details on URI format see:
     *                  vas_ldap_init_and_bind()
     *
     * @param scope     Optional LDAP search scope. May one of the following
     *                  strings: "base" for LDAP_SCOPE_BASE, "sub" for
     *                  LDAP_SCOPE_SUBTREE, or "one" for LDAP_SCOPE_ONELEVEL.
     *                  If null set, LDAP_SCOPE_SUBTREE will be used
     *
     * @param base      Optional search base for the LDAP search. The search
     *                  base is specified as a distinguished name
     *                  (OU=myou,DC=foo,DC=com). Pass in NULL to use the
     *                  defaultNamingContext LDAP search base. When using the
     *                  GC, pass in an empty string "" to search the entire
     *                  global catalog.
     *
     * @param filter    Required LDAP search filter that specifies search
     *                  conditions.
     *
     * @param anames    List attributes to obtain. May be either a single
     *                  string or an array of strings.
     *
     * @return  The value of the indicated attribute.
     *          Attributes are returned as an array of strings.
     *
     *          vas_err() returns:
     *          - VAS_ERR_SUCCESS on success or one of the following error codes:
     *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
     *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
     *          - VAS_ERR_FAILURE       - Unspecified failure
     *          - VAS_ERR_NOT_FOUND     - Matching entry doesn't exist
     *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t
     *                                    functions to obtain Kerberos error
     *                                    details
     *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
     *                                    to obtain LDAP error details
     *
     **/
    function find($uri, $scope, $base, $filter, $anames)
    {
        $rv = array();

        /* Make an array if it isn't.*/
        if ( ! is_array( $anames ) )
        {
            $anames = array( $anames );
        }

        /* Create an attribute structure that will hold information about
         * attributes that will be retrieved from the search */
        $attrs = vas_attrs_alloc( $this->ctx, $this->id );
        if ( vas_err() != VAS_ERR_SUCCESS )
        {
            return null;
        }

        /* Begin the search. The URI argument specifies if we want to talk to a
         * DC, GC, or you can specify a specific server to access (such as
         * DC://server1.example.com). The scope is used to specify where in the
         * tree you want to search. Attrs_names is a NULL terminated list of
         * attributes that we want to retrieve for the items that our search
         * filter matches. */
        vas_attrs_find( $this->ctx, $attrs, $uri, $scope, $base, $filter,
                $anames );

        while ( vas_err() == VAS_ERR_SUCCESS )
        {
            foreach ( $anames as $a )
            {
                do
                {
                    /* Get an entry from the results, one at a time */
                    $strvals = vas_vals_get_string ( $this->ctx, $attrs, $a );

                    if ( ( vas_err() == VAS_ERR_SUCCESS
                        || vas_err() == VAS_ERR_MORE_VALS )
                            && count( $strvals ) )
                    {
                        $rv = array_merge($rv, $strvals);
                    }
                }
                while ( vas_err() == VAS_ERR_MORE_VALS );
            }

            /* The first vas_attrs_find may not return all of the possible
             * results.  In many cases you only want to get the first entry so
             * for performance reasons this is the behavior. If you want more
             * than one result you must request more items and loop again for
             * the results. */
            vas_attrs_find_continue( $this->ctx, $attrs );
        }

        /* Indicate success on return. */
        vas_err_clear($this->ctx);
        return $rv;
    }

  /**
   * Query to see if a user is in a group in the Active Directory.
   *
   * @param username    The user name (a string).
   * @param groupname   The group name (a string).
   *
   * @return The vas_err() code is returned.
   *
   *          vas_err() returns:
   *          - VAS_ERR_SUCCESS on success or one of the following error codes:
   *          - VAS_ERR_NOT_FOUND       - The user is not a member
   *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
   *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
   *          - VAS_ERR_FAILURE         - Unspecified failure
   *
   **/
  function is_user_in_group($username, $groupname)
  {
    $group = vas_group_init($this->ctx, $this->id, $groupname, 0);

    if (vas_err() != VAS_ERR_SUCCESS)
    {
      // printf("group_init failed: %d\n", vas_err());
      return vas_err();
    }
    $user = vas_user_init($this->ctx, $this->id, $username, 0);

    if (vas_err() != VAS_ERR_SUCCESS)
    {
      // printf("user_init failed: %d\n", vas_err());
      return vas_err();
    }
    return vas_group_has_member($this->ctx, $this->id, $group, $user);
  }


  /**
   * Get the list of groups the user is a member of.
   *
   * @param username    The user name (a string).
   *
   * @param flags   Flags that modify the expansion behavior:
   *                - VAS_NAME_FLAG_NO_CACHE
   *                - VAS_NAME_FLAG_NO_LDAP
   *                - VAS_NAME_FLAG_FOREST_SCOPE - If a domain/realm part is
   *                                               not specified, the entire
   *                                               forest is searched. By
   *                                               default only the current
   *                                               realm will be searched.
   *
   * @return An array of strings containing the group names.
   *
   *          vas_err() returns:
   *          - VAS_ERR_SUCCESS on success or one of the following error codes:
   *          - VAS_ERR_NOT_FOUND       - Could not locate a user account
   *                                      with the given name.
   *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
   *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
   *          - VAS_ERR_FAILURE         - Unspecified failure
   *
   **/
  function get_groups_for_user($username, $flags)
  {
    $myuser = vas_user_init($this->ctx, $this->id, $username, $flags);

    if (vas_err() != VAS_ERR_SUCCESS)
    {
      return null;
    }
    $groups = vas_user_get_groups($this->ctx, $this->id, $myuser);

    if (vas_err() != VAS_ERR_SUCCESS)
    {
      return null;
    }
    //
    // Now convert the groups to strings.
    //
    $rv = array();

    foreach ($groups as $g)
    {
      $rv[] = vas_group_get_dn($this->ctx, $this->id, $g);

      if (vas_err() != VAS_ERR_SUCCESS)
      {
	     return null;
      }
    }
    return $rv;
  }

  /**
   * Query for specific attributes on a group.
   *
   * @param groupname   The group name (a string).
   * @param attributes   The attribute name to query for (or names as an array).
   *
   * @return On success the requested attributes as an array of strings.
   *         Null on error.
   *
   *          vas_err() returns:
   *          - VAS_ERR_SUCCESS on success or one of the following error codes:
   *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
   *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
   *          - VAS_ERR_FAILURE         - Unspecified failure
   *
   **/
  function get_group_attributes($groupname, $attributes)
  {
    $rv = array();

    // Make array if it isn't.
    if (!is_array($attributes))
    {
      $attributes = array($attributes);
    }
    $group = vas_group_init($this->ctx, $this->id, $groupname, 0);

    if (vas_err() != VAS_ERR_SUCCESS)
    {
      // printf("group_init failed: %d\n", vas_err());
      return null;
    }
    $attrs = vas_group_get_attrs($this->ctx, $this->id, $group, $attributes);

    if (vas_err() != VAS_ERR_SUCCESS)
    {
      return null;
    }
    foreach ($attributes as $a)
    {
      do
      {
	    /* Get an entry from the results, one at a time */
	    $strvals = vas_vals_get_string ( $this->ctx, $attrs, $a);

	    if(( vas_err() == VAS_ERR_SUCCESS || vas_err() == VAS_ERR_MORE_VALS )
            && count($strvals) )
        {
	      $rv = array_merge($rv, $strvals);
	    }
      } while( vas_err() == VAS_ERR_MORE_VALS );
    }
    return $rv;
  }

  /**
   * Modify attributes using LDAP on the server.
   *
   * @param uri   The URI that identifies the server that will be bound to.
   *              For more details on URI format see: vas_ldap_init_and_bind()
   *
   * @param dn    The distinguished name of the LDAP object to modify
   *
   * @param mods  Either a CVAS_LDAPMod class or an array of CVAS_LDAPMod
   *              classes. See the CVAS_LDAPMod documentation for more
   *              information.
   *
   * @return  VAS_ERR_SUCCESS on success, or one of the following error codes:
   *          - VAS_ERR_INVALID_PARAM  - Invalid parameters
   *          - VAS_ERR_NO_MEMORY      - Memory allocation failed
   *          - VAS_ERR_LDAP           - LDAP specific error
   **/
  function set_attributes($uri, $dn, $mods)
  {
    if (!is_array($mods))
    {
      $mode = array($mods);
    }

    return vas_ldap_set_attributes($this->ctx, $this->id, $uri, $dn, $mods);
  }
}

?>
