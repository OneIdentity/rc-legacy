
abs_srcdir		= $(shell cd $(srcdir) && pwd)
EXTRA_INSTALL_HOOKS 	=
EXTRA_UNINSTALL_HOOKS 	=
EXTRA_CLEAN_HOOKS 	=

# The directories that we install into
scriptdir 		= $(datadir)/php
docdir			= $(datadir)/doc

# installed PHP scripts, also used as documentation source
dist_script_DATA	= scripts/vasapi.php \
			  scripts/vas_gss.php \
			  scripts/vas_ldap.php \
			  scripts/vas.php

# the vas.so module is simply put in the datadir
data_DATA 		= extension/vas.so
#-- note: don't use a _SOURCES var here because its only intended for 
#   PROGRAMS, LIBRARIES and LT_LIBRARIES.
vas_so_sources		= extension/vasapi.c \
			  extension/php_vas.h 

#-- Some explicit rules to build the vas.so extension using phpize
extension/configure: extension/config.m4
	if test ! -d extension; then \
		mkdir -p extension; \
		touch extension/.linked; \
		ln -s $(abs_srcdir)/extension/config.m4 extension/config.m4; \
		ln -s $(abs_srcdir)/extension/vasapi.c extension/vasapi.c; \
	fi
	cd extension && $(PHPIZE)
extension/Makefile: extension/configure
	cd extension && ./configure CPPFLAGS=-I$(abs_srcdir)/extension
extension/vas.so: extension/Makefile $(vas_so_sources)
	cd extension && $(MAKE)
	cp extension/modules/vas.so $@

clean-vas_so:
	-cd extension && $(MAKE) clean
	-cd extension && $(PHPIZE) --clean
	-rm -rf extension/vas.so extension/autom4te.cache
	-if [ -f extension/.linked ]; then \
	    rm extension/config.m4 extension/vasapi.c extension/.linked; \
	    rmdir extension; \
	 fi

EXTRA_DIST		= $(vas_so_sources) \
			  extension/config.m4 \
			  LICENCE NEWS README \
			  doxvas.in

if HAVE_DOXYGEN
#------------------------------------------------------------------------------
# Create the documentation, html and man pages, in the doc subdirectory.
#------------------------------------------------------------------------------

doc/html/index.html: $(script_DATA) doxvas
	$(DOXYGEN) doxvas
doxvas: doxvas.in
	sed -e 's,[@]srcdir[@],$(srcdir),g' < $(srcdir)/doxvas.in > $@
install-doc: doc/html/index.html
	$(install_sh) -d $(DESTDIR)$(docdir)
	cp -r doc/* $(DESTDIR)$(docdir)/
uninstall-doc:
	rm -rf $(DESTDIR)$(docdir)
clean-doc:
	-rm -rf doc doxvas

EXTRA_INSTALL_HOOKS +=	 install-doc
EXTRA_UNINSTALL_HOOKS += uninstall-doc
EXTRA_CLEAN_HOOKS +=	 clean-doc
endif

uninstall-local: $(EXTRA_UNINSTALL_HOOKS)
install-data-local: $(EXTRA_INSTALL_HOOKS)
clean-local: clean-vas_so $(EXTRA_CLEAN_HOOKS)

#------------------------------------------------------------------------------
# This is for Polypkg...
#------------------------------------------------------------------------------
package:
	$(MAKE) install DESTDIR=$$PWD/pkgroot
	$(srcdir)/pp --destdir=$$PWD/pkgroot $(srcdir)/php_vas.pp \
		version=$(PKG_VERSION) \
		scriptdir=$(scriptdir) \
		extensiondir=$(extensiondir) \
		docdir=$(docdir)

EXTRA_DIST += pp php-vas.pp

#------------------------------------------------------------------------------
# Tests
#------------------------------------------------------------------------------

TESTS_ENVIRONMENT= EXTDIR=$$PWD/extension \
		   INCPATH=$(srcdir)/tests:$(srcdir)/scripts \
		   $(SHELL) $(srcdir)/tests/driver -f

EXTRA_DIST +=	tests/driver tests/driver.php \
		tests/test.php tests/checkAttribute.php

TESTS = \
		tests/t_vas_ctx_alloc.php \
		tests/t_vas_ctx_set_option.php \
		tests/t_vas_ctx_get_option.php \
		tests/t_vas_id_alloc.php \
		tests/t_vas_id_get_ccache_name.php \
		tests/t_vas_id_get_keytab_name.php \
		tests/t_vas_id_get_name.php \
		tests/t_vas_id_get_user.php \
		tests/t_vas_id_is_cred_established.php \
		tests/t_vas_id_establish_cred_password.php \
		tests/t_vas_id_establish_cred_keytab.php \
		tests/t_vas_id_renew_cred.php \
		tests/t_vas_auth.php \
		tests/t_vas_auth_with_password.php \
		tests/t_vas_auth_check_client_membership.php \
		tests/t_vas_auth_get_client_groups.php \
		tests/t_vas_attrs_alloc.php \
		tests/t_vas_attrs_find.php \
		tests/t_vas_attrs_find_continue.php \
		tests/t_vas_attrs_set_option.php \
		tests/t_vas_attrs_get_option.php \
		tests/t_vas_vals_get_string.php \
		tests/t_vas_vals_get_integer.php \
		tests/t_vas_vals_get_binary.php \
		tests/t_vas_vals_get_anames.php \
		tests/t_vas_vals_get_dn.php \
		tests/t_vas_name_to_principal.php \
		tests/t_vas_name_to_dn.php \
		tests/t_vas_info_forest_root.php \
		tests/t_vas_info_joined_domain.php \
		tests/t_vas_info_site.php \
		tests/t_vas_info_domains.php \
		tests/t_vas_info_servers.php \
		tests/t_vas_prompt_for_cred_string.php \
		tests/t_vas_err_get_code.php \
		tests/t_vas_err_get_string.php \
		tests/t_vas_err_clear.php \
		tests/t_vas_err_get_info.php \
		tests/t_vas_err_info_get_string.php \
		tests/t_vas_err_get_cause_by_type.php \
		tests/t_vas_user_init.php \
		tests/t_vas_user_is_member.php \
		tests/t_vas_user_get_groups.php \
		tests/t_vas_user_get_attrs.php \
		tests/t_vas_user_get_dn.php \
		tests/t_vas_user_get_domain.php \
		tests/t_vas_user_get_sam_account_name.php \
		tests/t_vas_user_get_sid.php \
		tests/t_vas_user_get_upn.php \
		tests/t_vas_user_get_pwinfo.php \
		tests/t_vas_user_get_krb5_client_name.php \
		tests/t_vas_user_get_account_control.php \
		tests/t_vas_user_check_access.php \
		tests/t_vas_user_check_conflicts.php \
		tests/t_vas_group_init.php \
		tests/t_vas_group_has_member.php \
		tests/t_vas_group_get_attrs.php \
		tests/t_vas_group_get_dn.php \
		tests/t_vas_group_get_domain.php \
		tests/t_vas_group_get_sid.php \
		tests/t_vas_service_init.php \
		tests/t_vas_service_get_attrs.php \
		tests/t_vas_service_get_dn.php \
		tests/t_vas_service_get_domain.php \
		tests/t_vas_service_get_krb5_client_name.php \
		tests/t_vas_service_get_spns.php \
		tests/t_vas_service_get_upn.php \
		tests/t_vas_computer_init.php \
		tests/t_vas_computer_is_member.php \
		tests/t_vas_computer_get_attrs.php \
		tests/t_vas_computer_get_dn.php \
		tests/t_vas_computer_get_dns_hostname.php \
		tests/t_vas_computer_get_domain.php \
		tests/t_vas_computer_get_sid.php \
		tests/t_vas_computer_get_spns.php \
		tests/t_vas_computer_get_sam_account_name.php \
		tests/t_vas_computer_get_upn.php \
		tests/t_vas_computer_get_krb5_client_name.php \
		tests/t_vas_computer_get_host_spn.php \
		tests/t_vas_computer_get_account_control.php \
		tests/t_vas_gss_initialize.php \
		tests/t_vas_gss_acquire_cred.php \
		tests/t_vas_gss_auth.php \
		tests/t_vas_gss_spnego_initiate.php \
		tests/t_vas_gss_spnego_accept.php \
		tests/t_vas_krb5_get_context.php \
		tests/t_vas_krb5_get_principal.php \
		tests/t_vas_krb5_get_ccache.php \
		tests/t_vas_ldap_init_and_bind.php \
		tests/t_vas_ldap_set_attributes.php \
		tests/t_vas_ldap_set_attributes1.php \
		tests/t_vas_ldap_set_attributes2.php \
		tests/t_vas_ldap_set_attributes3.php \
		tests/t_vas_ldap_set_attributes4.php \
		# end of tests
MISSING_TESTS =		
		tests/t_vas_gss_krb5_get_subkey.php \
		tests/t_vas_krb5_get_credentials.php \
		tests/t_vas_krb5_validate_credentials.php \
		# end of missing tests

EXTRA_DIST += $(TESTS)
