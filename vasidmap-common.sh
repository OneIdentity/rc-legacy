# (c) 2012 Quest Software, Inc. All rights reserved.
# Common shell functions for vasidmap scripts

# check_parm
# check_and_fix
# check_and_rename
# debug_echo
# detect_opsys 
# detect_samba_settings
# die
# echon
# is_lt
# query
# search_for_smbd
# vas_version
# vas_workgroup
# joined_domain_netbios_name
# vas_domainsid
# yesorno
# joined_domain_info

# Common VAS tools and files
VASTOOL=/opt/quest/bin/vastool
VAS_CONF=/etc/opt/quest/vas/vas.conf
VAS_KEYTAB=/etc/opt/quest/vas/host.keytab
VASIDMAPD=/opt/quest/sbin/vasidmapd

# regular expressions strings used in the check_* functions:
TAB='	'			# single tab \x09
SP='[ $TAB]'			# white space
LSP='\[ $TAB\]'			# escaped SP regex
META='[][/*+.()]'		# regex metachar
METASUBST='s/'"$META"'/[\\&]/g'	# sed script to escape metachars

AWK=awk
test -x /bin/nawk && AWK=/bin/nawk

# ini_get <section> <param-name> [<filename>]
#   Extracts the first definition or a parameter from the given section
#   Returns true if the value was found and printed; false otherwise
ini_get () {
    PREG=`echo "$2" | sed 's/\\*/\\\*/g' | sed "s/$SP$SP*/$LSP$LSP*/g"`
    $AWK "/^$SP*\\[/ { in_section = 0; }
	 /^$SP*\\[$1\\]/ { in_section=1; }
         /^$SP*$PREG$SP*=$SP*/ && in_section { 
	    sub( /^[^=]*$SP*=$SP*/ , \"\"); print; found=1; }
	 END { exit(found ? 0 : 1) } " $3
}

# ini_put <section> <param-name> <value> [<filename>]
#   Replaces or inserts a parameter definition in a file stream.
#   Returns true if the value was changed; false if no change was needed
#   Note: the resulting file content is written to stdout. 
ini_put () {
    PREG=`echo "$2" | sed 's/\\*/\\\*/g' | sed -e "s/$SP$SP*/$LSP$LSP*/g"`
    VALUE=`echo "$3" | sed -e "$METASUBST"`
    $AWK "/^$SP*\\[/ { 
	    if (in_section && !found) 
		{ print \"  $2 = \" newvalue; found = 1; changed = 1; }
	    in_section = 0; }
	 /^$SP*\\[$1\\]/ {
	    section_found = 1; 
	    in_section = 1; 
	 }
	 /^$SP*$PREG$SP*=$SP*$VALUE$SP*\$/ && in_section { found = 1; }
         /^$SP*$PREG$SP*=$SP*/ && in_section && !found { 
	    oldline = \$0;
	    sub(/[=].*/, \"= \" newvalue); 
	    found = 1; 
	    changed = (oldline != \$0);
	 }
	 { print } 
	 END { 
	    if (!section_found) 
		{ print \"[$1]\"; changed = 1; }
	    if (!found)
		{ print \"  $2 = \" newvalue; changed = 1; }
	    exit(changed ? 0 : 1) 
	 } " newvalue="$3" $4
}

# ini_del <section> <param-name> [<filename>]
#   Removes all matching parameter definitions from the file:
#     [section]
#       param-name = ...
#   Empty sections are left.
#   Returns true if the parameter was found and removed.
#   Note: the resulting file stream is written to stdout
ini_del () {
    PREG=`echo "$2" | sed 's/\\*/\\\*/g' | sed -e "s/$SP$SP*/$LSP$LSP*/g"`
    $AWK "/^$SP*\\[/ { in_section = 0; }
	 /^$SP*\\[$1\\]/ { in_section=1; }
         /^$SP*$PREG$SP*=$SP*/ && in_section { found = 1; }
	 { if (found) {changed=1; found=0;} else print; }
	 END { exit(changed ? 0 : 1) } " $3
}


# check_parm <param-name> <config-file>
#   Checks if the parameter is defined in the config file, by searching
#   for lines of the form
#       [section]
#         param-name = ...
#   Returns 0 only if a parameter definition is found
check_parm () {
    ini_get "global" "$1" "$2" > /dev/null
}


# check_and_fix <param-name> <correct-value> <config-file>
#   Checks if the parameter is defined incorrectly in the config file, and
#   if so, replaces it. If the parameter is not defined, no action is taken.
#   Returns 0 if the parameter was defined and/or corrected.
#   Returns 1 if the parameter was not defined in the config-file.
#   Exits the script if there is an error correcting the config-file
check_and_fix () {
	debug_echo "check_and_fix: $1 = $2"
	if oldvalue=`ini_get "global" "$1" "$3"`; then
	    # the parameter definition exists
	    if ini_put "global" "$1" "$2" "$3" > "$3.new"; then
	     # the value was changed
	     verbose_echo "Correcting parameter '$1' from '$oldvalue' to '$2'"
	     cat "$3.new" > "$3" || exit 1
	    fi
	    rm "$3.new"
	    return 0
	else
	    return 1 # parameter was not defined at all
	fi
}

# check_and_add <param-name> <value> <config-file>
#   Checks if the parameter is defined incorrectly in the config file, and
#   if so, repalce it. If the paramter is not defined then define it.
#   Returns 0 if the parameter was added or corrected.
#   Returns 1 otherwise
#   Exits the script if there is an error correcting the config-file
check_and_add()
{
  debug_echo "check_and_fix_add2: $1 = $2"
  if oldvalue=`ini_get "global" "$1" "$3"`; then
    # the parameter definition exists
    if ini_put "global" "$1" "$2" "$3" > "$3.new"; then
      # the value was changed
      verbose_echo "Correcting parameter '$1' from '$oldvalue' to '$2'"
      cat "$3.new" > "$3" || exit 1
    fi
      rm "$3.new"
      return 0
  else
    if ini_put "global" "$1" "$2" "$3" > "$3.new"; then
      # the value was added
      verbose_echo "Adding parameter '$1' with value '$2'"
      cat "$3.new" > "$3" || exit 1
    fi
      rm "$3.new"    
      return 0 # parameter was not defined at all
  fi

  return 1
}

# check_and_remove <param-name> <config-file>
# Removes definitions of param-name
# Returns 0 if removal occured.
# Exits the script if updating the config-file fails.
check_and_remove() {
  debug_echo "check_and_remove: $1"
  if value=`ini_get "global" "$1" "$2"`; then
    # the parameter definition exists
        ini_del "global" "$1" "$2" > "$2.new"
        verbose_echo "Removing parameter '$1'"
        cat "$2.new" > "$2" || exit 1
        return 0
  else
        return 1
  fi
}

# check_and_rename <old-param-name> <new-param-name> <config-file>
#   Replaces definitions of old-param-name with new-param-name.
#   Returns 0 if a renaming occurred.
#   Exits the script if updating config-file fails.
check_and_rename () {
	debug_echo "check_and_rename $1 -> $2"
	if value=`ini_get "global" "$1" "$3"`; then
	    ini_del "global" "$1" "$3" |
	    ini_put "global" "$2" "$value" > "$3.new"
	    verbose_echo "Renaming parameter '$1' to '$2'"
	    cat "$3.new" > "$3" || exit 1
	    return 0
	else
	    return 1
	fi
}

# debug_echo <text>
#   Prints a message to standard error if $DEBUG is defined and set to true
debug_echo () {
    if test x"$DEBUG" = x"true"; then
	echo "$0: $*" >&2
    fi
}

# verbose_echo <text>
#   Prints a message to standard output unless $QUIET is set to true.
verbose_echo () {
    if test x"$QUIET" != x"true"; then
	echo "$*"
    fi
}
# detect_opsys
#   Detects then sets the variable $OPSYS to represent the
#   current operating system.
detect_opsys () {
    if test -z "$OPSYS"; then
	OPSYS=`uname -s || echo unknown`
    fi
}

#
# Determines if we are running in a chroot
#
chrooted() {
   if [ "$(stat -c %d/%i /)" = "$(stat -Lc %d/%i /proc/1/root 2>/dev/null)" ]; then
	   # the devicenumber/inode pair of / is the same as that of
	   # /sbin/init's root, so we're *not* in a chroot and hence
	   # return false.
	   return 1
   fi
   return 0
}

# detect_samba_settings /path/to/smbd [/path/to/smb.conf]
#   Uses the samba server to set various $SAMBA_* variables, including:
#   $SAMBA_SBINDIR	location of server programs (eg smbd)
#   $SAMBA_BINDIR	location of tool programs (eg net)
#   $SAMBA_CONFIGFILE	location of smb.conf
#   $SAMBA_PRIVATE_DIR  location of private files, like secrets.tdb
#   $SAMBA_VERSION	version "x.y.z" string stripped of vendor information
detect_samba_settings () {
    #typeset d

    # Set $SAMBA_* variables from the server's hardcoded paths.
    SAMBA_VERSION=`$1 -V | sed -n -e 's/^Version \([0-9.]*\).*/\1/p'`
    test -n "$SAMBA_VERSION" || return 1
    eval `$1 -b | 
	sed -n '1,/^Paths:/d;/^$/q;s/^   \([^: ]*\): \(.*\)/SAMBA_\1="\2"/p'`
    # Override SAMBA_CONFIGFILE if possible
    test -n "$2" && SAMBA_CONFIGFILE="$2"
    # Correct SAMBA_PRIVATE_DIR
    d=`$SAMBA_BINDIR/testparm -s "$SAMBA_CONFIGFILE" 2>/dev/null | 
	sed -n -e '1d;/^\[/q;s/^	private dir = //p'` &&
	    SAMBA_PRIVATE_DIR="$d"
}

# detect_vas
#   Detects VAS and sets $VAS_VERSION to the current version number
detect_vas () {
    #typeset version

    if test -z "$VAS_VERSION"; then
	VAS_VERSION=`$VASTOOL -v | sed -n -e '1s/.*Version \([0-9.]*\).*/\1/p'`
	debug_echo "VAS version: $VAS_VERSION"
    fi
    test -n "$VAS_VERSION"
}

# die <text>
#   Prints a message to standard error, and exits the script in error
die () {
    echo "ERROR: $*" >&2
    exit 1
}

# die_cat
#   Prints the text on standard input to standard error and exits with an error
#   Intended to be used like this:
#       die_cat <<-.
#             Something bad just happened!
#       .
die_cat () {
    cat >&2
    exit 1
}

# echon <text>
#   Emits text without a newline.
#   The code below figure out the right way to do echon.
_echo1 () { echo -n "$*"; }
_echo2 () { echo "$*\\c"; }
_echo3 () { echo "$* +"; }
if test "x`_echo1 y`z" = "xyz"; then
	echon () { _echo1 "$*"; }
elif test "x`_echo2 y`z" = "xyz"; then
	echon () { _echo2 "$*"; }
else
	echon () { _echo3 "$*"; }
fi

# is_lt <version1> <version2>
#   Returns true if dotted version string version1 is less than version2
is_lt () {
    a="$1" b="$2"
    while test -n "$a" -o -n "$b"; do
	ah=`echo "$a" | sed -e 's/\..*//'`
	bh=`echo "$b" | sed -e 's/\..*//'`
	if test x"$ah" = x"$bh"; then
	    a=`echo "$a" | sed -e 's/^[^.]*//;s/^\.//'`
	    b=`echo "$b" | sed -e 's/^[^.]*//;s/^\.//'`
	    continue
	fi
	{ echo "$ah"; echo "$bh"; } | sort -n -c 2>/dev/null
	return
    done
    return 1
}

# query <prompt> <varname> [default-response]
#   Prompts the user for a response, and sets $varname to that given.
#   If a blank line response is given, then $varname is set to the 
#   default-response (or the empty string).
query () {
	eval $2=
	while eval "test ! -n \"\$$2\""; do
	    echon "$1${3+ [$3]}: " >&2
	    eval "read $2" || die "(end of file)"
	    eval : "\${$2:=\$3}"
	done
}

# search_for_smbd
#   Prints the path to a working smbd (NOT quest smbd).
#   Returns false if no smbd could be found.
search_for_smbd () {
    #typeset search smbd

    # Either the search list of smbds is given to us, or we have
    # to construct our own 'best guess'
    detect_opsys
    case $OPSYS in
	HP-UX)
	    search=/opt/samba/sbin/smbd
	    ;;
	Linux)
	    search=/usr/sbin/smbd
	    ;;
	SunOS)
	    search=/opt/csw/sbin/smbd 
	    ;;
	AIX)
	    search=`echo /opt/pware/samba/*/sbin/smbd`
	    ;;
	Darwin)
            search=/usr/sbin/smbd
            ;;
    esac
    search="/opt/quest/sbin/smbd $search /usr/local/sbin/smbd"

    #-- test each smbd candidate for existence and whether they can
    #   respond to the -V version request. Set $smbd to the result
    smbd=
    for s in $search; do 
	if test -x "$s" && "$s" -V >/dev/null 2>/dev/null; then 
	    smbd=$s
	    break
	fi
    done
    test -n "$smbd" && echo $smbd	    # Returns false if smbd is not set
}

# vas_workgroup [vastool-options]
#   Determines the currently joined workgroup.
#   Uses vastool to query the default directory and find its NetBIOS name
#   Extra arguments are passed directly to vastool (eg, -u host/).
vas_workgroup () {
    #typeset rootDNC
    forestDNC=`$VASTOOL "$@" info forest-root-dn 2>/dev/null ||
	       $VASTOOL "$@" search -q -s base -b '' \
		"(rootDomainNamingContext=*)" \
		rootDomainNamingContext` &&
    rootDNC=`$VASTOOL "$@" info domain-dn 2>/dev/null || 
             $VASTOOL "$@" search -q -s base -b '' \
		"(rootDomainNamingContext=*)" \
		rootDomainNamingContext` &&
    $VASTOOL "$@" \
	search -q -b "CN=Partitions,CN=Configuration,$forestDNC" -s sub \
	"nCName=$rootDNC" \
	nETBIOSName
}

# joined_domain_netbios_name [vastool-options]
#   Determines the currently joined netbios name.
#   Uses vastoo
#   Extra arguments are passed directly to vastool (eg, -u host/).
#
joined_domain_netbios_name () {

  NETBIOS=

  for SERVER in `$VASTOOL "$@" info servers | grep -v "^Servers"`; do
        NETBIOS="`$VASTOOL "$@" info cldap $SERVER 2>/dev/null | grep -i \"Server Netbios Domain:\" | awk '{print $4}'`"
	if [ -n "$NETBIOS" ]; then
	  break
        fi
  done

  if [ -z "$NETBIOS" ]; then

  for SERVER in `$VASTOOL "$@" info servers -s * | grep -v "^Servers"`; do
    NETBIOS="`$VASTOOL "$@" info cldap $SERVER 2>/dev/null | grep -i \"Server Netbios Domain:\" | awk '{print $4}'`"
    if [ -n "$NETBIOS" ]; then
      break
    fi
  done
  
  fi

  test -n "$NETBIOS" && echo "$NETBIOS"
}

# vas_domainsid [vastool-options]
#   Returns the domain SID for the currently joined domain.
#   If not joined to a domain, then returns the domain SID for the root.
vas_domainsid () {
    rootDNC=`$VASTOOL "$@" info domain-dn 2>/dev/null || 
             $VASTOOL "$@" search -q -s base -b '' \
		"(rootDomainNamingContext=*)" \
		rootDomainNamingContext` &&
    $VASTOOL "$@" \
	attrs -q -b -d "$rootDNC" objectSid
}


# yesorno <question> [default-response]
#   Prompts the user for a yes-no question.
#   Re-prompting will occur if the user enters a blank line and there
#   is no default-response.
#   Returns 0 for Yes, 1 for No.
yesorno () {
	echo "";
	while :; do
	    query "$1" YESORNO $2
	    case "$YESORNO" in
		Y*|y*) echo; return 0;;
		N*|n*) echo; return 1;;
		*) echo "Please enter 'y' or 'n'" >&2;;
	    esac
	done
}

# joined_domain_info
#
#  $1 server
#  $2 cldap attributes: Possible values:
#     Server_IP, Server_Forest, Server_Domain, Server_Hostname,
#     Server_Netbios_Domain, Server_Netbios_Hostname, Server_Site,
#     Client_Site.
#
#  Returns a ":" delim string of attribute values about the queried server
#
#  EXAMPLE: joined_domain info "example.com" "server_ip server_Netbios_name"
#
joined_domain_info() {
  DOMAIN="$1"
  ATTRS=`echo $2 | tr '[A-Z]' '[a-z]'`
  VALUES=

  for INFO in "`/opt/quest/bin/vastool info cldap $DOMAIN`"; do
    for ATTR in $ATTRS; do

      ATTR=`echo $ATTR | tr '[_]' '[ ]'`

      KEY=`echo "$INFO" | sed 's,:.*,,' | grep -i "^$ATTR" | tr '[A-Z]' '[a-z]'`

      if [ x"$KEY" = x"$ATTR" ]; then
       if [ -z "$VALUES" ]; then
         VALUES=`printf "%s\n" "$INFO" | grep -i "^$ATTR"| sed 's,[^:]*:,,' | awk '{print $1}'`
       else
         VALUES=$VALUES:`printf "%s\n" "$INFO" | grep -i "^$ATTR"| sed 's,[^:]*:,,' | awk '{print $1}'`
       fi
      fi
    done
  done

  test -n "$VALUES" && echo "$VALUES"
}

