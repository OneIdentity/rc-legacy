%set
    name="quest-vasidmap"
    description="VAS idmap module for Samba"
    pp_solaris_name=QSFTidmap
    pidfile="/var/run/vasidmapd.pid"
    daemon="/opt/quest/sbin/vasidmapd"
    summary="VAS idmap module for Samba"

%set [aix]
    pp_aix_pidfile="/var/opt/quest/vas/vasidmapd.pid"
    pp_aix_mkssys_cmd_args="-F -P $pp_aix_pidfile"
    pp_aix_mkssys_args=-R
    pp_aix_mkssys_group=quest-vas

%files
    $sbindir/vasidmapd
    $bindir/vasidmap
    $sbindir/vas-samba-config
    $sbindir/vas-krb5-config
    $libexecdir/vasidmap-status
    $libexecdir/vas-set-samba-password root:
    $pkgdatadir/vasidmap-common.sh
    $mandir/man*/*

# AIX doesn't want a pidfile set when creating a system service.
%service vasidmapd [!aix]
    pidfile="/var/run/vasidmapd.pid"

%service vasidmapd
    cmd="$sbindir/vasidmapd -D ${pidfile:+-P $pidfile}"

%post
svc=vasidmapd
