%set
    name="quest-vasidmap"
    description="VAS idmap module for Samba"
    pp_solaris_name=QSFTidmap

#%depend
#    libvas.so.4.2
#    vasclnt 3.0.2

#%check
#    %(quest_require_vas 3.0.2)

%files
    $sbindir/vasidmapd
    $bindir/vasidmap
    $sbindir/vas-samba-config
    $sbindir/vas-krb5-config
    $libexecdir/vas-set-samba-password root:
    $pkgdatadir/vasidmap-common.sh
    $mandir/man*/*

%service vasidmapd
    cmd="$sbindir/vasidmapd -F"
