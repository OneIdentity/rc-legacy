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
    $bindir/vasidmap-config
    $bindir/vas-samba-config
    $bindir/vas-samba-config-native
    $bindir/vasidmap
    $sbindir/vasidmapd
    $sbindir/vas-set-samba-password
    $libexecdir/vas-set-samba-password-native
    $libexecdir/vasidmap-krb5-config
    $mandir/man8/vasidmapd.8
    $mandir/man1/vasidmap.1

%service vasidmapd
    cmd="$sbindir/vasidmapd -F"
