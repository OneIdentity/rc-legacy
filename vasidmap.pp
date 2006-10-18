%set
    name="vasidmapd"
    description="VAS idmap module for Samba"

#%depend
#    libvas.so.4.2
#    vasclnt 3.0.2

%check
    %(quest_require_vas 3.0.2)

%files
    $bindir/vasidmap-config
    $bindir/vasidmap-preload
    $bindir/vasidmap
    $sbindir/vasidmapd
    $mandir/man8/vasidmapd.8

%service vasidmapd
    cmd="$sbindir/vasidmapd -F"
