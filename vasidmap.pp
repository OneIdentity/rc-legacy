%set
    name="vasidmapd"
    description="VAS idmap module for Samba"
    prefix=/opt/quest
    bindir=$prefix/bin
    sbindir=$prefix/sbin
    mandir=$prefix/man

#%depend
#    libvas.so.4

%files
    $bindir/vasidmap-config
    $bindir/vasidmap-preload
    $bindir/vasidmap
    $sbindir/vasidmapd
    $mandir/man8/vasidmapd.8

%service vasidmapd
    cmd="$sbindir/vasidmapd -F"

