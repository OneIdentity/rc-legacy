%set
    name="vasidmapd"
    description="VAS idmap module for Samba"
    prefix=/opt/quest
    bindir=$prefix/bin
    sbindir=$prefix/sbin
    mandir=$prefix/man

%depend
    quest-samba 3.0.23

%files
    $bindir/vasidmap-config
    $bindir/vasidmap-preload
    $bindir/vasidmap
    $sbindir/vasidmapd
    $mandir/man8/vasidmapd.8

%service vasidmapd
    cmd="$sbindir/vasidmapd -F"

