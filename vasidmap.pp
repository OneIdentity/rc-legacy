%set
    name="vasidmapd"
    description="VAS idmap module for Samba"
    prefix=/opt/quest
    bindir=$prefix/bin
    sbindir=$prefix/sbin

%depend
    quest-samba 3.0.23

%files
    $bindir/vasidmap-config
    $bindir/vasidmap-preload
    $bindir/vasidmap
    $sbindir/vasidmapd

%service vasidmapd
    cmd="$sbindir/vasidmapd -F"

