%set
    name="vasidmapd"
    description="VAS idmap module for Samba"

%depend
    samba 3.0.22

%files
    /opt/quest/bin/vasidmap-config
    /opt/quest/bin/vasidmap-preload
    /opt/quest/bin/vasidmap
    /opt/quest/sbin/vasidmapd

%service vasidmapd
    cmd=/opt/quest/sbin/vasidmapd

