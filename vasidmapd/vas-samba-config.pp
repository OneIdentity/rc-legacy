%set
    name="vas-samba-config"
    description="Setup ADS security for Samba"
    pp_solaris_name=QSFTsmbcfg
    summary="Setup ADS security for Samba"

%files
    $sbindir/vas-samba-config
    $sbindir/vas-krb5-config
    $libexecdir/vasidmap-status
    $libexecdir/vas-set-samba-password root:
    $pkgdatadir/vasidmap-common.sh
    $mandir/man*/*
