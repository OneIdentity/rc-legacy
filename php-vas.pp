%set
 copyright="2007 Quest Software Inc. All rights reserved."
 pp_rpm_serial="${revision%M}"
 summary="PHP-VAS API bindings"
 description="php-vas is a PHP implementation of the Vintela Authentication\
 Services Developer SDK (PHP-VAS bindings). Using php-vas, you can write PHP\
 programs to the VAS API set."

 pp_solaris_name=php-vas

# AIX cannot handle non-digits in its version identifier
[aix] summary="$name $version"
[aix] version=`echo $version | tr _ . | tr -d a-zA-Z`

%files dev
# $libdir/*.a       ignore-others
 $prefix/include/*

%files
 $libdir/
 $libdir/**
 $lockdir/
 $piddir/            root:
 $logfilebase/
 $mandir/man*/*
 $spooldir/          1777

#[rpm] /sbin/*

%files doc
 $swatdir/
 $swatdir/**
[rpm] /etc/xinetd.d/swat-quest optional

# stuff to fix here...
%service nmbd-quest
    cmd="$prefix/sbin/pooporickie -F"
    group="ph-vas-quest"
    description="php-vas library"

# ...and here!
%post [sd]
    if /usr/bin/id php-vas >/dev/null 2>&1; then
      : php-vas user exists
    else
      /usr/sbin/groupadd php-vas || :
      /usr/sbin/useradd -g php-vas -d "/noexist/php-vas" -s /usr/bin/false -c "PHP-VAS user" php-vas
    fi
