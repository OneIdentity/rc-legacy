%set
 copyright="2007 Quest Software Inc. All rights reserved."
 pp_rpm_serial="${revision%M}"
 summary="PHP-VAS API bindings"
 description="php-vas is a PHP implementation of the Vintela Authentication\
 Services Developer SDK (PHP-VAS bindings). Using php-vas, you can write PHP\
 programs to the VAS API set."

 name=php-vas
 pp_solaris_name=QSFTphpv

# AIX cannot handle non-digits in its version identifier
[aix] summary="$name $version"
[aix] version=`echo $version | tr _ . | tr -d a-zA-Z`

%files
 $scriptdir/
 $scriptdir/*.php
 $datadir/vas.*

%if -n "$docdir"
%files doc
 $docdir/
 $docdir/**
%endif

