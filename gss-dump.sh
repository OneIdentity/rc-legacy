#!/bin/sh
# (c) 2009 Quest Software, Inc. All rights reserved.
#
# Use wireshark to decode and display the content of GSSAPI tokens.
# 
# Usage: gss-dump [-k keytab]
#
#     -k keytab      Use the keytab for decrypting token content
#

: ${TSHARK:=tshark}   # Use environment variable $TSHARK, otherwise search PATH
: ${TEXT2PCAP:=text2pcap}
TMP="${TMPDIR-/tmp}/dumpb64$$.pcap"

set -- `getopt k: "$@"`
keytab=
error=false
while test $# -gt 0; do
    case $1 in
        --)  shift; break;;
        -k)  echo "Using keytab: $2";   # "-k keytab" option
             keytab="$2"; shift;;
        *)  error=true;;
    esac
    shift
done

if $error || test $# -gt 0; then
    echo "usage: $0 [-k keytab]" >&2
    exit 1
fi

while :; do
   test -t && printf "Input: " >&2
   # Read lines until a '.' is seen
   DATA=
   while :; do 
       read REPLY || exit 0
       DATA="$DATA $REPLY"
       case "$REPLY"
            in *.) break;;
       esac
   done
   DATA=`echo "$DATA" | tr -d ' .'` # strip out whitespace and dots
   # fabricate a packet capture file
   printf "GET /\r\nWWW-Authenticate: Negotiate %s\r\n\r\n" "$DATA" |
     od -Ax -tx1 | 
       $TEXT2PCAP -q -T 1,2 - "$TMP" || exit 1

   test -t && echo "Decoded:" >&2
   $TSHARK -d tcp.port==1,http -V \
       ${keytab+-o Kerberos.decrypt:true -o Kerberos.file:"$keytab"} \
           -r "$TMP" |
       # Strip out the 'fabricated' parts
       sed -n -e '1,/WWW-Authenticate:/d;s/^        //;/^[ ]*\\r\\n$/q;p'
   rm -f $TMP
done
