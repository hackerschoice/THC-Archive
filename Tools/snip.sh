#!/bin/sh
# snip (c) copyright 2000 by plasmoid / thc <plasmoid@pimmel.com>
# 
# snippy lil' snip script that shows accessible smb-netbios shares 
# in a given ip-range. - requires smbclient and nbtscan. 
#
# $Id: snip,v 1.2 2001/04/18 19:17:59 plasmoid Exp $

# set the right paths here, if smbclient and nbtscan are not within your
# path. 
SMBCLIENT=smbclient
NBTSCAN=nbtscan
ECHO=echo

if [ "`$ECHO -n`" != "-n" ] ; then
   GNUECHO=1
fi

$ECHO "snip (c) copyright 2000 by plasmoid / thc <plasmoid@pimmel.com>"

if [ -z "$*" ] ; then
   $ECHO "usage: snip <scan_range>"
   $ECHO "<scan_range>    what to scan. can either be single IP like "
   $ECHO "                xxx.xxx.xxx.xxx or range of addresses in one "
   $ECHO "                of two forms xxx.xxx.xxx.xxx/xx or "
   $ECHO "                xxx.xxx.xxx.xxx-xxx."
   exit 
fi

if [ "x$GNUECHO" = "x1" ] ; then
   $ECHO -n " - snipping $1: "
else
   $ECHO " - snipping $1: \c"
fi

servers=`$NBTSCAN -s : $1 | grep \<server\> | \
         sed s/" "/"%"/g | cut -d : -sf 1,2,4`
$ECHO "done."

if [ "x$GNUECHO" = "x1" ] ; then 
   $ECHO -n " - searching shares: "
else
   $ECHO " - searching shares: \c"
fi
for i in $servers ; do
   
   i=`$ECHO $i | sed s/"%"/" "/g`
   
   ip=`$ECHO $i | cut -d : -sf 1`
   host=`$ECHO $i | cut -d : -sf 2 | awk '{ print $1 }'`
   user=`$ECHO $i | cut -d : -sf 3`
   
   if [ "x$user" = "x<unknown>" ] ; then
      smbarg="-I $ip -L $host -N"
   else
      smbarg="-I $ip -L $host -N -U $user"
   fi 

   output=`$SMBCLIENT $smbarg | grep Disk | awk '{ print $1 }'`
   for j in $output ; do 
      if [ "x$user" = "x<unknown>" ] ; then
         result="$result\n$SMBCLIENT //$host/$j -I $ip -N"
      else
         result="$result\n$SMBCLIENT //$host/$j -I $ip -N -U $user"
      fi
   done 
if [ "x$GNUECHO" = "x1" ] ; then
   $ECHO -n "."
else
   $ECHO ".\c"
fi
done
$ECHO " done."
$ECHO " - results: "
$ECHO "$result"


