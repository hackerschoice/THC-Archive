#!/bin/sh
# dosfndecode - dos filename decoder
# (c) 2000 by plasmoid / thc <plasmoid@pimmel.com>
#
# convert files cutted to the dos extension (8.3 format) into proper unix
# files by evaluating the ident definition. the ident definition can be
# found in correct formated source trees, as for e.g. *surprise* *surprise*
# the solaris source. 
# 
# this tool comes really handy if you have the broken solaris 2.7 source
# that is flying around. but don't ask us, we don't have warez. sorry!
#

prepath=`pwd`

if [ "x$1" = "x" -o ! -d $1 ] ; then
   echo "dos filename decoder - (C) 2000 by plasmoid / thc <plasmoid@pimmel.com>"
   echo "usage: $0 dir"
   echo "       where dir is the directory to convert recursively"
   exit 0
fi

for j in `find $1 -type d` ; do 
echo " entering $j"
cd $j
   for i in * ; do 
      identline=`egrep -se \("#ident"\|"#pragma ident"\) $i`

      if [ "x$identline" != "x" -a "x`echo $0 | grep $i`" = "x" ] ; then
         newname=`echo $identline | sed s/@\(\#\)/!/g | cut -d! -f2`
         newname=`echo $newname | awk '{ print $1 }'`
         if [ "x`echo $newname | grep :`" != "x" ] ; then
            newname=`echo $newname | cut -d: -f2`
         fi
         if [ $i != $newname ] ; then
            echo " -- converting $i -> $newname"
            mv -f $i $newname
         fi
      fi
   done
echo " leaving $j"
cd $prepath
done
exit 1
