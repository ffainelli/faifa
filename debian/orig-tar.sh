#!/bin/sh -e

# $1 version
TAR=../faifa_$1.orig.tar.gz
DIR=faifa-$1.orig
REVISION=`echo $1 | sed -e 's/.*svn//'`
BASESVN=trunk

# clean up the upstream tarball
svn export -r $REVISION https://svn.open-plc.org/$BASESVN $DIR
# Rework Makefile (remove distclean debian handling)
patch -d $DIR -p0 < debian/patches/Makefile.patch
GZIP=--best tar -c -z -f $TAR -X debian/orig-tar.exclude $DIR
rm -rf $DIR

# move to directory 'tarballs'
if [ -r .svn/deb-layout ]; then
  . .svn/deb-layout
  mv $TAR $origDir
  echo "moved $TAR to $origDir"
fi

exit 0

