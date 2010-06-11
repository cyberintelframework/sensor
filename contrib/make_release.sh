#!/bin/sh

KEYID=91987C36
MAKEROOT=/home/build/sensor
DIST=lenny
REPOSITORY=/opt/surfnetids/repositories/surfids
CHROOTBUILD=/home/build/chrootimg/$DIST.tgz
CHROOTTEST=/home/build/chrootimg/$DIST_test.tgz
MIRROR=http://ftp.nl.debian.org/debian


# Clean up previous build
cd $MAKEROOT
rm surfids-sensor_*

# Update or create the chroot environment
if [ -s $CHROOTBUILD ]
then
    sudo pbuilder --update --basetgz $CHROOTBUILD --distribution $DIST --mirror $MIRROR
else
    sudo pbuilder --create --basetgz $CHROOTBUILD --distribution $DIST --mirror $MIRROR
fi


## Update to latest version
# If this fails, please checkout the sensor trunk:
# cd $MAKEROOT
#  svn co http://svn.ids.surfnet.nl/surfids/sensor/trunk
rm -rf $MAKEROOT/sensor-trunk
svn export http://svn.ids.surfnet.nl/surfids/sensor/trunk sensor-trunk
cd $MAKEROOT/sensor-trunk
#svn update

# Increment changelog entry
dch -i -m
#svn commit

## create the package
pdebuild -- --basetgz $CHROOTBUILD


### Test the package
#if [ -s $CHROOTTEST ]
#then
#    sudo piuparts -b  $CHROOTTEST -d $DIST *.deb -m $MIRROR
#else
#    sudo piuparts -s  $CHROOTTEST -d $DIST *.deb -m $MIRROR
#   # check exit code
#fi


# Collect results and sign
cd $MAKEROOT
sudo mv /var/cache/pbuilder/result/surfids-sensor_* .
debsign -k$KEYID surfids-sensor_*_i386.changes

# add package to repository
cd $REPOSITORY
sudo reprepro include $DIST $MAKEROOT/surfids-sensor_*_i386.changes


