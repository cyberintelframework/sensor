#!/bin/sh

KEYID=91987C36
MAKEROOT=/home/gijs/makerelease
DISTRIBUTION=lenny
REPOSITORY=/opt/surfnetids/repositories/surfids

# Clean up previous build
cd $MAKEROOT
rm surfids-sensor_*

## Update to latest version
# If this fails, please checkout the sensor trunk:
# cd $MAKEROOT
#  svn co http://svn.ids.surfnet.nl/surfids/sensor/trunk
cd $MAKEROOT/sensor-trunk
svn update

# Increment changelog entry
dch -i -m
svn commit

## create the package
# if this doesn't work, create a chroot environment for your distribution:
# pbuilder --create --basetgz $DISTRIBUTION.tgz--distribution $DISTRIBUTION \
#  --mirror http://ftp.nl.debian.org/debian
pdebuild -- --basetgz /home/gijs/makerelease/chrootimg/$DISTRIBUTION.tgz


# Collect results and sign
cd $MAKEROOT
sudo mv /var/cache/pbuilder/result/surfids-sensor_* .
debsign -k$KEYID surfids-sensor_*_i386.changes

# add package to repository
cd $REPOSITORY
sudo reprepro include $DISTRIBUTION $MAKEROOT/surfids-sensor_*_i386.changes


