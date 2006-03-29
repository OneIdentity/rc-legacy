# Set this to "srcdir" to build from SRCDIR as set below,
# otherwise HEAD will be built.
BUILD_FROM=not srcdir

NAME=vas_apps
BASE_VERSION=0.7.2
QUEST_VERSION=1
VERSION=${BASE_VERSION}q${QUEST_VERSION}
SOURCE=${NAME}-${VERSION}.tar.gz
PWD=$(shell pwd)
TOPDIR=${PWD}/..
SRCDIR=${TOPDIR}/heimdal
BUILDDIR=/var/tmp/build-vas_apps
EXT_DIST_DIR=/data/rc/pub/ext/heimdal
GPGV=gpg --verify

all: package

clean:
	-rm -rf ${BUILDDIR}
	-rm .*.stamp

prepare-source: .prepare-source.stamp

.prepare-source.stamp:
	mkdir -p ${BUILDDIR}
	( set -ex; \
		cd ${BUILDDIR}; \
		rm -rf ${NAME}-${VERSION}; \
		if [ "x${BUILD_FROM}" = "xsrcdir" ]; then \
			cp -r ${SRCDIR} ${NAME}-${VERSION}; \
			make -C ${NAME}-${VERSION} distclean; \
		else \
			svn co svn+ssh://cvsau/opt/svn/rc/vas-apps/trunk/heimdal ${NAME}-${VERSION}; \
		fi; \
		cd ${NAME}-${VERSION}; \
		autoreconf; \
		rm -rf autom4te.cache; \
		find . -name '*~' | xargs rm -rf || echo No tildefiles to remove; \
	)
	touch $@

patchfile: ${NAME}-${VERSION}.patch

${NAME}-${VERSION}.patch: prepare-upstream prepare-source
	( set -ex; \
		cd ${BUILDDIR}; \
		diff -ru --unidirectional-new-file -x .svn -x '*~' heimdal-${BASE_VERSION} ${NAME}-${VERSION} > ${PWD}/$@ || echo OK; \
	)

source-archive: source-archive-tgz

source-archive-tgz: ${NAME}-${VERSION}.tar.gz

${NAME}-${VERSION}.tar.gz: prepare-source
	( set -ex; \
		cd ${BUILDDIR}; \
		tar --exclude .svn -c ${NAME}-${VERSION} | gzip > ${PWD}/$@; \
	)

prepare-upstream: .prepare-upstream.stamp

.prepare-upstream.stamp:
	mkdir -p ${BUILDDIR} 
	cp ${EXT_DIST_DIR}/heimdal-${BASE_VERSION}.tar.gz* ${BUILDDIR}
	if [ -f ${BUILDDIR}/heimdal-${BASE_VERSION}.tar.gz.asc ]; then \
		(cd ${BUILDDIR}; ${GPGV} heimdal-${BASE_VERSION}.tar.gz.asc) || exit 1; \
	fi
	( set -ex; \
		cd ${BUILDDIR}; \
		tar -zxf heimdal-${BASE_VERSION}.tar.gz; \
	)
	touch $@

package: rpm

rpm: source-archive-tgz
	sudo rpm/build

.PHONY: clean package all patchfile prepare-upstream prepare-source \
	source-archive source-archive-tgz source-archive-bz2 rpm
