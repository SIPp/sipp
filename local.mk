all: pcapplay_ossl

#EXTRACFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm1\nIncludes: $(shell quilt applied)\n\""
#EXTRACPPFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm1\nIncludes:  $(shell quilt applied )\n\""
#EXTRACFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm1\"" -D_GNU_SOURCE -D__USE_LARGEFILE64 -D_FILE_OFFSET_BITS=64
#EXTRACPPFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm1\"" -D_GNU_SOURCE -D__USE_LARGEFILE64 -D_FILE_OFFSET_BITS=64

PATCHES=$(shell quilt applied |sed -e 's/^patches\///;s/\.diff//')
EXTRACFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm0 (with $(PATCHES))\"" -D__USE_LARGEFILE64 -D_FILE_OFFSET_BITS=64
EXTRACPPFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm0 (with $(PATCHES))\"" -D__USE_LARGEFILE64 -D_FILE_OFFSET_BITS=64
EXTRALIBS=-static -lgsl -lgslcblas -lm
EXTRAENDLIBS=-lz -lkrb5 -lk5crypto -lcom_err -lresolv -ldl -lkrb5support -lkeyutils -lselinux -lsepol
