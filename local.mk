all: pcapplay_ossl

EXTRACFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm2\nIncludes: $(shell quilt applied)\n\""
EXTRACPPFLAGS=-g -DHAVE_GSL -DLOCAL_VERSION_EXTRA="\"-ibm2\nIncludes:  $(shell quilt applied )\n\""
EXTRALFLAGS=-lgsl -lgslcblas
EXTRALIBS=-static -lgsl -lgslcblas -lm
EXTRAENDLIBS=-lz -lkrb5 -lk5crypto -lcom_err -lresolv -ldl -lkrb5support
