all: pcapplay_ossl

EXTRACFLAGS=-g -DHAVE_GSL
EXTRACPPFLAGS=-g -DHAVE_GSL
EXTRALFLAGS=-lgsl -lgslcblas
#EXTRALIBS=-lgsl -lgslcblas -lm
EXTRALIBS=-static -lgsl -lgslcblas -lm
#EXTRALIBS=-lefence -lgsl -lgslcblas -lm
EXTRAENDLIBS=-lkrb5 -lk5crypto -lcom_err  -lresolv
