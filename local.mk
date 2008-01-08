# Remove '#' if you want to enable GSL features (pause)
#  EXTRACPPFLAGS=-DHAVE_GSL -I`if test -f /usr/local/lib/libgsl.so; then echo /usr/local; else echo ./ext; fi;`/include
#  EXTRACFLAGS=-DHAVE_GSL -I`if test -f /usr/local/lib/libgsl.so; then echo /usr/local; else echo ./ext; fi;`/include
#  EXTRALIBS=-L`if test -f /usr/local/lib/libgsl.so; then echo /usr/local; else echo ./ext; fi;`/lib -lgsl -lgslcblas
