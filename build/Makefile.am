bin_PROGRAMS = mkbootimg unpackbootimg

mkbootimg_SOURCES = $(top_srcdir)/src/bootimg.h $(top_srcdir)/src/mkbootimg.c
mkbootimg_CFLAGS = $(LIBSSL_CFLAGS)
mkbootimg_LDADD = $(LIBSSL_LIBS)

unpackbootimg_SOURCES = $(top_srcdir)/src/bootimg.h \
						$(top_srcdir)/src/unpackbootimg.c
unpackbootimg_CFLAGS = $(LIBSSL_CFLAGS)
unpackbootimg_LDADD = $(LIBSSL_LIBS)

