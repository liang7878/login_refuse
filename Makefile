# contrib/login_refuse/Makefile

MODULE_big = login_refuse
OBJS = login_refuse.o

EXTENSION = login_refuse
DATA = login_refuse--0.1.sql

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/login_refuse
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif