# GIT_DESC is provided by external include
include version.mk

# To allow sudo make install without mandating root to define PIN_ROOT
ifneq ("$(PIN_ROOT)", "")
    CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
    include $(CONFIG_ROOT)/makefile.config
    include $(TOOLS_ROOT)/Config/makefile.default.rules
endif

TOOL_CXXFLAGS+=-DGIT_DESC=\"$(GIT_DESC)\"

PREFIX=/usr/local

all: ia32 intel64

$(OBJDIR)sqlite3$(OBJ_SUFFIX): sqlite3.c sqlite3.h
	$(CC) $(TOOL_CFLAGS) -DSQLITE_THREADSAFE=0 -Wno-return-local-addr -Wno-misleading-indentation $(COMP_OBJ)$@ $<

$(OBJDIR)TracerMod.so: $(OBJDIR)TracerMod$(OBJ_SUFFIX) $(OBJDIR)sqlite3$(OBJ_SUFFIX)
	$(LINKER) $(TOOL_LDFLAGS_NOOPT) $(LINK_EXE)$@ $(^:%.h=) $(TOOL_LPATHS) $(TOOL_LIBS)

ia32:
	mkdir -p obj-ia32
	$(MAKE) TARGET=ia32 obj-ia32/TracerMod.so

intel64:
	mkdir -p obj-intel64
	$(MAKE) TARGET=intel64 obj-intel64/TracerMod.so

clean-all:
	$(MAKE) TARGET=ia32 clean
	$(MAKE) TARGET=intel64 clean

install:
	cp -a TracerMod $(PREFIX)/bin
	cp -a obj-* $(PREFIX)/bin
