CC  = gcc
CPP = g++

################################################################
INCDIR = -I./include
CFLAGS = -fPIC -lpthread
CPPFLAGS = -fPIC -g -W -Wall -std=c++11 -w -I. -I../.. -I../../../.. -DWEBRTC_WIN -D__native_client__ #-DOPENSSL_NO_SSL_INTERN 

LIBDIR = -L./lib
LINK_FLAGS = -w -g -D__STDC_CONSTANT_MACROS
LIBS =  -lstdc++ -ljsoncpp -lcrypto -lssl 
ifeq ($(OS),Windows_NT)
	LIBS += -lws2_32 -lpsapi -lsecur32 -lwinmm
endif
################################################################

PROGRAM = server

OBJS = ../../../rtc_tools/simple_command_line_parser.o #main.o \

################################################################
# The directories in which source files reside.
# At least one path should be specified.  

SRCDIRS   := .        # current directory  

################################################################
# search all subdirs

DIRDEPTH := 
DIRPATH := . ../../../rtc_base 
ifeq ($(DIRDEPTH),)
	SRCDIRS := $(shell find $(DIRPATH) -type d)
else ifeq ($(DIRDEPTH),)
	SRCDIRS := $(shell find $(DIRPATH) -type d)
else
	SRCDIRS := $(shell find $(DIRPATH) -maxdepth $(DIRDEPTH) -type d)
endif

################################################################
# The source file types (headers excluded).  
# At least one type should be specified.  
# The valid suffixes are among of .c, .C, .cc, .cpp, .CPP, .c++, .cp, or .cxx.  
# SRCEXTS   := .c .cpp # C/C++ program  

SRCEXTS   := .cc

ifneq ($(SRCDIRS),)
ifneq ($(SRCEXTS),)
	SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))  
	OBJS += $(foreach x,$(SRCEXTS), $(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES))))  
endif
endif

################################################################
# The object file filter (included or excluded).  
# FILTER_IN   := %.c %.s      # included
# FILTER_OUT   := %.o %.cc   # excluded

FILTER_IN := 
FILTER_OUT := 

OUT_SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*test*,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*libevent,$(SRCEXTS))))  
#OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*queue_win,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/unix*,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*posix,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/mac*,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*converter,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*gcd,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*quic*,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/logcat_trace_context,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*darwin*,$(SRCEXTS))))  
#OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*opensslstreamadapter,$(SRCEXTS))))  
#OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*openssl*,$(SRCEXTS))))  

FILTER_OUT := $(foreach x,$(SRCEXTS), $(patsubst %$(x),%.o,$(filter %$(x),$(OUT_SOURCES))))  

ifneq ($(FILTER_IN),)
	OBJS := $(filter $(FILTER_IN), $(OBJS))
endif

ifneq ($(FILTER_OUT),)
	OBJS := $(filter-out $(FILTER_OUT), $(OBJS))
endif
################################################################

DEBUGOBJS = $(patsubst %.o,%.d,$(OBJS))  

$(PROGRAM): $(OBJS)
	$(CPP) $(LINK_FLAGS) -o $@  $(OBJS) $(LIBDIR) $(LIBS) 

clean:
	clear
	rm -rf $(OBJS) *.o $(PROGRAM)

################################################################
#$(OBJS):%.o :%.c  先用$(OBJS)中的一项，比如foo.o: %.o : %.c  含义为:试着用%.o匹配foo.o。如果成功%就等于foo。如果不成功，  
# Make就会警告，然后。给foo.o添加依赖文件foo.c(用foo替换了%.c里的%)  
# 也可以不要下面的这个生成规则，因为下面的 include $(DEF)  就隐含了。此处为了明了，易懂。故留着  

#compile c source file
%.o: %.c
	$(CC) $(CFLAGS) $(INCDIR) -c $< -o $@
%.o: %.C
	$(CC) $(CFLAGS) $(INCDIR) -c $< -o $@

#compile c++ source file
%.o: %.cpp
	$(CPP) $(CPPFLAGS) $(INCDIR) -c $< -o $@
%.o: %.cp
	$(CPP) $(CPPFLAGS) $(INCDIR) -c $< -o $@
%.o: %.CPP
	$(CPP) $(CPPFLAGS) $(INCDIR) -c $< -o $@
%.o: %.cc
#	@echo $(OBJS)
	$(CPP) $(CPPFLAGS) $(INCDIR) -c $< -o $@
%.o: %.cxx
	$(CPP) $(CPPFLAGS) $(INCDIR) -c $< -o $@
%.o: %.c++
	$(CPP) $(CPPFLAGS) $(INCDIR) -c $< -o $@
################################################################
