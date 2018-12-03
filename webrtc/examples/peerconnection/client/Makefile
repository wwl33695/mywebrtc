CC  = gcc
CPP = g++

################################################################
INCDIR = -I./include
CFLAGS = -fPIC -lpthread
CPPFLAGS = -fPIC -g -W -Wall -std=c++11 -w -I. -I../.. -I../../../.. -I../../../../third_party/libsrtp/crypto/include \
			-I../../../../third_party/libsrtp/include \
			-DWEBRTC_WIN -D__native_client__ -DWEBRTC_APM_DEBUG_DUMP -DWEBRTC_INTELLIGIBILITY_ENHANCER

LIBDIR = -L./lib
LINK_FLAGS = -w -g -D__STDC_CONSTANT_MACROS
LIBS =  -lstdc++ -ljsoncpp -lcrypto -lssl 
ifeq ($(OS),Windows_NT)
	LIBS += -lws2_32 -lpsapi -lsecur32 -lwinmm -lgdi32
endif
################################################################
# set output binary file name

PROGRAM = client

# set output object file name

OBJS = ../../../common_types.o \

################################################################
# search all subdirs

DIRPATH := ../../../rtc_base ../../../p2p ../../../media ../../../api ../../../call ../../../system_wrappers \
			../../../video ../../../audio ../../../pc ../../../modules/rtp_rtcp

ifneq ($(DIRPATH),)
	SRCDIRS := $(shell find $(DIRPATH) -type d)
endif
################################################################
# The directories in which source files reside.
# At least one path should be specified.  
# add specific directory

SRCDIRS += .        

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

# my filter function
# $(1): objects
# $(2): filter string
my_string_filter_out = $(filter-out $(foreach v,$(1),$(if $(findstring $(2),$(v)),$(v),)), $1)

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
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/sctp*,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*opus*,$(SRCEXTS))))

OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/fakertp,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/fakewebrtccall,$(SRCEXTS))))  

OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*loopback,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/replay,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/srtpsession,$(SRCEXTS))))  


OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/video_frame_buffer,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/i420_buffer,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/simulcast_encoder_adapter,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/rent_a_codec,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/audio_device_impl,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/noise_suppression_impl,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/aec_core_mips,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/aec_core_neon,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/aecm_core_mips,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/aecm_core_neon,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/covariance_matrix_generator,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/ooura_fft_neon,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/window_capturer_win,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/mock_desktop_capturer_callback,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/desktop_frame_rotation,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/mouse_cursor_monitor_win,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/cropping_window_capturer_win,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/bwe_simulations,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/sink_filter_ds,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/video_capture_ds,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/video_capture_factory_windows,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/h264_encoder_impl,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/h264_decoder_impl,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/vp8_impl,$(SRCEXTS))))  
OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/vp9_noop,$(SRCEXTS))))  


#OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*opensslstreamadapter,$(SRCEXTS))))  
#OUT_SOURCES += $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*openssl*,$(SRCEXTS))))  

FILTER_OUT := $(foreach x,$(SRCEXTS), $(patsubst %$(x),%.o,$(filter %$(x),$(OUT_SOURCES))))  
ifneq ($(FILTER_OUT),)
	OBJS := $(filter-out $(FILTER_OUT), $(OBJS))
endif

OBJS := $(call my_string_filter_out,$(OBJS),test)
OBJS := $(call my_string_filter_out,$(OBJS),tools/)
OBJS := $(call my_string_filter_out,$(OBJS),android)
OBJS := $(call my_string_filter_out,$(OBJS),linux)
OBJS := $(call my_string_filter_out,$(OBJS),mac)
OBJS := $(call my_string_filter_out,$(OBJS),x11)
OBJS := $(call my_string_filter_out,$(OBJS),aec_dump)
OBJS := $(call my_string_filter_out,$(OBJS),audio_coding)
OBJS := $(call my_string_filter_out,$(OBJS),audio_processing)

OBJS := $(call my_string_filter_out,$(OBJS),desktop_capture)
OBJS := $(call my_string_filter_out,$(OBJS),video_coding)
OBJS := $(call my_string_filter_out,$(OBJS),video_capture)
OBJS := $(call my_string_filter_out,$(OBJS),video_processing)


FILTER_IN_STRING := 
FILTER_IN := $(foreach v,$(OBJS),$(if $(findstring $(FILTER_IN_STRING),$(v)),$(v),))
ifneq ($(FILTER_IN_STRING),)
	OBJS := $(filter $(FILTER_IN), $(OBJS))
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
