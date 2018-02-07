CXX=g++

CPPFLAGS=-g -std=c++11

LDFLAGS=

INC_DIR=-I/home/jack/unicorn-1.0.1/include

LIB_DIR=-L/home/jack/unicorn-1.0.1

LIBS=-lunicorn -lpthread -lstdc++fs

RM=rm -f


SRCS=pe-run-snapshot.cpp syscall_macro.cpp syscall_win7.cpp fk_memory.cpp fk_file.cpp pe_socket.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

all: pe-run-snapshot

pe-run-snapshot: $(OBJS)
	$(CXX) -o pe-run-snapshot $(OBJS) $(LDFLAGS) $(LIB_DIR) $(LIBS)

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CXX) $(CPPFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS) pe-run-snapshot ./.depend


#distclean: clean
#    $(RM) *~ .depend
	
include .depend
