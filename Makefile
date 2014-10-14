CC = gcc
CFALGS = -w -g
CPP =  $(CC) -E
AR = ar
ARFALGS = -qcs
RM = rm -rf

DIR  = /home/wrt/decoder
LIB = $(DIR)/lib
BIN = $(DIR)/bin
INC = $(DIR)/inc
TEST = $(DIR)/test
VMX = $(DIR)/vmx_xml2


TARGET =  libvmx1.so
OBJDIR = $(DIR)/objs
OBJS = $(OBJDIR)/vmx1.o


$(TARGET): $(OBJDIR) $(OBJS)
	$(CC) $(CFALGS) -shared -o $@  $(OBJS) -I/usr/local/include/libxml2  -I $(INC)  -lpthread -static -L$(LIB)  -lxml2

$(OBJS):$(VMX)/vmx1.c  
	$(CC) $(CFALGS) -fPIC -c $<  -o $@ -I $(INC) -I/usr/local/include/libxml2

$(OBJDIR):
	mkdir -p $@

clean:
	-$(RM)  $(OBJDIR)  $(TARGET)
