CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -Wall -Wextra -O2 -I. -fsanitize=address -g
ARFLAGS ?= rcs

LDFLAGS ?= -fsanitize=address
LIBS    ?= -lssl -lcrypto -L. -laccumulator

LIBNAME   := libaccumulator.a
TARGET    := main

LIBSRC    := accumulator.c
LIBOBJ    := $(LIBSRC:.c=.o)

MAINSRC   := main.c
MAINOBJ   := $(MAINSRC:.c=.o)

OBJS := $(LIBOBJ) $(MAINOBJ)

DEPFLAGS := -MMD -MP

.PHONY: all clean distclean

all: $(TARGET)


$(LIBNAME): $(LIBOBJ)
	$(AR) $(ARFLAGS) $@ $^

$(TARGET): $(MAINOBJ) $(LIBNAME)
	$(CC) $(LDFLAGS) -o $@ $(MAINOBJ) -L. -laccumulator -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

-include $(OBJS:.o=.d)

clean:
	$(RM) $(OBJS) $(OBJS:.o=.d) $(TARGET) $(LIBNAME)

distclean: clean
	$(RM) *~ core
