CC      ?= gcc
CFLAGS   = -Wall -Wextra -Wformat-security -O3 -fstack-protector-all
LIBS  = -lnetfilter_queue -lnfnetlink
PROGRAM  = notsodeep
SOURCE   = notsodeep.c

all: notsodeep 

notsodeep: notsodeep.c
	$(CC) $(SOURCE) $(CFLAGS) $(LIBS) -o $(PROGRAM)

clean:
	@rm -rf $(PROGRAM)
