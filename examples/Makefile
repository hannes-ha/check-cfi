CXX = clang++
CC = clang

CFLAGS = -fsanitize=cfi -fvisibility=hidden -flto -fuse-ld=gold
IGNORELIST = -fsanitize-ignorelist=half_ignorelist.txt

TARGETS = half_indirect indirect single_indirect vcall

all: $(TARGETS)

half_indirect: half_indirect.c
	$(CC) $(CFLAGS) $(IGNORELIST) -o $@ $<

indirect: indirect.c
	$(CC) $(CFLAGS) -o $@ $<

single_indirect: single_indirect.c
	$(CC) $(CFLAGS) -o $@ $<

vcall: vcall.cpp
	$(CXX) $(CFLAGS) -o $@ $<

.PHONY: clean all

clean :
	rm -f $(TARGETS)
