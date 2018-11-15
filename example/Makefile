all: example example_secured

example: main.c cacheutils.h ../nospec.h
	clang main.c -o example -Os

example_secured: main.c cacheutils.h ../nospec.h
	clang main.c -o example_secured -Os -DSECURE

clean:
	rm -f example example_secured
