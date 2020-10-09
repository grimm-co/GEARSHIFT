all: simple simple.so
.PHONY: all

simple: simple.c
	$(CC) -O0 -DINCLUDE_MAIN -o simple simple.c
	strip simple

simple.so: simple.c
	$(CC) -shared -O0 -o simple.so simple.c
	strip simple.so
