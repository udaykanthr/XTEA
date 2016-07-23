src = $(wildcard *.c)
obj = $(src:.c=.o)

# LDFLAGS = -lGL -lglut -lpng -lz -lm
LDFLAGS = -lz -lm

myprog: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) myprog
