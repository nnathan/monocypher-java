CC = cc
MONO = monocypher.c
SRC = $(filter-out $(MONO), $(wildcard *.c))
EXE = $(SRC:.c=)

all: $(EXE)

%: %.c $(MONO)
	$(CC) -o $@ $^

clean:
	find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '.gitignore' -exec rm -f {} +
