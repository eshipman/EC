CC = gcc
FLAGS = -O3 -pedantic -ansi -Wall
EXE = a.out

main: main.c defs.h
	${CC} ${FLAGS} defs.h main.c -o ${EXE}

clean:
	rm -rf ${EXE}
