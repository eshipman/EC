
CC = gcc
FLAGS = -O3
EXE = a.out
TEST = b.out

main: main.c defs.h
	${CC} ${FLAGS} defs.h main.c -o ${EXE}

test: test.c defs.h
	${CC} ${FLAGS} defs.h test.c -o ${TEST}

clean:
	rm -rf ${EXE} ${TEST}