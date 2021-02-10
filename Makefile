
LIB += aes_gcm.so
CFLAGS += -fPIC
CFLAGS += -shared
LDFLAGS += -I/usr/include/lua5.3
SRC_DIR:= src
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:.c=.o)
CC = gcc

${LIB}: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJ) ${LIB}