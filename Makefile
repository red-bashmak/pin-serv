LDLIBS += -lcrypto -luv -pthread
CFLAGS += -g -Wall -std=gnu11

build/server: build/server.o build/pin_block.o build/hex_codec.o build/msg.o

build/%.o: src/%.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	$(RM) build/*.o build/server
