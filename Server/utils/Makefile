
LDFLAGS += -lcrypto
CFLAGS += --std=c99 -I../../c_api

LIB_SRC_FILES = ../../c_api/elliptic_license.c ../../c_api/base32.c

ELGEN_SRC_FILES = elgen.c $(LIB_SRC_FILES)
GENERATE_KEY_SRC_FILES = generate-key.c $(LIB_SRC_FILES)

all: elgen generate-key

elgen: $(ELGEN_SRC_FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

generate-key: $(GENERATE_KEY_SRC_FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f elgen
	rm -f generate-key
