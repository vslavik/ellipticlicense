
LDFLAGS += -lcrypto
CFLAGS += --std=c99 -I../../c_api

SRC_FILES = elgen.c \
			../../c_api/elliptic_license.c ../../c_api/base32.c


all: elgen

elgen: $(SRC_FILES)
	$(CC) -o $@ $(SRC_FILES) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f elgen
