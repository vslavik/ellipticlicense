//
//  elgen - command line utility for key generation
//  Part of EllipticLicense project
//
//  Tested on Mac OS X and Linux (x86 and x86_64)
//  Make sure to link against libcrypto 0.9.8 or later
//
//  Copyright (c) 2009 Dmitry Chestnykh, Coding Robots
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef __clang__
// OpenSSL is deprecated in OS X, but still good enough for licensing checks:
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>

#include "elliptic_license.h"

// Error codes
enum {
	ERR_STDIN_READ = 1,
	ERR_CURVE_UNKNOWN = 2,
	ERR_INIT_KEY = 3,
	ERR_PUBLIC_KEY_DECODING = 4,
	ERR_PRIVATE_KEY_DECODING = 5,
	ERR_WRONG_KEYS = 6,
	ERR_SIGNING = 7,
};

size_t hex2bin(unsigned char **bin, const char *hex)
{
	BIGNUM *bn = NULL;
	if (!BN_hex2bn(&bn, hex))
		return 0;
	size_t buf_len = (size_t)BN_num_bytes(bn);
	*bin = OPENSSL_malloc(buf_len);
	int len = BN_bn2bin(bn, *bin);
	BN_free(bn);
	return len;
}


int read_params(char *name, size_t name_size, char *curve_name, size_t curve_size, char *pubkey, size_t pubkey_size, char *privkey, size_t privkey_size)
{
	// Read "name\ncurve_name\npubkey\nprivkey\n from stdin
	if (fgets(name, name_size, stdin) == NULL ||
		fgets(curve_name, curve_size, stdin) == NULL ||
		fgets(pubkey, pubkey_size, stdin) == NULL ||
	    (fgets(privkey, privkey_size, stdin) == NULL && !feof(stdin)))
		return 0;
	// Get rid of \n
	size_t len;
	if ((len = strlen(name)) > 1)
		name[len-1] = '\0';
	if ((len = strlen(curve_name)) > 1)
		curve_name[len-1] = '\0';
	if ((len = strlen(pubkey)) > 1)
		pubkey[len-1] = '\0';
	if ((len = strlen(privkey)) > 1 && privkey[len] == '\n')
		privkey[len-1] = '\0';
	return 1;
}

int main (int argc, const char * argv[]) {
	
	EC_KEY *eckey;

	unsigned int curve;
	size_t digest_len;
	
	char name[1024], curve_name[200], pubkey[1024], privkey[1024];

	if (!read_params(name, 1024, curve_name, 200, pubkey, 1024, privkey, 1024))
		return ERR_STDIN_READ;
	
	///*debug*/printf("%s\n%s\n%s\n%s\n", name, curve_name, pubkey, privkey);
	
	// Get curve type and digest_len
	if (strcmp(curve_name, "secp112r1") == 0) {
		curve = NID_secp112r1;
		digest_len = 14;
	} else if (strcmp(curve_name, "secp128r1") == 0) {
		curve = NID_secp128r1;
		digest_len = 16;		
	} else if (strcmp(curve_name, "secp160r1") == 0) {
		curve = NID_secp160r1;
		digest_len = 20;		
	} else {
		return ERR_CURVE_UNKNOWN;
	}
	
	eckey = EC_KEY_new_by_curve_name(curve);
	if (eckey == NULL)
		return ERR_INIT_KEY;
	
	// set public key
	unsigned char *bin = NULL;
	size_t len = hex2bin(&bin, pubkey);
	if (len == 0)
		return ERR_PUBLIC_KEY_DECODING;
	const unsigned char *bin_copy = bin;
	eckey = o2i_ECPublicKey(&eckey, &bin_copy, len);
	OPENSSL_free(bin);
	
	// set private key
	len = hex2bin(&bin, privkey);
	if (len == 0)
		return ERR_PUBLIC_KEY_DECODING;
	bin_copy = bin;
	eckey = d2i_ECPrivateKey(&eckey, &bin_copy, len);
	OPENSSL_free(bin);
	
	// check keys
	if (!EC_KEY_check_key(eckey))
		return ERR_WRONG_KEYS;
	
	// calculate sha-1
	unsigned char digest[digest_len];
    el_compute_digest(name, digest, digest_len);

	// sign
    size_t signatureLength = 2 * digest_len;
    unsigned char *signatureBytes = OPENSSL_malloc(signatureLength);

    // The length of ECDSA_SIG's r and s components may be shorter than digestLength rarely
    // (see docs, incl. BN_num_bytes). We want fixed-length license keys, so just discard
    // these results.
    for (;;) {
        ECDSA_SIG *sig = ECDSA_do_sign(digest, digest_len, eckey);
        if (sig == NULL)
            return ERR_SIGNING;
        size_t rlen = BN_num_bytes(sig->r);
        size_t slen = BN_num_bytes(sig->s);
        if (rlen + slen == signatureLength) {
            BN_bn2bin(sig->r, signatureBytes);
            BN_bn2bin(sig->s, signatureBytes+rlen); // join two values into signatureBytes
            ECDSA_SIG_free(sig);
            break;
        }
        // else: try again
        ECDSA_SIG_free(sig);
    }
	
	size_t b32len = el_base32_encode_buffer_size(signatureLength);
	char *base32 = OPENSSL_malloc(b32len);
	memset(base32, 0, b32len);

    el_base32_encode(signatureBytes, signatureLength, base32, b32len);
	printf("%s", base32);
	
	OPENSSL_free(signatureBytes);
	OPENSSL_free(base32);
	return 0;
}
