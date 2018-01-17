//
//  generate-key - command line utility for creation of crypto keys
//  Part of EllipticLicense project
//
//  Copyright (c) 2017-2018 Vaclav Slavik
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

#include <assert.h>
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

#define FORMAT_HEX     0
#define FORMAT_C       1
#define FORMAT_PYTHON  2

void dump_in_hex(const char *label, unsigned char *bin, size_t len, int format)
{
    printf("  %s:\t", label);

    switch (format)
    {
        case FORMAT_HEX:
            for (size_t i = 0; i < len; i++)
                printf("%02x", bin[i]);
            break;

        case FORMAT_C:
            printf("{ ");
            for (size_t i = 0; i < len; i++)
            {
                if (i > 0)
                    printf(",");
                printf("0x%02X", bin[i]);
            }
            printf(" };");
            break;

        case FORMAT_PYTHON:
            printf("b'");
            for (size_t i = 0; i < len; i++)
            {
                printf("\\x%02X", bin[i]);
            }
            printf("'");
            break;
    }
    printf("\n");
}

int main (int argc, const char * argv[])
{
    EC_KEY *eckey;
    unsigned int curve;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s {secp112r1|secp128r1|secp160r1}\n", argv[0]);
        return -2;
    }

    // Get curve type:
    if (strcmp(argv[1], "secp112r1") == 0)
        curve = NID_secp112r1;
    else if (strcmp(argv[1], "secp128r1") == 0)
        curve = NID_secp128r1;
    else if (strcmp(argv[1], "secp160r1") == 0)
        curve = NID_secp160r1;
    else
        return -1;

    eckey = EC_KEY_new_by_curve_name(curve);
    if (eckey == NULL)
        return -1;

    if (!EC_KEY_generate_key(eckey))
        return -1;

    unsigned char *public = NULL;
    int len_public = i2o_ECPublicKey(eckey, &public);

    unsigned char *private = NULL;
    int len_private = i2d_ECPrivateKey(eckey, &private);

    printf("\nHex-encoded:\n\n");
    dump_in_hex("public", public, len_public, FORMAT_HEX);
    dump_in_hex("private", private, len_private, FORMAT_HEX);

    printf("\nC:\n\n");
    dump_in_hex("public", public, len_public, FORMAT_C);
    dump_in_hex("private", private, len_private, FORMAT_C);

    printf("\nPython:\n\n");
    dump_in_hex("public", public, len_public, FORMAT_PYTHON);
    dump_in_hex("private", private, len_private, FORMAT_PYTHON);

    return 0;
}
