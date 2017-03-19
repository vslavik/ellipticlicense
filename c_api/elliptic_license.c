//
//  elliptic_license.c
//  EllipticLicense
//
//  Copyright (c) 2013-2017 Vaclav Slavik
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


#include "elliptic_license.h"

#include <string.h>

#ifdef __clang__
// OpenSSL is deprecated in OS X, but still good enough for licensing checks:
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>

#define DIGEST_LENGTH_112   14
#define DIGEST_LENGTH_128   16
#define DIGEST_LENGTH_160   20
#define DIGEST_LENGTH_MAX   DIGEST_LENGTH_160

struct el_context
{
    EC_KEY*        ecKey;
    el_curve_t     curve;
    int            digestLength;
    const uint8_t *blockedKeys;
    int            blockedKeysCount;
};


el_context_t el_create_context(el_curve_t curve,
                               const uint8_t *publicKeyData, int publicKeyLength)
{
    EC_KEY *key = NULL;
    int digestLength = 0;

    switch (curve)
    {
        case el_curve_secp112r1:
            key = EC_KEY_new_by_curve_name(NID_secp112r1);
            digestLength = DIGEST_LENGTH_112;
            break;
        case el_curve_secp128r1:
            key = EC_KEY_new_by_curve_name(NID_secp128r1);
            digestLength = DIGEST_LENGTH_128;
            break;
        case el_curve_secp160r1:
            key = EC_KEY_new_by_curve_name(NID_secp160r1);
            digestLength = DIGEST_LENGTH_160;
            break;
    }

    if (!key)
        return NULL;
    key = o2i_ECPublicKey(&key, &publicKeyData, publicKeyLength);
    if (!key)
        return NULL;

    if (!EC_KEY_check_key(key))
    {
        EC_KEY_free(key);
        return NULL;
    }

    el_context_t ctxt = malloc(sizeof(struct el_context));
    ctxt->ecKey = key;
    ctxt->curve = curve;
    ctxt->digestLength = digestLength;
    ctxt->blockedKeys = NULL;
    ctxt->blockedKeysCount = 0;
    return ctxt;
}


void el_destroy_context(el_context_t ctxt)
{
    if (!ctxt)
        return;
    if (ctxt->ecKey)
        EC_KEY_free(ctxt->ecKey);
    free(ctxt);
}


int el_set_private_key(el_context_t ctxt,
                       const uint8_t *privateKeyData, int privateKeyLength)
{
    ctxt->ecKey = d2i_ECPrivateKey(&ctxt->ecKey, &privateKeyData, privateKeyLength);
    return ctxt->ecKey && EC_KEY_check_key(ctxt->ecKey);
}


void el_set_blocked_keys(el_context_t ctxt,
                         const uint8_t *keyHashes, int dataSize)
{
    ctxt->blockedKeys = keyHashes;
    ctxt->blockedKeysCount = dataSize / SHA_DIGEST_LENGTH;
}


int el_verify_license_key(el_context_t ctxt,
                          const char *licenseKey, const char *name)
{
    // TODO: change this back to use C99 variable length arrays once Visual C++
    //       can deal with it (2013 still can't)
    ECDSA_SIG *signature = NULL;
    uint8_t *signatureData = NULL;
    uint8_t *digest = NULL;

    if (!licenseKey || !strlen(licenseKey) || !name || !strlen(name))
        return 0;

    int signatureLength = el_base32_decode_buffer_size((int)strlen(licenseKey));

    signatureData = malloc(signatureLength);
    signatureLength = el_base32_decode(licenseKey, signatureData, signatureLength);

    // Check length of signature before verifying
    if (signatureLength != ctxt->digestLength * 2)
    {
        free(signatureData);
        return 0;
    }

    signature = ECDSA_SIG_new();
    if (!signature)
    {
        free(signatureData);
        return 0;
    }

    int partLen = signatureLength / 2;
    signature->r = BN_bin2bn(signatureData,           partLen, signature->r);
    signature->s = BN_bin2bn(signatureData + partLen, partLen, signature->s);
    if (!signature->r || !signature->s)
    {
        free(signatureData);
        ECDSA_SIG_free(signature);
        return 0;
    }

    digest = malloc(ctxt->digestLength);
    el_compute_digest(name, digest, ctxt->digestLength);

    int result = ECDSA_do_verify(digest, ctxt->digestLength, signature, ctxt->ecKey) == 1;

    // If the key was accepted, check it against a blacklist of blocked keys:
    if (result && ctxt->blockedKeys)
    {
        unsigned char sha1hash[SHA_DIGEST_LENGTH];
        SHA1(signatureData, signatureLength, sha1hash);
        const uint8_t *ptr = ctxt->blockedKeys;
        for (int i = 0; i < ctxt->blockedKeysCount; i++, ptr += SHA_DIGEST_LENGTH)
        {
            if (memcmp(sha1hash, ptr, SHA_DIGEST_LENGTH) == 0)
            {
                result = 0;
                break;
            }
        }
    }

    free(signatureData);
    free(digest);
    ECDSA_SIG_free(signature);

    return result;
}


int el_generate_license_key(el_context_t ctxt,
                            const char *name, char *output)
{
    int signatureLength = 2 * ctxt->digestLength;
    int bufferLength = el_base32_encode_buffer_size(signatureLength);

    if (output == NULL)
        return bufferLength;

    unsigned char digest[DIGEST_LENGTH_MAX];
    el_compute_digest(name, digest, ctxt->digestLength);

    unsigned char signatureBytes[2 * DIGEST_LENGTH_MAX];

    // The length of ECDSA_SIG's r and s components may be shorter than digestLength rarely
    // (see docs, incl. BN_num_bytes). We want fixed-length license keys, so just discard
    // these results.
    for (;;)
    {
        ECDSA_SIG *sig = ECDSA_do_sign(digest, ctxt->digestLength, ctxt->ecKey);
        if (sig == NULL)
            return -1;
        int rlen = BN_num_bytes(sig->r);
        int slen = BN_num_bytes(sig->s);
        if (rlen + slen == signatureLength)
        {
            BN_bn2bin(sig->r, signatureBytes);
            BN_bn2bin(sig->s, signatureBytes+rlen); // join two values into signatureBytes
            ECDSA_SIG_free(sig);
            break;
        }
        // else: try again
        ECDSA_SIG_free(sig);
    }

    el_base32_encode(signatureBytes, signatureLength, output, bufferLength);
    return bufferLength;
}


void el_compute_digest(const char *name, uint8_t *digest, int digestSize)
{
    uint8_t sha256_digest[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, name, strlen(name));
    SHA256_Final(sha256_digest, &sha256);

    memcpy(digest, sha256_digest, digestSize);
}
