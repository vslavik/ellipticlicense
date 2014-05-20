//
//  elliptic_license.c
//  EllipticLicense
//
//  Copyirght (c) 2013 Vaclav Slavik
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

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>


struct el_context
{
    EC_KEY*    ecKey;
    el_curve_t curve;
    int        digestLength;
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
            digestLength = 14;
            break;
        case el_curve_secp128r1:
            key = EC_KEY_new_by_curve_name(NID_secp128r1);
            digestLength = 16;
            break;
        case el_curve_secp160r1:
            key = EC_KEY_new_by_curve_name(NID_secp160r1);
            digestLength = 20;
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

    // TODO: blocked keys checking

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

    free(signatureData);
    free(digest);
    ECDSA_SIG_free(signature);

    return result;
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