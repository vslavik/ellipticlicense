//
//  elliptic_license.h
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

#ifndef elliptic_license_h
#define elliptic_license_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/// Type of the elliptic curve used to create the keys
typedef enum
{
    el_curve_secp112r1 = 112, ///< 112-bit keys
    el_curve_secp128r1 = 128, ///< 128-bit keys
    el_curve_secp160r1 = 160  ///< 160-bit keys
} el_curve_t;

/// EL context
typedef struct el_context* el_context_t;

/**
    Creates a new context for use with other functions.

    @param  curve           Type of the curve - and so key length - to use.
    @param  publicKeyData   Public key to use.
    @param  publicKeyLength Length of @a publicKeyData data.

    @return Pointer to the context object or NULL on failure.
 */
el_context_t el_create_context(el_curve_t curve,
                               const uint8_t *publicKeyData, int publicKeyLength);

/// Destroys previously created context
void el_destroy_context(el_context_t ctxt);

/**
    Sets list of blocked (blacklisted) keys that should not be accepted.

    Typically, this functionality is used to block keys for refunded purchases
    or pirated keys so that they aren't recognized as valid anymore.

    The @a keyHashes array contains SHA-1 hashes of blocked keys (20 bytes per
    hash). The hashes are computed from license keys (not names) by first
    decoding the user-entered key as base32 (see el_base32_decode()) and then
    calculating SHA-1 hash of the decoded data.

    The @a keyHashes pointer must remain valid as long as @a ctxt is being used;
    this function does not make a copy.

    Example:
    
        static const uint8_t blocked_keys[] = {
          // Key A7MS6-VWIW5-35WFV-72XMU-FLGMH-CTGTJ-FPHYX-DUMTF-V3CQY:
          0xE9,0x4D,0x1B,0xFC,0x06,0xCB,0x97,0x8F,0xE3,0xC6,0xF9,0xBD,0x25,0x51,0xB1,0xA9,0xEA,0xFF,0x66,0x18,
          // Key BMLMP-LKIFU-V65IW-V4A6D-EDFRG-OFGWS-4MA5X-EGFQM-KC2MI:
          0xBC,0x7D,0x4D,0x63,0xB3,0xBA,0xFA,0x53,0xFA,0xC0,0x42,0x8E,0x97,0xDA,0x60,0x21,0xB9,0x45,0x7A,0x68
        };
        el_set_blocked_keys(ctxt, blocked_keys, sizeof(blocked_keys));

    @param ctxt       EL context.
    @param keyHashes  Array of SHA-1 hashes of blacklisted keys.
    @param dataSize   Size (in bytes) of @a keyHashes array.
 */
void el_set_blocked_keys(el_context_t ctxt,
                         const uint8_t *keyHashes, int dataSize);

/**
    Verifies validity of the license key.
    
    @param ctxt       EL context.
    @param licenseKey The key, as a base32-encoded string.
    @param name       UTF-8 encoded identifier of license holder (e.g. name).
    
    @return 0 if the key is invalid, nonzero if valid.
 */
int el_verify_license_key(el_context_t ctxt,
                          const char *licenseKey, const char *name);


/**
    Calculates SHA-256 digest of the input, truncated to requested size in bytes.

    @param name         UTF-8 encoded string to create digest for; typically
                        a customer name or email.
    @param digest       Buffer to write the digest to.
    @param digestSize   Length of the requested digest in bytes. This must be
                        less or equal to SHA-256 digest size (32 bytes).
 */
void el_compute_digest(const char *name, uint8_t *digest, int digestSize);

/**
    Upper bound for the length of decoded base32 data.

    @note Actual length may be smaller because of padding characters
          (hypnens, whitespace) in the base32-encoded input.
 */
int el_base32_decode_buffer_size(int stringLength);

/**
    Size of the buffer needed to encode data of given length to base32.
    
    @note The returned value includes space for the terminating NULL character.
 */
int el_base32_encode_buffer_size(int dataLength);

/**
    Decodes base32 (RFC 4648/3548) data.

    In addition to the base32 alphabet, whitespace and hyphens are allowed,
    but all other characters are considered invalid.

    @param encoded   NULL-terminated string to decode.
    @param result    Pointer to output buffer.
    @param bufSize   Size of the @a result buffer.

    @return The number of output bytes or -1 on error.

    @note If the output buffer is too small, the result will silently be truncated.
    
    @see el_base32_decode_buffer_size()
 */
int el_base32_decode(const char *encoded, uint8_t *result, int bufSize);

/**
    Encodes data in base32 (RFC 4648/3548).

    @param data      Data to encode.
    @param length    Size of @a data.
    @param result    Pointer to output buffer for the string. The data will be
                     NULL-terminated if there's enough room in the buffer for it.
    @param bufSize   Size of the @a result buffer.

    @return The number of output bytes or -1 on error.

    @note If the output buffer is too small, the result will silently be truncated.

    @see el_base32_encode_buffer_size()
 */
int el_base32_encode(const uint8_t *data, int length, char *result, int bufSize);

#ifdef __cplusplus
}
#endif

#endif // elliptic_license_h
