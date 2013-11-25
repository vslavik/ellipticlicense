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

#include <stdint.h>

/**
    Decodes base32 (RFC 4648/3548) data.

    In addition to the base32 alphabet, white-space and hyphens are allowed,
    but all other characters are considered invalid.

    @param encoded   NULL-terminated string to decode.
    @param result    Pointer to output buffer.
    @param bufSize   Size of the @a result buffer.

    @return The number of output bytes or -1 on error.

    @note If the output buffer is too small, the result will silently be truncated.
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
 */
int el_base32_encode(const uint8_t *data, int length, char *result, int bufSize);

#endif // elliptic_license_h
