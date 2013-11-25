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

void el_compute_digest(const char *name, uint8_t *digest, int digestSize)
{
    uint8_t sha256_digest[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, name, strlen(name));
    SHA256_Final(sha256_digest, &sha256);

    memcpy(digest, sha256_digest, digestSize);
}