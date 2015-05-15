//
//  NSData+ELAdditions.m
//  EllipticLicense
//
//  Created by Dmitry Chestnykh on 28.03.09.
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
//
//  Base32 encoding/decoding methods taken from public domain code at
//  http://www.cocoadev.com/index.pl?NSDataCategory


#import "NSData+ELAdditions.h"

#import "elliptic_license.h"

#ifdef __clang__
// OpenSSL is deprecated in OS X, but still good enough for licensing checks:
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#import "openssl/sha.h"

@implementation NSData (ELAdditions)

+ (NSData *)el_dataWithBase32String:(NSString *)encoded;
{
	if (! [encoded canBeConvertedToEncoding:NSASCIIStringEncoding]) return nil;
	const char *chars = [encoded UTF8String]; // avoids using characterAtIndex.

	int bytesLen = el_base32_decode_buffer_size((int)strlen(chars));
	uint8_t bytes[bytesLen];

    bytesLen = el_base32_decode(chars, bytes, bytesLen);
    if (bytesLen == -1)
        return nil;

	return [NSData dataWithBytes:bytes length:bytesLen];
}

- (NSString *)el_base32String;
{
	const uint8_t *bytes = [self bytes];
	int bytesLen = (int)[self length];

	int charsLen = el_base32_encode_buffer_size(bytesLen);
	char chars[charsLen];

    charsLen = el_base32_encode(bytes, bytesLen, chars, charsLen);
    if (charsLen == -1)
        return nil;

	return [NSString stringWithCString:chars encoding:NSASCIIStringEncoding];
}

- (NSData *)el_sha1Digest;
{
	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1([self bytes], [self length], digest);
	return [NSData dataWithBytes:digest length:SHA_DIGEST_LENGTH];
}

-  (NSString *)el_sha1DigestString;
{
	return [[self el_sha1Digest] el_hexString];
}

- (NSString *)el_hexString;
{
	const unsigned char *bytes = [self bytes];
	NSMutableString *hexString = [[NSMutableString alloc] initWithCapacity:[self length] * 2];
	for (int i = 0; i < [self length]; i++)
		[hexString appendFormat:@"%02x", (unsigned char)(bytes[i])];
	return [hexString uppercaseString];
}

+ (NSData *)el_dataWithHexString:(NSString *)hexString;
{
	NSMutableData *data = [NSMutableData dataWithCapacity:[hexString length]/2];
	char *chars = (char *)[hexString UTF8String];
	unsigned char value;
	while (*chars != '\0') {
		if (*chars >= '0' && *chars <= '9')
			value = (*chars - '0') << 4;
		else if (*chars >= 'a' && *chars <= 'f')
			value = (*chars - 'a' + 10) << 4;
		else if (*chars >= 'A' && *chars <= 'F')
			value = (*chars - 'A' + 10) << 4;
		else
			return nil;
		
		chars++;
		if (*chars >= '0' && *chars <= '9')
			value |= *chars - '0';
		else if (*chars >= 'a' && *chars <= 'f')
			value |= *chars - 'a' + 10;
		else if (*chars >= 'A' && *chars <= 'F')
			value |= *chars - 'A' + 10;
		else
			return nil;
		[data appendBytes:&value length:sizeof(value)];
		chars++;
	}
	return data;
}

@end
