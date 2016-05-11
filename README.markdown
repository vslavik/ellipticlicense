EllipticLicense
===============

*Note: this is an incompatible(!) fork of now-defunct https://github.com/dchest/ellipticlicense*


Short product key generation and validation framework based on elliptic curves digital signatures (ECDSA).
 for Mac OS X/Cocoa.

Project goal: replacement for AquaticPrime with shorter keys and similar or better security.

*Documentation will be available later... For now, read EllipticLicense.h*

[Watch screencast](http://www.youtube.com/watch?v=lcT8YcbUpg0)


## Installation

Modern enough OS X SDK (10.7 or up) is required. You must also have OpenSSL library and headers. Starting with OS X 10.11 SDK, OpenSSL 0.9.7 (which was deprecated in the SDK for years) headers are no longer available and you have to compile your own version of OpenSSL. A reasonable version that is known to work is `OpenSSL-OSX` from CocoaPods.

The easiest way to add EllipticLicense to your project is with CocoaPods:

    $ pod install EllipticLicense

Alternatively, simply include all files form the `c_api` folder in your project. It is recommend to use this API instead of the Objective-C one, because it cannot be introspected at runtime (unlike Obj-C) and so is somehow less vulnerable to being patched out.


## Example keys

112-bit curve (~ equivalent to RSA-512, 2^56 bit security):

	Licensed to: John Doe
	License key: HQYRV-OZFNZ-M3L7B-WA644-CXLG4-D7IRD-QZ6FY-GJGTO-MEXEG

128-bit curve (2^64 bit security):

	Licensed to: John Doe
	License key: YBFB-L264-32WL-KHK4-DA4L-L7VW-HGCV-PO3U-PFF6-RJHW-MRBS-5OW4-53WA
		
160-bit curve (~ equivalent to RSA-1024, 2^80 bit security):

	Licensed to: John Doe
	License key: IPAA6CH2-2STFJTCW-PYBDDBDM-YK4ZYA6N-3YE624E4-2K7KFDLE-LODJEN5W-WRADC652

## EllipticLicenseDeveloper App


There's a GUI application for managing your project public and private keys, generating licenses and blocking keys called EllipticLicenseDeveloper included.



License
--------

EllipticLicense is licensed under Apache 2 license. See LICENSE. License!


* * *

This fork maintained by [Vaclav Slavik](mailto:vslavik@fastmail.fm) (@vslavik)
Originally made by [Coding Robots](http://www.codingrobots.com)
