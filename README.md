# AesKeyWrap

[![CI Status](http://img.shields.io/travis/indisoluble/AesKeyWrap.svg?style=flat)](https://travis-ci.org/indisoluble/AesKeyWrap)
[![Version](https://img.shields.io/cocoapods/v/AesKeyWrap.svg?style=flat)](http://cocoapods.org/pods/AesKeyWrap)
[![License](https://img.shields.io/cocoapods/l/AesKeyWrap.svg?style=flat)](http://cocoapods.org/pods/AesKeyWrap)

ObjC implementation of the AES Key Wrap with Padding Algorithm described in
[RFC 3394](https://tools.ietf.org/html/rfc3394) &
[RFC 5649](https://tools.ietf.org/html/rfc5649).

## Installation

AesKeyWrap is available through [CocoaPods](http://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod "AesKeyWrap"
```

## Usage

```objc
#import <CommonCrypto/CommonCryptor.h>

#import "AKWAesKeyWrap.h"

u_char buffer[kCCKeySizeAES192] = {...};
NSData *keyEncryptionKey = [NSData dataWithBytes:buffer length:kCCKeySizeAES192];

NSString *txt = @"Some text";

NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:[txt dataUsingEncoding:NSUTF8StringEncoding]
                                                 withKeyEncryptionKey:keyEncryptionKey
                                                                error:nil];
NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                withKeyEncryptionKey:keyEncryptionKey
                                                               error:nil];

XCTAssertEqualObjects([txt dataUsingEncoding:NSUTF8StringEncoding], plainData);
```

## License

AesKeyWrap is available under the MIT license. See the LICENSE file for more info.
