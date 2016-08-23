//
//  AKWAesKeyWrap.h
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <Foundation/Foundation.h>

/**
 This class provides the methods to cipher/decipher a buffer of any data as specified in the RFC 3394 & RFC 5649.
 */

NS_ASSUME_NONNULL_BEGIN

@interface AKWAesKeyWrap : NSObject

/**
 Given a buffer and an encryption key, this method ciphers the first with the latest and return the new encrypted data.
 
 @param plainData Any number of bytes bewteen 1 and 2^32
 @param kek Key Encryption Key with kCCKeySizeAES128 (16), kCCKeySizeAES192 (24) or kCCKeySizeAES256 (32) bytes
 @param error It will be set to one of the errors described in `AKWErrorFactory` if there is a problem during the ciphering process, otherwise it will keep its original value
 
 @return The new ciphered data or nil, if there is an error
 
 @see AKWErrorFactory
 */
+ (nullable NSData *)cipheredDataByWrappingPlainData:(NSData *)plainData
                                withKeyEncryptionKey:(NSData *)kek
                                               error:(NSError **)error;

/**
 Given a buffer previously generated with cipheredDataByWrappingPlainData:withKeyEncryptionKey:error: and the same key used before, this method decipher the buffer and return the plain data.

 @param cipheredData A ciphered buffer generated with cipheredDataByWrappingPlainData:withKeyEncryptionKey:error: or any other method that conform to RFC 3394 & RFC 5649.
 @param kek Key Encryption Key with kCCKeySizeAES128 (16), kCCKeySizeAES192 (24) or kCCKeySizeAES256 (32) bytes
 @param error It will be set to one of the errors described in `AKWErrorFactory` if there is a problem during the deciphering process, otherwise it will keep its original value

 @return The plain data or nil, if there is an error

 @see AKWErrorFactory
 */
+ (nullable NSData *)plainDataByUnwrappingCipheredData:(NSData *)cipheredData
                                  withKeyEncryptionKey:(NSData *)kek
                                                 error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
