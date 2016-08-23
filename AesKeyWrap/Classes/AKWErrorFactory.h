//
//  AKWErrorFactory.h
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <Foundation/Foundation.h>

/**
 List and factory of possible errors during ciphering/deciphering process
 */

typedef NS_ENUM(NSInteger, AKWErrorFactoryType) {
    AKWErrorFactoryTypeInputDataTooSmall = 0,
    AKWErrorFactoryTypeInputDataTooBig,
    AKWErrorFactoryTypeInputDataNotAlignedProperly,
    AKWErrorFactoryTypeInvalidKeyEncryptionKey,
    AKWErrorFactoryTypeEncryptionFailed,
    AKWErrorFactoryTypeOverflow,
    AKWErrorFactoryTypeIntegrityCheckingOfAlternativeInitialValueFailed
};

NS_ASSUME_NONNULL_BEGIN

extern NSString * const AKWErrorFactoryDomain;

@interface AKWErrorFactory : NSObject

/** Returned when the plain data is not at least 1 byte or the encryption data is less than 16 bytes */
+ (NSError *)errorInputDataTooSmall;

/** Returned when the input data is bigger than the methods can handle, for example, the input data can not be bigger than 2^32 bytes */
+ (NSError *)errorInputDataTooBig;

/** Returned when the ciphered input data is not a multiple of 64 bits */
+ (NSError *)errorInputDataNotAlignedProperly;

/** Returned when the Key Encryption Key does not have the right size: kCCKeySizeAES128 (16), kCCKeySizeAES192 (24) or kCCKeySizeAES256 (32) bytes */
+ (NSError *)errorInvalidKeyEncryptionKey;

/** Returned if any problem happens while ciphering/deciphering the input data */
+ (NSError *)errorEncryptionFailed;

/**
 During the ciphering/deciphering process, the methods perform multiple arithmetic operations, if any of these operations fails because of an overflow, they will return this error
 */
+ (NSError *)errorOverflow;

/**
 Returned when the deciphered data does not pass the verification described in RFC 5649, for example, when the Key Encryption Key provided was not the original one
 */
+ (NSError *)errorIntegrityCheckingOfAlternativeInitialValueFailed;

@end

NS_ASSUME_NONNULL_END
