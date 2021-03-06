//
//  AKWErrorFactory.h
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <Foundation/Foundation.h>

/**
 List possible errors during ciphering/deciphering process
 */

typedef NS_ENUM(NSInteger, AKWErrorFactoryType) {
    /** @see [AKWErrorFactory errorInputDataTooSmall] */
    AKWErrorFactoryTypeInputDataTooSmall = 0,
    /** @see [AKWErrorFactory errorInputDataTooBig] */
    AKWErrorFactoryTypeInputDataTooBig,
    /** @see [AKWErrorFactory errorInputDataNotAlignedProperly] */
    AKWErrorFactoryTypeInputDataNotAlignedProperly,
    /** @see [AKWErrorFactory errorInvalidKeyEncryptionKey] */
    AKWErrorFactoryTypeInvalidKeyEncryptionKey,
    /** @see [AKWErrorFactory errorEncryptionFailed] */
    AKWErrorFactoryTypeEncryptionFailed,
    /** @see [AKWErrorFactory errorOverflow] */
    AKWErrorFactoryTypeOverflow,
    /** @see [AKWErrorFactory errorIntegrityCheckingOfInitialValueFailed] */
    AKWErrorFactoryTypeIntegrityCheckingOfInitialValueFailed
};

/**
 Factory of possible errors during ciphering/deciphering process
 */

NS_ASSUME_NONNULL_BEGIN

extern NSString * const AKWErrorFactoryDomain;

@interface AKWErrorFactory : NSObject

/** Returned when the input data to cipher or decipher does not have the minimum required size */
+ (NSError *)errorInputDataTooSmall;

/** Returned when the input data is bigger than the methods can handle */
+ (NSError *)errorInputDataTooBig;

/** Returned when the input data is not a multiple of 64 bits */
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
 Returned when the deciphered data does not pass the verification described in RFC 3394 or RFC 5649, for example, when the Key Encryption Key provided was not the original one
 */
+ (NSError *)errorIntegrityCheckingOfInitialValueFailed;

@end

NS_ASSUME_NONNULL_END
