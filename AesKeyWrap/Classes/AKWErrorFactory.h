//
//  AKWErrorFactory.h
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <Foundation/Foundation.h>

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

+ (NSError *)errorInputDataTooSmall;
+ (NSError *)errorInputDataTooBig;
+ (NSError *)errorInputDataNotAlignedProperly;
+ (NSError *)errorInvalidKeyEncryptionKey;
+ (NSError *)errorEncryptionFailed;
+ (NSError *)errorOverflow;
+ (NSError *)errorIntegrityCheckingOfAlternativeInitialValueFailed;

@end

NS_ASSUME_NONNULL_END
