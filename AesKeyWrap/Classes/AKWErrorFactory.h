//
//  AKWErrorFactory.h
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, AKWErrorFactoryType) {
    AKWErrorFactoryTypeEmptyData = 0,
    AKWErrorFactoryTypeDataOverSizeLimit,
    AKWErrorFactoryTypeInvalidKeyEncryptionKey,
    AKWErrorFactoryTypeEncryptionFailed,
    AKWErrorFactoryTypeOverflow
};

NS_ASSUME_NONNULL_BEGIN

extern NSString * const AKWErrorFactoryDomain;

@interface AKWErrorFactory : NSObject

+ (NSError *)errorEmptyData;
+ (NSError *)errorDataOverSizeLimit;
+ (NSError *)errorInvalidKeyEncryptionKey;
+ (NSError *)errorEncryptionFailed;
+ (NSError *)errorOverflow;

@end

NS_ASSUME_NONNULL_END
