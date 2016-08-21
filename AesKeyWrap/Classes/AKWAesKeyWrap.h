//
//  AKWAesKeyWrap.h
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AKWAesKeyWrap : NSObject

+ (nullable NSData *)cipheredDataByWrappingPlainData:(NSData *)plainData
                                withKeyEncryptionKey:(NSData *)kek
                                               error:(NSError **)error;
+ (nullable NSData *)plainDataByUnwrappingCipheredData:(NSData *)cipheredData
                                  withKeyEncryptionKey:(NSData *)kek
                                                 error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
