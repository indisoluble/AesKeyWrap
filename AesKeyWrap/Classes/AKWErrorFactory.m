//
//  AKWErrorFactory.m
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import "AKWErrorFactory.h"

NSString * const AKWErrorFactoryDomain = @"AKWErrorFactoryDomain";

@implementation AKWErrorFactory

#pragma mark - Public class methods

+ (NSError *)errorEmptyData
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeEmptyData
                           userInfo:nil];
}

+ (NSError *)errorDataOverSizeLimit
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeDataOverSizeLimit
                           userInfo:nil];
}

+ (NSError *)errorInvalidKeyEncryptionKey
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeInvalidKeyEncryptionKey
                           userInfo:nil];
}

+ (NSError *)errorEncryptionFailed
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeEncryptionFailed
                           userInfo:nil];
}

+ (NSError *)errorOverflow
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeOverflow
                           userInfo:nil];
}

@end
