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

+ (NSError *)errorInputDataTooSmall
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeInputDataTooSmall
                           userInfo:nil];
}

+ (NSError *)errorInputDataTooBig
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeInputDataTooBig
                           userInfo:nil];
}

+ (NSError *)errorInputDataNotAlignedProperly
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeInputDataNotAlignedProperly
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

+ (NSError *)errorIntegrityCheckingOfInitialValueFailed
{
    return [NSError errorWithDomain:AKWErrorFactoryDomain
                               code:AKWErrorFactoryTypeIntegrityCheckingOfInitialValueFailed
                           userInfo:nil];
}

@end
