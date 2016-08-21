//
//  AKWAesKeyWrapTest.m
//  AesKeyWrap
//
//  Created by Enrique de la Torre (dev) on 21/08/2016.
//  Copyright © 2016 Enrique de la Torre. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <XCTest/XCTest.h>

#import "AKWAesKeyWrap.h"
#import "AKWErrorFactory.h"

@interface AKWAesKeyWrapTest : XCTestCase

@end

@implementation AKWAesKeyWrapTest

- (void)testEmptyPlainDataAndValidKek_wrapPlainData_returnError
{
    // given
    NSData *plainData = [self emptyPlainData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:&error];

    // then
    XCTAssertNil(cipheredData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeEmptyData);
}

- (void)testValidPlainDataAndInvalidKek_wrapPlainData_returnError
{
    // given
    NSData *plainData = [self anyValidPlainData];
    NSData *kek = [self anyInvalidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:&error];

    // then
    XCTAssertNil(cipheredData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInvalidKeyEncryptionKey);
}

- (void)test20OctetsPlainDataAnd192BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"c37b7e6492584340 bed1220780894115 5068f738"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipherData = [self dataWithHexString:@"138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"];

    XCTAssertEqualObjects(cipheredData, expectedCipherData);
}

- (void)test7OctetsPlainDataAnd192BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"466f7250617369"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipherData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];

    XCTAssertEqualObjects(cipheredData, expectedCipherData);
}

#pragma mark - Private methods

- (NSData *)anyValidPlainData
{
    return [@"test" dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSData *)emptyPlainData
{
    return [NSData data];
}

- (NSData *)anyValidKeyEncryptionKey
{
    u_char rawKek[kCCKeySizeAES128];

    return [NSData dataWithBytes:rawKek length:sizeof(rawKek)];
}

- (NSData *)anyInvalidKeyEncryptionKey
{
    u_char rawKek[kCCKeySizeAES128 + 1];

    return [NSData dataWithBytes:rawKek length:sizeof(rawKek)];
}

- (NSData *)dataWithHexString:(NSString *)hexString
{
    NSString *replacedHexString = [hexString stringByReplacingOccurrencesOfString:@" "
                                                                       withString:@""];
    XCTAssertEqual(replacedHexString.length % 2, 0);

    NSMutableData *data = [NSMutableData data];

    NSRange range = NSMakeRange(0, 2);
    for (range.location = 0; range.location < replacedHexString.length; range.location += range.length)
    {
        u_char byte = [self byteInHexString:[replacedHexString substringWithRange:range]];

        [data appendBytes:&byte length:sizeof(u_char)];
    }

    return data;
}

- (u_char)byteInHexString:(NSString *)hexString
{
    NSScanner *scanner = [NSScanner scannerWithString:hexString];

    uint uintValue = 0;
    XCTAssertTrue([scanner scanHexInt:&uintValue]);

    return (u_char)uintValue;
}

@end
