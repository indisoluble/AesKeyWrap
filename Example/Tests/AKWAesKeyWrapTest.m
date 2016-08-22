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
    NSData *plainData = [self emptyData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:&error];

    // then
    XCTAssertNil(cipheredData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataTooSmall);
}

- (void)testEmptyCipheredDataAndValidKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self emptyData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataTooSmall);
}

- (void)testNotAlignedCipheredDataAndValidKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self anyNotAlignedCipherData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataNotAlignedProperly);
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

- (void)testValidCipheredDataAndInvalidKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self anyValidCipheredData];
    NSData *kek = [self anyInvalidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:&error];

    // then
    XCTAssertNil(plainData);
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
    NSData *expectedCipheredData = [self dataWithHexString:@"138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd192BitKek_unwrapCipheredData_returnExpected20OctetsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"c37b7e6492584340 bed1220780894115 5068f738"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
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
    NSData *expectedCipheredData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd192BitKek_unwrapCipheredData_returnExpected7OctetsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"466f7250617369"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)testCipheredDataAnd192BitUnrelatedKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176aa"];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeIntegrityCheckingOfAlternativeInitialValueFailed);
}

#pragma mark - Private methods

- (NSData *)emptyData
{
    return [NSData data];
}

- (NSData *)anyValidPlainData
{
    u_char bytes[1];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)anyValidCipheredData
{
    u_char bytes[2 * sizeof(uint64_t)];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)anyNotAlignedCipherData
{
    u_char bytes[(2 * sizeof(uint64_t)) + 1];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
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
