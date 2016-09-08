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

- (void)testTooSmallPlainDataAndValidKek_wrapPlainData_returnError
{
    // given
    NSData *plainData = [self anyTooSmallPlainData];
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

- (void)testNotAlignedPlainDataAndValidKek_wrapPlainData_returnError
{
    // given
    NSData *plainData = [self anyNotAlignedPlainData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:&error];


    // then
    XCTAssertNil(cipheredData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataNotAlignedProperly);
}

- (void)testTooSmallCipheredDataAndValidKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self anyTooSmallCipheredData];
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
    NSData *cipheredData = [self anyNotAlignedCipheredData];
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

- (void)testPlainDataAndInvalidKek_wrapPlainData_returnError
{
    // given
    NSData *plainData = [self anyPlainData];
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

- (void)testCipheredDataAndInvalidKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self anyCipheredData];
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

- (void)test128BitsPlainDataAnd128BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd128BitKek_unwrapCipheredData_returnExpected128BitsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)test128BitsPlainDataAnd192BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F1011121314151617"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd192BitKek_unwrapCipheredData_returnExpected128BitsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F1011121314151617"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)test128BitsPlainDataAnd256BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd256BitKek_unwrapCipheredData_returnExpected128BitsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)test192BitsPlainDataAnd192BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF0001020304050607"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F1011121314151617"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd192BitKek_unwrapCipheredData_returnExpected192BitsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F1011121314151617"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF0001020304050607"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)test192BitsPlainDataAnd256BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF0001020304050607"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd256BitKek_unwrapCipheredData_returnExpected192BitsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF0001020304050607"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)test256BitsPlainDataAnd256BitKek_wrapPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingPlainData:plainData
                                                     withKeyEncryptionKey:kek
                                                                    error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd256BitKek_unwrapCipheredData_returnExpected256BitsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)testCipheredDataAnd256BitUnrelatedKek_unwrapCipheredData_returnError
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"];
    NSData *kek = [self dataWithHexString:@"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E10"];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingCipheredData:cipheredData
                                                    withKeyEncryptionKey:kek
                                                                   error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeIntegrityCheckingOfInitialValueFailed);
}

- (void)testEmptyPlainDataAndValidKek_wrapWithPaddingPlainData_returnError
{
    // given
    NSData *plainData = [self emptyData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingWithPaddingPlainData:plainData
                                                               usingKeyEncryptionKey:kek
                                                                               error:&error];

    // then
    XCTAssertNil(cipheredData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataTooSmall);
}

- (void)testEmptyCipheredDataAndValidKek_unwrapWithPaddingCipheredData_returnError
{
    // given
    NSData *cipheredData = [self emptyData];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingWithPaddingCipheredData:cipheredData
                                                              usingKeyEncryptionKey:kek
                                                                              error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataTooSmall);
}

- (void)testNotAlignedCipheredDataAndValidKek_unwrapWithPaddingCipheredData_returnError
{
    // given
    NSData *cipheredData = [self anyNotAlignedCipheredDataToUnwrapWithPadding];
    NSData *kek = [self anyValidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingWithPaddingCipheredData:cipheredData
                                                              usingKeyEncryptionKey:kek
                                                                              error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInputDataNotAlignedProperly);
}

- (void)testPlainDataAndInvalidKek_wrapWithPaddingPlainData_returnError
{
    // given
    NSData *plainData = [self anyPlainDataToWrapWithPadding];
    NSData *kek = [self anyInvalidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingWithPaddingPlainData:plainData
                                                               usingKeyEncryptionKey:kek
                                                                               error:&error];

    // then
    XCTAssertNil(cipheredData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInvalidKeyEncryptionKey);
}

- (void)testCipheredDataAndInvalidKek_unwrapWithPaddingCipheredData_returnError
{
    // given
    NSData *cipheredData = [self anyCipheredDataToUnwrapWithPadding];
    NSData *kek = [self anyInvalidKeyEncryptionKey];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingWithPaddingCipheredData:cipheredData
                                                              usingKeyEncryptionKey:kek
                                                                              error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeInvalidKeyEncryptionKey);
}

- (void)test20OctetsPlainDataAnd192BitKek_wrapWithPaddingPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"c37b7e6492584340 bed1220780894115 5068f738"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingWithPaddingPlainData:plainData
                                                               usingKeyEncryptionKey:kek
                                                                               error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd192BitKek_unwrapWithPaddingCipheredData_returnExpected20OctetsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingWithPaddingCipheredData:cipheredData
                                                              usingKeyEncryptionKey:kek
                                                                              error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"c37b7e6492584340 bed1220780894115 5068f738"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)test7OctetsPlainDataAnd192BitKek_wrapWithPaddingPlainData_returnExpectedCipheredData
{
    // given
    NSData *plainData = [self dataWithHexString:@"466f7250617369"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *cipheredData = [AKWAesKeyWrap cipheredDataByWrappingWithPaddingPlainData:plainData
                                                               usingKeyEncryptionKey:kek
                                                                               error:nil];

    // then
    NSData *expectedCipheredData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];

    XCTAssertEqualObjects(cipheredData, expectedCipheredData);
}

- (void)testCipheredDataAnd192BitKek_unwrapWithPaddingCipheredData_returnExpected7OctetsPlainData
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8"];

    // when
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingWithPaddingCipheredData:cipheredData
                                                              usingKeyEncryptionKey:kek
                                                                              error:nil];

    // then
    NSData *expectedPlainData = [self dataWithHexString:@"466f7250617369"];

    XCTAssertEqualObjects(plainData, expectedPlainData);
}

- (void)testCipheredDataAnd192BitUnrelatedKek_unwrapWithPaddingCipheredData_returnError
{
    // given
    NSData *cipheredData = [self dataWithHexString:@"afbeb0f07dfbf541 9200f2ccb50bb24f"];
    NSData *kek = [self dataWithHexString:@"5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176aa"];

    // when
    NSError *error = nil;
    NSData *plainData = [AKWAesKeyWrap plainDataByUnwrappingWithPaddingCipheredData:cipheredData
                                                              usingKeyEncryptionKey:kek
                                                                              error:&error];

    // then
    XCTAssertNil(plainData);
    XCTAssertEqualObjects(error.domain, AKWErrorFactoryDomain);
    XCTAssertEqual(error.code, AKWErrorFactoryTypeIntegrityCheckingOfInitialValueFailed);
}

#pragma mark - Private methods

- (NSData *)emptyData
{
    return [NSData data];
}

- (NSData *)anyPlainData
{
    u_char bytes[2 * sizeof(uint64_t)];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)anyCipheredData
{
    u_char bytes[3 * sizeof(uint64_t)];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)anyTooSmallPlainData
{
    NSData *validData = [self anyPlainData];

    return [validData subdataWithRange:NSMakeRange(0, validData.length - 1)];
}

- (NSData *)anyNotAlignedPlainData
{
    NSData *validData = [self anyPlainData];

    NSMutableData *data = [NSMutableData dataWithData:validData];
    [data appendData:validData];

    return [data subdataWithRange:NSMakeRange(0, data.length - 1)];
}

- (NSData *)anyTooSmallCipheredData
{
    NSData *validData = [self anyCipheredData];

    return [validData subdataWithRange:NSMakeRange(0, validData.length - 1)];
}

- (NSData *)anyNotAlignedCipheredData
{
    NSData *validData = [self anyCipheredData];

    NSMutableData *data = [NSMutableData dataWithData:validData];
    [data appendData:validData];

    return [data subdataWithRange:NSMakeRange(0, data.length - 1)];
}

- (NSData *)anyPlainDataToWrapWithPadding
{
    u_char bytes[1];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)anyCipheredDataToUnwrapWithPadding
{
    u_char bytes[2 * sizeof(uint64_t)];

    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

- (NSData *)anyNotAlignedCipheredDataToUnwrapWithPadding
{
    NSData *validData = [self anyCipheredDataToUnwrapWithPadding];

    NSMutableData *data = [NSMutableData dataWithData:validData];
    [data appendData:validData];

    return [data subdataWithRange:NSMakeRange(0, data.length - 1)];
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
