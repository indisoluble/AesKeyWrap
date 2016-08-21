//
//  AKWAesKeyWrap.m
//  Pods
//
//  Created by Enrique de la Torre (dev) on 20/08/2016.
//
//

#import <CommonCrypto/CommonCryptor.h>

#import "AKWAesKeyWrap.h"

#import "AKWErrorFactory.h"

typedef u_int32_t AKWAesKeyWrapUInt32BitType;
typedef u_int64_t AKWAesKeyWrapUInt64BitType;

typedef u_char AKWAesKeyWrap8BitRawValueType;
typedef AKWAesKeyWrap8BitRawValueType AKWAesKeyWrap32BitRawValueType[sizeof(AKWAesKeyWrapUInt32BitType)];
typedef AKWAesKeyWrap8BitRawValueType AKWAesKeyWrap64BitRawValueType[sizeof(AKWAesKeyWrapUInt64BitType)];
typedef AKWAesKeyWrap8BitRawValueType AKWAesKeyWrap128BitRawValueType[2 * sizeof(AKWAesKeyWrap64BitRawValueType)];

static const AKWAesKeyWrapUInt64BitType kUInt64BitMax = UINT64_MAX;
static const AKWAesKeyWrapUInt32BitType kUInt32BitMax = UINT32_MAX;
static const NSUInteger kTimesIntermediateValuesAreCalculated = 6;
static const AKWAesKeyWrap32BitRawValueType kAIV32BitConstant = {0xA6, 0x59, 0x59, 0xA6};

@implementation AKWAesKeyWrap

#pragma mark - Public class methods

+ (nullable NSData *)cipheredDataByWrappingPlainData:(NSData *)plainData
                                withKeyEncryptionKey:(NSData *)kek
                                               error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap isPlainDataValid:plainData error:error])
    {
        return nil;
    }

    if (![AKWAesKeyWrap isKeyEncryptionKeyValid:kek error:error])
    {
        return nil;
    }

    // 1) Append padding & Initialize variables.
    // Set A0 to an initial value
    AKWAesKeyWrap64BitRawValueType a;
    [AKWAesKeyWrap getAlternativeInitialValue:a withMessageLengthIndicator:plainData.length];

    // For i = 1 to n
    //     R[i] = P[i]
    NSUInteger padding = [AKWAesKeyWrap paddingForMessageLengthIndicator:plainData.length];
    NSUInteger paddedBytesSize = (plainData.length + padding);

    AKWAesKeyWrap8BitRawValueType paddedBytes[paddedBytesSize];
    [AKWAesKeyWrap getPaddedBytes:paddedBytes withLength:paddedBytesSize fromData:plainData];

    // 2) Calculate intermediate values.
    NSUInteger n = (paddedBytesSize / (NSUInteger)sizeof(AKWAesKeyWrap64BitRawValueType));

    if (n == 1)
    {
        // If the padded plaintext contains exactly eight octets, C[0] | C[1] = ENC(K, A | P[1]).
        AKWAesKeyWrap128BitRawValueType b;
        if (![AKWAesKeyWrap get128BitCipheredValue:b
                     withMostSignificant64BitValue:a
                     andLeastSignificant64BitValue:paddedBytes
                                               kek:kek
                                             error:error])
        {
            return nil;
        }

        [AKWAesKeyWrap getMostSignificant64BitValue:a in128BitValue:b];
        [AKWAesKeyWrap getLeastSignificant64BitValue:paddedBytes in128BitValue:b];
    }
    else
    {
        // Otherwise, apply the wrapping process

        // For j = 0 to 5
        for (NSUInteger j = 0; j < kTimesIntermediateValuesAreCalculated; j++)
        {
            // For i=1 to n
            for (NSUInteger i = 0; i < n; i++)
            {
                // B = AES(K, A | R[i])
                AKWAesKeyWrap128BitRawValueType b;

                AKWAesKeyWrap8BitRawValueType *ri = (paddedBytes +
                                                     (i * sizeof(AKWAesKeyWrap64BitRawValueType)));
                if (![AKWAesKeyWrap get128BitCipheredValue:b
                             withMostSignificant64BitValue:a
                             andLeastSignificant64BitValue:ri
                                                       kek:kek
                                                     error:error])
                {
                    return nil;
                }

                // A = MSB(64, B) ^ t where t = (n*j)+i
                AKWAesKeyWrap64BitRawValueType msb;
                [AKWAesKeyWrap getMostSignificant64BitValue:msb in128BitValue:b];

                AKWAesKeyWrap64BitRawValueType t;
                if (![AKWAesKeyWrap get64BitValue:t
                    byMultipliyingUnsignedInteger:n
                              withUnsignedInteger:j
                         andAddingUnsignedInteger:(i + 1)
                                            error:error])
                {
                    return nil;
                }

                [AKWAesKeyWrap get64BitXorValue:a with64BitValue:msb and64BitValue:t];
                
                // R[i] = LSB(64, B)
                [AKWAesKeyWrap getLeastSignificant64BitValue:ri in128BitValue:b];
            }
        }
    }

    // 3) Output the results.
    // Set C[0] = A
    // For i = 1 to n
    //     C[i] = R[i]
    NSMutableData *cipheredData = [NSMutableData dataWithBytes:a
                                                        length:sizeof(AKWAesKeyWrap64BitRawValueType)];
    [cipheredData appendBytes:paddedBytes length:paddedBytesSize];

    return cipheredData;
}

+ (nullable NSData *)plainDataByUnwrappingCipheredData:(NSData *)cipheredData
                                  withKeyEncryptionKey:(NSData *)kek
                                                 error:(NSError **)error
{
    return nil;
}

#pragma mark - Private class methods

+ (BOOL)isPlainDataValid:(NSData *)plainData error:(NSError **)error
{
    if (plainData.length == 0)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorEmptyData];
        }

        return NO;
    }

    if (plainData.length > kUInt32BitMax)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorDataOverSizeLimit];
        }

        return NO;
    }

    return YES;
}

+ (BOOL)isKeyEncryptionKeyValid:(NSData *)kek error:(NSError **)error
{
    if ((kek.length == kCCKeySizeAES128) ||
        (kek.length == kCCKeySizeAES192) ||
        (kek.length == kCCKeySizeAES256))
    {
        return YES;
    }

    if (error)
    {
        *error = [AKWErrorFactory errorInvalidKeyEncryptionKey];
    }

    return NO;
}

+ (void)getAlternativeInitialValue:(AKWAesKeyWrap64BitRawValueType)aiv
        withMessageLengthIndicator:(AKWAesKeyWrapUInt32BitType)mli
{
    memcpy(aiv, kAIV32BitConstant, sizeof(AKWAesKeyWrap32BitRawValueType));

    AKWAesKeyWrapUInt32BitType swapped = CFSwapInt32HostToBig(mli);
    memcpy(aiv + sizeof(AKWAesKeyWrap32BitRawValueType), &swapped, sizeof(AKWAesKeyWrapUInt32BitType));
}

+ (AKWAesKeyWrapUInt32BitType)paddingForMessageLengthIndicator:(AKWAesKeyWrapUInt32BitType)mli
{
    AKWAesKeyWrapUInt32BitType size64BitRawValue = sizeof(AKWAesKeyWrap64BitRawValueType);
    AKWAesKeyWrapUInt32BitType modulo = (mli % size64BitRawValue);

    return (modulo == 0 ? 0 : size64BitRawValue - modulo);
}

+ (void)getPaddedBytes:(u_char *)buffer withLength:(NSUInteger)length fromData:(NSData *)data
{
    [data getBytes:buffer range:NSMakeRange(0, data.length)];

    if ((length - data.length) > 0)
    {
        memset(buffer + data.length, '\0', length - data.length);
    }
}

+ (BOOL)get128BitCipheredValue:(AKWAesKeyWrap128BitRawValueType)buffer
 withMostSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)msb
 andLeastSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)lsb
                           kek:(NSData *)kek
                         error:(NSError **)error
{
    AKWAesKeyWrap128BitRawValueType concatenatedValue;
    [AKWAesKeyWrap get128BitConcatenatedValue:concatenatedValue
                withMostSignificant64BitValue:msb
                andLeastSignificant64BitValue:lsb];

    return [AKWAesKeyWrap get128BitCipheredValue:buffer
                         byEncrypting128BitValue:concatenatedValue
                                         withKek:kek
                                           error:error];
}

+ (void)get128BitConcatenatedValue:(AKWAesKeyWrap128BitRawValueType)buffer
     withMostSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)msb
     andLeastSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)lsb
{
    memcpy(buffer, msb, sizeof(AKWAesKeyWrap64BitRawValueType));
    memcpy(buffer + sizeof(AKWAesKeyWrap64BitRawValueType), lsb, sizeof(AKWAesKeyWrap64BitRawValueType));
}

+ (BOOL)get128BitCipheredValue:(AKWAesKeyWrap128BitRawValueType)buffer
       byEncrypting128BitValue:(AKWAesKeyWrap128BitRawValueType)dataIn
                       withKek:(NSData *)kek
                         error:(NSError **)error
{
    return [AKWAesKeyWrap get128BitValue:buffer
                 byUsingAESOn128BitValue:dataIn
                           withOperation:kCCEncrypt
                                     kek:kek
                                   error:error];
}

+ (BOOL)get128BitDecipheredValue:(AKWAesKeyWrap128BitRawValueType)buffer
         byDecrypting128BitValue:(AKWAesKeyWrap128BitRawValueType)dataIn
                         withKek:(NSData *)kek
                           error:(NSError **)error
{
    return [AKWAesKeyWrap get128BitValue:buffer
                 byUsingAESOn128BitValue:dataIn
                           withOperation:kCCDecrypt
                                     kek:kek
                                   error:error];
}

+ (BOOL)    get128BitValue:(AKWAesKeyWrap128BitRawValueType)buffer
   byUsingAESOn128BitValue:(AKWAesKeyWrap128BitRawValueType)dataIn
             withOperation:(CCOperation)operation
                       kek:(NSData *)kek
                     error:(NSError **)error
{
    size_t dataOutSize = (sizeof(AKWAesKeyWrap128BitRawValueType) + kCCBlockSizeAES128);
    AKWAesKeyWrap8BitRawValueType dataOut[dataOutSize];
    size_t dataOutMoved = 0;

    CCCryptorStatus status = CCCrypt(operation,
                                     kCCAlgorithmAES,
                                     kCCOptionECBMode,
                                     kek.bytes,
                                     kek.length,
                                     nil,
                                     dataIn,
                                     sizeof(AKWAesKeyWrap128BitRawValueType),
                                     dataOut,
                                     dataOutSize,
                                     &dataOutMoved);

    if ((status == kCCSuccess) && (dataOutMoved  == sizeof(AKWAesKeyWrap128BitRawValueType)))
    {
        memcpy(buffer, dataOut, dataOutMoved);

        return YES;
    }

    if (error)
    {
        *error = [AKWErrorFactory errorEncryptionFailed];
    }

    return NO;
}

+ (BOOL)        get64BitValue:(AKWAesKeyWrap64BitRawValueType)buffer
byMultipliyingUnsignedInteger:(NSUInteger)value1
          withUnsignedInteger:(NSUInteger)value2
     andAddingUnsignedInteger:(NSUInteger)value3
                        error:(NSError **)error
{
    if ([AKWAesKeyWrap doesUInt64OverflowByMultipliyingUnsignedInteger:value1
                                                    andUnsignedInteger:value2])
    {
        if (error)
        {
            *error = [AKWErrorFactory errorOverflow];
        }

        return NO;
    }
    AKWAesKeyWrapUInt64BitType multipliedValue = ((AKWAesKeyWrapUInt64BitType)value1 *
                                                  (AKWAesKeyWrapUInt64BitType)value2);

    if ([AKWAesKeyWrap doesUInt64OverflowByByAddingUnsignedInteger:value3 toUInt64:multipliedValue])
    {
        if (error)
        {
            *error = [AKWErrorFactory errorOverflow];
        }

        return NO;
    }
    AKWAesKeyWrapUInt64BitType result = (multipliedValue + value3);

    AKWAesKeyWrapUInt64BitType swapped = CFSwapInt64HostToBig(result);
    memcpy(buffer, &swapped, sizeof(AKWAesKeyWrap64BitRawValueType));

    return YES;
}

+ (BOOL)doesUInt64OverflowByMultipliyingUnsignedInteger:(NSUInteger)value1
                                     andUnsignedInteger:(NSUInteger)value2
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return ((kUInt64BitMax / value1) < value2);
}

+ (BOOL)doesUInt64OverflowByByAddingUnsignedInteger:(NSUInteger)unsignedIntegerValue
                                           toUInt64:(AKWAesKeyWrapUInt64BitType)uint64Value
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return (unsignedIntegerValue > (kUInt64BitMax - uint64Value));
}

+ (void)getMostSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)buffer
                       in128BitValue:(AKWAesKeyWrap128BitRawValueType)value
{
    memcpy(buffer, value, sizeof(AKWAesKeyWrap64BitRawValueType));
}

+ (void)getLeastSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)buffer
                       in128BitValue:(AKWAesKeyWrap128BitRawValueType)value
{
    memcpy(buffer, value + sizeof(AKWAesKeyWrap64BitRawValueType), sizeof(AKWAesKeyWrap64BitRawValueType));
}

+ (void)get64BitXorValue:(AKWAesKeyWrap64BitRawValueType)buffer
          with64BitValue:(AKWAesKeyWrap64BitRawValueType)value1
           and64BitValue:(AKWAesKeyWrap64BitRawValueType)value2
{
    for (NSUInteger i = 0; i < sizeof(AKWAesKeyWrap64BitRawValueType); i++)
    {
        buffer[i] = (value1[i] ^ value2[i]);
    }
}

@end
