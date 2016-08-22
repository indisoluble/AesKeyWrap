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
typedef size_t AKWAesKeyWrapSizeType;

typedef u_char AKWAesKeyWrap8BitRawValueType;
typedef AKWAesKeyWrap8BitRawValueType AKWAesKeyWrap32BitRawValueType[sizeof(AKWAesKeyWrapUInt32BitType)];
typedef AKWAesKeyWrap8BitRawValueType AKWAesKeyWrap64BitRawValueType[sizeof(AKWAesKeyWrapUInt64BitType)];
typedef AKWAesKeyWrap8BitRawValueType AKWAesKeyWrap128BitRawValueType[2 * sizeof(AKWAesKeyWrap64BitRawValueType)];

static const AKWAesKeyWrapUInt64BitType kUInt64BitMax = UINT64_MAX;
static const AKWAesKeyWrapUInt32BitType kUInt32BitMax = UINT32_MAX;
static const AKWAesKeyWrapSizeType kSizeMax = SIZE_T_MAX;

// The input key data may be as short as one octet, which will result in an
// output of two 64-bit blocks (or 16 octets)
static const AKWAesKeyWrapUInt32BitType kPlainDataMinSize = 1;
// The use of a 32-bit fixed field to carry the octet length of the key data
// bounds the size of the input at 2^32 octets
static const AKWAesKeyWrapUInt32BitType kPlainDataMaxSize = kUInt32BitMax;

// Min size = <Alternative Initial Value> + <64-bit ciphertext data block>
static const AKWAesKeyWrapUInt32BitType kCipheredDataMinSize = (sizeof(AKWAesKeyWrap64BitRawValueType) +
                                                                sizeof(AKWAesKeyWrap64BitRawValueType));
// Max size = <Alternative Initial Value>  + <64-bit ciphertext data block> + ... + <64-bit ciphertext data block with padding>
static const AKWAesKeyWrapUInt64BitType kCipheredDataMaxSize = ((AKWAesKeyWrapUInt64BitType)sizeof(AKWAesKeyWrap64BitRawValueType) +
                                                                (AKWAesKeyWrapUInt64BitType)kPlainDataMaxSize +
                                                                (AKWAesKeyWrapUInt64BitType)(sizeof(AKWAesKeyWrap64BitRawValueType) -
                                                                                             (kPlainDataMaxSize % sizeof(AKWAesKeyWrap64BitRawValueType))));

static const AKWAesKeyWrapUInt32BitType kTimesIntermediateValuesAreCalculated = 6;
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
    AKWAesKeyWrapUInt32BitType mli = (AKWAesKeyWrapUInt32BitType)plainData.length;

    // Set A0 to an initial value
    AKWAesKeyWrap64BitRawValueType a;
    [AKWAesKeyWrap getAlternativeInitialValue:a withMessageLengthIndicator:mli];

    // For i = 1 to n
    //     R[i] = P[i]
    AKWAesKeyWrapUInt32BitType padding = [AKWAesKeyWrap paddingForMessageLengthIndicator:mli];
    if ([AKWAesKeyWrap doesSizeOverflowByByAddingUInt32:mli toUInt32:padding])
    {
        if (error)
        {
            *error = [AKWErrorFactory errorOverflow];
        }

        return nil;
    }
    AKWAesKeyWrapSizeType paddedBytesSize = (mli + padding);

    AKWAesKeyWrap8BitRawValueType paddedBytes[paddedBytesSize];
    [AKWAesKeyWrap getPaddedBytes:paddedBytes withLength:paddedBytesSize fromData:plainData];

    // 2) Calculate intermediate values.
    AKWAesKeyWrapUInt32BitType n = (AKWAesKeyWrapUInt32BitType)(paddedBytesSize /
                                                                sizeof(AKWAesKeyWrap64BitRawValueType));

    if (n == 1)
    {
        // If the padded plaintext contains exactly eight octets, C[0] | C[1] = ENC(K, A | P[1]).
        AKWAesKeyWrap128BitRawValueType b;
        if (![AKWAesKeyWrap get128BitCipheredValue:b
             byEncryptingMostSignificant64BitValue:a
                     andLeastSignificant64BitValue:paddedBytes
                                           withKek:kek
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
        for (AKWAesKeyWrapUInt32BitType j = 0; j < kTimesIntermediateValuesAreCalculated; j++)
        {
            // For i=1 to n
            for (AKWAesKeyWrapUInt32BitType i = 0; i < n; i++)
            {
                // B = AES(K, A | R[i])
                AKWAesKeyWrap128BitRawValueType b;

                AKWAesKeyWrap8BitRawValueType *ri = (paddedBytes +
                                                     (i * sizeof(AKWAesKeyWrap64BitRawValueType)));
                if (![AKWAesKeyWrap get128BitCipheredValue:b
                     byEncryptingMostSignificant64BitValue:a
                             andLeastSignificant64BitValue:ri
                                                   withKek:kek
                                                     error:error])
                {
                    return nil;
                }

                // A = MSB(64, B) ^ t where t = (n*j)+i
                AKWAesKeyWrap64BitRawValueType msb;
                [AKWAesKeyWrap getMostSignificant64BitValue:msb in128BitValue:b];

                AKWAesKeyWrap64BitRawValueType t;
                if (![AKWAesKeyWrap get64BitValue:t
                             byMultipliyingUInt32:n
                                       withUInt32:j
                                  andAddingUInt32:(i + 1)
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
    // 0) Check input
    if (![AKWAesKeyWrap isCipheredDataValid:cipheredData error:error])
    {
        return nil;
    }

    if (![AKWAesKeyWrap isKeyEncryptionKeyValid:kek error:error])
    {
        return nil;
    }

    // 1) Initialize variables.
    // Set A = C[0]
    AKWAesKeyWrap64BitRawValueType a;
    memcpy(a, cipheredData.bytes, sizeof(AKWAesKeyWrap64BitRawValueType));

    // For i = 1 to n
    //     R[i] = C[i]
    if ([AKWAesKeyWrap doesSizeOverflowByBySubtractingUInt32:sizeof(AKWAesKeyWrap64BitRawValueType)
                                                    toUInt64:cipheredData.length])
    {
        if (error)
        {
            *error = [AKWErrorFactory errorOverflow];
        }

        return nil;
    }
    AKWAesKeyWrapSizeType paddedBytesSize = (cipheredData.length - sizeof(AKWAesKeyWrap64BitRawValueType));

    AKWAesKeyWrap8BitRawValueType paddedBytes[paddedBytesSize];
    memcpy(paddedBytes, cipheredData.bytes + sizeof(AKWAesKeyWrap64BitRawValueType), paddedBytesSize);

    // 2) Compute intermediate values.
    AKWAesKeyWrapUInt32BitType n = (AKWAesKeyWrapUInt32BitType)(paddedBytesSize /
                                                                sizeof(AKWAesKeyWrap64BitRawValueType));

    if (n == 1)
    {
        // When n is one (n=1), the ciphertext contains exactly two 64-bit blocks (C[0] and C[1]),
        // and they are decrypted as a single AES block using AES in ECB mode [Modes] with K
        // (the KEK) to recover the AIV and the padded plaintext key
        AKWAesKeyWrap128BitRawValueType b;

        if (![AKWAesKeyWrap get128BitDecipheredValue:b
               byDecryptingMostSignificant64BitValue:a
                       andLeastSignificant64BitValue:paddedBytes
                                             withKek:kek
                                               error:error])
        {
            return nil;
        }

        [AKWAesKeyWrap getMostSignificant64BitValue:a in128BitValue:b];
        [AKWAesKeyWrap getLeastSignificant64BitValue:paddedBytes in128BitValue:b];
    }
    else
    {
        // Otherwise, apply the unwrapping process

        // For j = 5 to 0
        for (AKWAesKeyWrapUInt32BitType j = kTimesIntermediateValuesAreCalculated; j > 0; j--)
        {
            // For i = n to 1
            for (AKWAesKeyWrapUInt32BitType i = n; i > 0; i--)
            {
                // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                AKWAesKeyWrap64BitRawValueType t;
                if (![AKWAesKeyWrap get64BitValue:t
                             byMultipliyingUInt32:n
                                       withUInt32:(j - 1)
                                  andAddingUInt32:i
                                            error:error])
                {
                    return nil;
                }

                AKWAesKeyWrap64BitRawValueType xorValue;
                [AKWAesKeyWrap get64BitXorValue:xorValue with64BitValue:a and64BitValue:t];

                AKWAesKeyWrap128BitRawValueType b;

                AKWAesKeyWrap8BitRawValueType *ri = (paddedBytes +
                                                     ((i - 1) * sizeof(AKWAesKeyWrap64BitRawValueType)));
                if (![AKWAesKeyWrap get128BitDecipheredValue:b
                       byDecryptingMostSignificant64BitValue:xorValue
                               andLeastSignificant64BitValue:ri
                                                     withKek:kek
                                                       error:error])
                {
                    return nil;
                }

                // A = MSB(64, B)
                [AKWAesKeyWrap getMostSignificant64BitValue:a in128BitValue:b];
                
                // R[i] = LSB(64, B)
                [AKWAesKeyWrap getLeastSignificant64BitValue:ri in128BitValue:b];
            }
        }
    }

    // 3) Output results.
    // If A is an appropriate initial value
    if (![AKWAesKeyWrap alternativeInitialValue:a
                          isValidForPaddedBytes:paddedBytes
                                     withLength:paddedBytesSize
                                          error:error])
    {
        return nil;
    }

    // Let m = the MLI value extracted from A.
    // Let P = P[1] | P[2] | ... | P[n].
    // For i = 1, ... , m
    //     Q[i] = LSB(8, MSB(8*i, P))
    AKWAesKeyWrapUInt32BitType mli = [AKWAesKeyWrap messageLengthIndicatorInAlternativeInitialValue:a];

    return [NSData dataWithBytes:paddedBytes length:mli];
}

#pragma mark - Private class methods

+ (BOOL)isPlainDataValid:(NSData *)plainData error:(NSError **)error
{
    if (plainData.length < kPlainDataMinSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooSmall];
        }

        return NO;
    }

    if (plainData.length > kPlainDataMaxSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooBig];
        }

        return NO;
    }

    return YES;
}

+ (BOOL)isCipheredDataValid:(NSData *)cipheredData error:(NSError **)error
{
    if (cipheredData.length < kCipheredDataMinSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooSmall];
        }

        return NO;
    }

    if (cipheredData.length > kCipheredDataMaxSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooBig];
        }

        return NO;
    }

    if (cipheredData.length % sizeof(AKWAesKeyWrap64BitRawValueType) != 0)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataNotAlignedProperly];
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

+ (BOOL)alternativeInitialValue:(AKWAesKeyWrap64BitRawValueType)aiv
          isValidForPaddedBytes:(AKWAesKeyWrap8BitRawValueType *)paddedBytes
                     withLength:(AKWAesKeyWrapSizeType)length
                          error:(NSError **)error
{
    // 1) Check that MSB(32,A) = A65959A6.
    AKWAesKeyWrap32BitRawValueType msb;
    [AKWAesKeyWrap getMostSignificant32BitValue:msb in64BitValue:aiv];

    if (memcmp(msb, kAIV32BitConstant, sizeof(AKWAesKeyWrap32BitRawValueType)) != 0)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorIntegrityCheckingOfAlternativeInitialValueFailed];
        }

        return NO;
    }

    // 2) Check that 8*(n-1) < LSB(32,A) <= 8*n.  If so, let MLI = LSB(32,A).
    AKWAesKeyWrapUInt32BitType mli  = [AKWAesKeyWrap messageLengthIndicatorInAlternativeInitialValue:aiv];

    AKWAesKeyWrapSizeType lowerLimit = (length - sizeof(AKWAesKeyWrap64BitRawValueType));

    if ((mli > length) || (mli <= lowerLimit))
    {
        if (error)
        {
            *error = [AKWErrorFactory errorIntegrityCheckingOfAlternativeInitialValueFailed];
        }

        return NO;
    }

    // 3) Let b = (8*n)-MLI, and then check that the rightmost b octets of the output data are zero.
    AKWAesKeyWrapSizeType b = (length - mli);
    if (b > 0)
    {
        AKWAesKeyWrap8BitRawValueType padding[b];
        memset(padding, '\0', b);

        if (memcmp(padding, paddedBytes + length - b, b) != 0)
        {
            if (error)
            {
                *error = [AKWErrorFactory errorIntegrityCheckingOfAlternativeInitialValueFailed];
            }

            return NO;
        }
    }

    return YES;
}

+ (void)getAlternativeInitialValue:(AKWAesKeyWrap64BitRawValueType)aiv
        withMessageLengthIndicator:(AKWAesKeyWrapUInt32BitType)mli
{
    AKWAesKeyWrapUInt32BitType swapped = CFSwapInt32HostToBig(mli);

    [AKWAesKeyWrap get64BitConcatenatedValue:aiv
               withMostSignificant32BitValue:(AKWAesKeyWrap8BitRawValueType *)kAIV32BitConstant
               andLeastSignificant32BitValue:(AKWAesKeyWrap8BitRawValueType *)&swapped];
}

+ (AKWAesKeyWrapUInt32BitType)messageLengthIndicatorInAlternativeInitialValue:(AKWAesKeyWrap64BitRawValueType)aiv
{
    AKWAesKeyWrapUInt32BitType uint32Value;
    [AKWAesKeyWrap getLeastSignificant32BitValue:(AKWAesKeyWrap8BitRawValueType *)&uint32Value
                                    in64BitValue:aiv];

    return CFSwapInt32BigToHost(uint32Value);
}

+ (AKWAesKeyWrapUInt32BitType)paddingForMessageLengthIndicator:(AKWAesKeyWrapUInt32BitType)mli
{
    AKWAesKeyWrapUInt32BitType size64BitRawValue = sizeof(AKWAesKeyWrap64BitRawValueType);
    AKWAesKeyWrapUInt32BitType modulo = (mli % size64BitRawValue);

    return (modulo == 0 ? 0 : size64BitRawValue - modulo);
}

+ (void)getPaddedBytes:(AKWAesKeyWrap8BitRawValueType *)buffer
            withLength:(AKWAesKeyWrapSizeType)length
              fromData:(NSData *)data
{
    [data getBytes:buffer range:NSMakeRange(0, data.length)];

    if ((length - data.length) > 0)
    {
        memset(buffer + data.length, '\0', length - data.length);
    }
}

+ (BOOL)        get128BitCipheredValue:(AKWAesKeyWrap128BitRawValueType)buffer
 byEncryptingMostSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)msb
         andLeastSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)lsb
                               withKek:(NSData *)kek
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

+ (BOOL)        get128BitDecipheredValue:(AKWAesKeyWrap128BitRawValueType)buffer
   byDecryptingMostSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)msb
           andLeastSignificant64BitValue:(AKWAesKeyWrap64BitRawValueType)lsb
                                 withKek:(NSData *)kek
                                   error:(NSError **)error
{
    AKWAesKeyWrap128BitRawValueType concatenatedValue;
    [AKWAesKeyWrap get128BitConcatenatedValue:concatenatedValue
                withMostSignificant64BitValue:msb
                andLeastSignificant64BitValue:lsb];

    return [AKWAesKeyWrap get128BitDecipheredValue:buffer
                           byDecrypting128BitValue:concatenatedValue
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

+ (void)get64BitConcatenatedValue:(AKWAesKeyWrap64BitRawValueType)buffer
    withMostSignificant32BitValue:(AKWAesKeyWrap32BitRawValueType)msb
    andLeastSignificant32BitValue:(AKWAesKeyWrap32BitRawValueType)lsb
{
    memcpy(buffer, msb, sizeof(AKWAesKeyWrap32BitRawValueType));
    memcpy(buffer + sizeof(AKWAesKeyWrap32BitRawValueType), lsb, sizeof(AKWAesKeyWrap32BitRawValueType));
}

+ (void)getMostSignificant32BitValue:(AKWAesKeyWrap32BitRawValueType)buffer
                        in64BitValue:(AKWAesKeyWrap64BitRawValueType)value
{
    memcpy(buffer, value, sizeof(AKWAesKeyWrap32BitRawValueType));
}

+ (void)getLeastSignificant32BitValue:(AKWAesKeyWrap32BitRawValueType)buffer
                         in64BitValue:(AKWAesKeyWrap64BitRawValueType)value
{
    memcpy(buffer, value + sizeof(AKWAesKeyWrap32BitRawValueType), sizeof(AKWAesKeyWrap32BitRawValueType));
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

+ (BOOL)get64BitValue:(AKWAesKeyWrap64BitRawValueType)buffer
 byMultipliyingUInt32:(AKWAesKeyWrapUInt32BitType)value1
           withUInt32:(AKWAesKeyWrapUInt32BitType)value2
      andAddingUInt32:(AKWAesKeyWrapUInt32BitType)value3
                error:(NSError **)error
{
    if ([AKWAesKeyWrap doesUInt64OverflowByMultipliyingUInt32:value1 andUInt32:value2])
    {
        if (error)
        {
            *error = [AKWErrorFactory errorOverflow];
        }

        return NO;
    }
    AKWAesKeyWrapUInt64BitType multipliedValue = ((AKWAesKeyWrapUInt64BitType)value1 *
                                                  (AKWAesKeyWrapUInt64BitType)value2);

    if ([AKWAesKeyWrap doesUInt64OverflowByByAddingUInt32:value3 toUInt64:multipliedValue])
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

+ (BOOL)doesUInt64OverflowByMultipliyingUInt32:(AKWAesKeyWrapUInt32BitType)value1
                                     andUInt32:(AKWAesKeyWrapUInt32BitType)value2
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return ((kUInt64BitMax / value1) < value2);
}

+ (BOOL)doesUInt64OverflowByByAddingUInt32:(AKWAesKeyWrapUInt32BitType)uint32Value
                                  toUInt64:(AKWAesKeyWrapUInt64BitType)uint64Value
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return (uint32Value > (kUInt64BitMax - uint64Value));
}

+ (BOOL)doesSizeOverflowByByAddingUInt32:(AKWAesKeyWrapUInt32BitType)value1
                                toUInt32:(AKWAesKeyWrapUInt32BitType)value2
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return (value1 > (kSizeMax - value2));
}

+ (BOOL)doesSizeOverflowByBySubtractingUInt32:(AKWAesKeyWrapUInt32BitType)value1
                                     toUInt64:(AKWAesKeyWrapUInt64BitType)value2
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return ((value2 - value1) > kSizeMax);
}

+ (void)get64BitXorValue:(AKWAesKeyWrap64BitRawValueType)buffer
          with64BitValue:(AKWAesKeyWrap64BitRawValueType)value1
           and64BitValue:(AKWAesKeyWrap64BitRawValueType)value2
{
    for (AKWAesKeyWrapUInt32BitType i = 0; i < sizeof(AKWAesKeyWrap64BitRawValueType); i++)
    {
        buffer[i] = (value1[i] ^ value2[i]);
    }
}

@end
