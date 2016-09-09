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

// RFC 3394: The only restriction the key wrap algorithm places on n is that n be
// at least two
static const AKWAesKeyWrapUInt32BitType kPlainDataMinSize = (2  * sizeof(AKWAesKeyWrap64BitRawValueType));
static const AKWAesKeyWrapUInt32BitType kCipheredDataMinSize = (sizeof(AKWAesKeyWrap64BitRawValueType) + kPlainDataMinSize);

// RFC 5649: The input key data may be as short as one octet, which will result in an
// output of two 64-bit blocks (or 16 octets)
static const AKWAesKeyWrapUInt32BitType kWrapWithPaddingPlainDataMinSize = 1;
// RFC 5649: The use of a 32-bit fixed field to carry the octet length of the key data
// bounds the size of the input at 2^32 octets
static const AKWAesKeyWrapUInt32BitType kWrapWithPaddingPlainDataMaxSize = kUInt32BitMax;

// RFC 5649: Min size = <Alternative Initial Value> + <64-bit ciphertext data block>
static const AKWAesKeyWrapUInt32BitType kWrapWithPaddingCipheredDataMinSize = (sizeof(AKWAesKeyWrap64BitRawValueType) +
                                                                               sizeof(AKWAesKeyWrap64BitRawValueType));
// RFC 5649: Max size = <Alternative Initial Value>  +
//                      <64-bit ciphertext data block> + ... +
//                      <64-bit ciphertext data block with padding>
static const AKWAesKeyWrapUInt64BitType kWrapWithPaddingCipheredDataMaxSize = ((AKWAesKeyWrapUInt64BitType)sizeof(AKWAesKeyWrap64BitRawValueType) +
                                                                               (AKWAesKeyWrapUInt64BitType)kWrapWithPaddingPlainDataMaxSize +
                                                                               (AKWAesKeyWrapUInt64BitType)(sizeof(AKWAesKeyWrap64BitRawValueType) -
                                                                                                            (kWrapWithPaddingPlainDataMaxSize %
                                                                                                             sizeof(AKWAesKeyWrap64BitRawValueType))));

static const AKWAesKeyWrapUInt32BitType kTimesIntermediateValuesAreCalculated = 6;
static const AKWAesKeyWrap64BitRawValueType kIVConstant = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
static const AKWAesKeyWrap32BitRawValueType kAIV32BitConstant = {0xA6, 0x59, 0x59, 0xA6};

@implementation AKWAesKeyWrap

#pragma mark - Public class methods

+ (nullable NSData *)cipheredDataByWrappingPlainData:(NSData *)plainData
                                withKeyEncryptionKey:(NSData *)kek
                                               error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap canPlainDataBeWrapped:plainData error:error])
    {
        return nil;
    }

    // 1) Cipher padded plain data
    return [AKWAesKeyWrap cipheredDataByWrappingPaddedPlainBytes:(AKWAesKeyWrap8BitRawValueType *)plainData.bytes
                                                      withLength:plainData.length
                                           usingKeyEncryptionKey:kek
                                                    initialValue:kIVConstant
                                                           error:error];
}

+ (nullable NSData *)plainDataByUnwrappingCipheredData:(NSData *)cipheredData
                                  withKeyEncryptionKey:(NSData *)kek
                                                 error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap canCipheredDataBeUnwrapped:cipheredData error:error])
    {
        return nil;
    }

    // 1) Decipher data
    AKWAesKeyWrap64BitRawValueType iv;
    NSData *plainData = [AKWAesKeyWrap paddedPlainDataByUnwrappingCipheredBytes:(AKWAesKeyWrap8BitRawValueType *)cipheredData.bytes
                                                                     withLength:cipheredData.length
                                                          usingKeyEncryptionKey:kek
                                                          returningInitialValue:iv
                                                                          error:error];
    if (!plainData)
    {
        return nil;
    }

    // 2) Output results.
    if (memcmp(iv, kIVConstant, sizeof(AKWAesKeyWrap64BitRawValueType)) != 0)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorIntegrityCheckingOfInitialValueFailed];
        }

        return nil;
    }

    return plainData;
}

+ (nullable NSData *)cipheredDataByWrappingWithPaddingPlainData:(NSData *)plainData
                                          usingKeyEncryptionKey:(NSData *)kek
                                                          error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap canPlainDataBeWrappedWithPadding:plainData error:error])
    {
        return nil;
    }

    // 1) Prepare padded plain data
    AKWAesKeyWrapUInt32BitType mli = (AKWAesKeyWrapUInt32BitType)plainData.length;

    AKWAesKeyWrap64BitRawValueType aiv;
    [AKWAesKeyWrap getAlternativeInitialValue:aiv withMessageLengthIndicator:mli];

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

    // 2) Cipher padded plain data
    return [AKWAesKeyWrap cipheredDataByWrappingPaddedPlainBytes:paddedBytes
                                                      withLength:paddedBytesSize
                                           usingKeyEncryptionKey:kek
                                                    initialValue:aiv
                                                           error:error];
}

+ (nullable NSData *)plainDataByUnwrappingWithPaddingCipheredData:(NSData *)cipheredData
                                            usingKeyEncryptionKey:(NSData *)kek
                                                            error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap canCipheredDataBeUnwrappedWithPadding:cipheredData error:error])
    {
        return nil;
    }

    // 1) Decipher data
    AKWAesKeyWrap64BitRawValueType aiv;
    NSData *plainData = [AKWAesKeyWrap paddedPlainDataByUnwrappingCipheredBytes:(AKWAesKeyWrap8BitRawValueType *)cipheredData.bytes
                                                                     withLength:cipheredData.length
                                                          usingKeyEncryptionKey:kek
                                                          returningInitialValue:aiv
                                                                          error:error];
    if (!plainData)
    {
        return nil;
    }

    // 2) Output results.
    // If A is an appropriate initial value
    if (![AKWAesKeyWrap alternativeInitialValue:aiv
                          isValidForPaddedBytes:(AKWAesKeyWrap8BitRawValueType *)plainData.bytes
                                     withLength:plainData.length
                                          error:error])
    {
        return nil;
    }

    // Let m = the MLI value extracted from A.
    // Let P = P[1] | P[2] | ... | P[n].
    // For i = 1, ... , m
    //     Q[i] = LSB(8, MSB(8*i, P))
    AKWAesKeyWrapUInt32BitType mli = [AKWAesKeyWrap messageLengthIndicatorInAlternativeInitialValue:aiv];

    return [plainData subdataWithRange:NSMakeRange(0, mli)];
}

#pragma mark - Private class methods

+ (nullable NSData *)cipheredDataByWrappingPaddedPlainBytes:(AKWAesKeyWrap8BitRawValueType *)paddedPlainBytes
                                                 withLength:(AKWAesKeyWrapSizeType)paddedPlainBytesLength
                                      usingKeyEncryptionKey:(NSData *)kek
                                               initialValue:(const AKWAesKeyWrap64BitRawValueType)iv
                                                      error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap isKeyEncryptionKeyValid:kek error:error])
    {
        return nil;
    }

    // 1) Initialize variables.
    // Set A0 to an initial value
    AKWAesKeyWrap64BitRawValueType a;
    memcpy(a, iv, sizeof(AKWAesKeyWrap64BitRawValueType));

    // For i = 1 to n
    //     R[i] = P[i]
    AKWAesKeyWrap8BitRawValueType r[paddedPlainBytesLength];
    memcpy(r, paddedPlainBytes, paddedPlainBytesLength);

    // 2) Calculate intermediate values.
    AKWAesKeyWrapSizeType n = (paddedPlainBytesLength / sizeof(AKWAesKeyWrap64BitRawValueType));

    if (n == 1)
    {
        // If the padded plaintext contains exactly eight octets, C[0] | C[1] = ENC(K, A | P[1]).
        AKWAesKeyWrap128BitRawValueType b;
        if (![AKWAesKeyWrap get128BitCipheredValue:b
             byEncryptingMostSignificant64BitValue:a
                     andLeastSignificant64BitValue:r
                                           withKek:kek
                                             error:error])
        {
            return nil;
        }

        [AKWAesKeyWrap getMostSignificant64BitValue:a in128BitValue:b];
        [AKWAesKeyWrap getLeastSignificant64BitValue:r in128BitValue:b];
    }
    else
    {
        // Otherwise, apply the wrapping process

        // For j = 0 to 5
        for (AKWAesKeyWrapUInt32BitType j = 0; j < kTimesIntermediateValuesAreCalculated; j++)
        {
            // For i=1 to n
            for (AKWAesKeyWrapSizeType i = 0; i < n; i++)
            {
                // B = AES(K, A | R[i])
                AKWAesKeyWrap128BitRawValueType b;

                AKWAesKeyWrap8BitRawValueType *ri = (r + (i * sizeof(AKWAesKeyWrap64BitRawValueType)));
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
                               byMultipliyingSize:n
                                       withUInt32:j
                                    andAddingSize:(i + 1)
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
    [cipheredData appendBytes:r length:paddedPlainBytesLength];
    
    return cipheredData;
}

+ (nullable NSData *)paddedPlainDataByUnwrappingCipheredBytes:(AKWAesKeyWrap8BitRawValueType *)cipheredBytes
                                                   withLength:(AKWAesKeyWrapSizeType)cipheredBytesLength
                                        usingKeyEncryptionKey:(NSData *)kek
                                        returningInitialValue:(AKWAesKeyWrap64BitRawValueType)iv
                                                        error:(NSError **)error
{
    // 0) Check input
    if (![AKWAesKeyWrap isKeyEncryptionKeyValid:kek error:error])
    {
        return nil;
    }

    // 1) Initialize variables.
    // Set A = C[0]
    AKWAesKeyWrap64BitRawValueType a;
    memcpy(a, cipheredBytes, sizeof(AKWAesKeyWrap64BitRawValueType));

    // For i = 1 to n
    //     R[i] = C[i]
    AKWAesKeyWrapSizeType length = (cipheredBytesLength - sizeof(AKWAesKeyWrap64BitRawValueType));

    AKWAesKeyWrap8BitRawValueType r[length];
    memcpy(r, cipheredBytes + sizeof(AKWAesKeyWrap64BitRawValueType), length);

    // 2) Compute intermediate values.
    AKWAesKeyWrapSizeType n = (length / sizeof(AKWAesKeyWrap64BitRawValueType));

    if (n == 1)
    {
        // When n is one (n=1), the ciphertext contains exactly two 64-bit blocks (C[0] and C[1]),
        // and they are decrypted as a single AES block using AES in ECB mode [Modes] with K
        // (the KEK) to recover the AIV and the padded plaintext key
        AKWAesKeyWrap128BitRawValueType b;

        if (![AKWAesKeyWrap get128BitDecipheredValue:b
               byDecryptingMostSignificant64BitValue:a
                       andLeastSignificant64BitValue:r
                                             withKek:kek
                                               error:error])
        {
            return nil;
        }

        [AKWAesKeyWrap getMostSignificant64BitValue:a in128BitValue:b];
        [AKWAesKeyWrap getLeastSignificant64BitValue:r in128BitValue:b];
    }
    else
    {
        // Otherwise, apply the unwrapping process

        // For j = 5 to 0
        for (AKWAesKeyWrapUInt32BitType j = kTimesIntermediateValuesAreCalculated; j > 0; j--)
        {
            // For i = n to 1
            for (AKWAesKeyWrapSizeType i = n; i > 0; i--)
            {
                // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                AKWAesKeyWrap64BitRawValueType t;
                if (![AKWAesKeyWrap get64BitValue:t
                               byMultipliyingSize:n
                                       withUInt32:(j - 1)
                                    andAddingSize:i
                                            error:error])
                {
                    return nil;
                }

                AKWAesKeyWrap64BitRawValueType xorValue;
                [AKWAesKeyWrap get64BitXorValue:xorValue with64BitValue:a and64BitValue:t];

                AKWAesKeyWrap128BitRawValueType b;

                AKWAesKeyWrap8BitRawValueType *ri = (r + ((i - 1) * sizeof(AKWAesKeyWrap64BitRawValueType)));
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
    memcpy(iv, a, sizeof(AKWAesKeyWrap64BitRawValueType));

    return [NSData dataWithBytes:r length:length];
}

+ (BOOL)canPlainDataBeWrapped:(NSData *)plainData error:(NSError **)error
{
    if (plainData.length < kPlainDataMinSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooSmall];
        }

        return NO;
    }

    if (plainData.length % sizeof(AKWAesKeyWrap64BitRawValueType) != 0)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataNotAlignedProperly];
        }

        return NO;
    }

    return YES;
}

+ (BOOL)canPlainDataBeWrappedWithPadding:(NSData *)plainData error:(NSError **)error
{
    if (plainData.length < kWrapWithPaddingPlainDataMinSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooSmall];
        }

        return NO;
    }

    if (plainData.length > kWrapWithPaddingPlainDataMaxSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooBig];
        }

        return NO;
    }

    return YES;
}

+ (BOOL)canCipheredDataBeUnwrapped:(NSData *)cipheredData error:(NSError **)error
{
    if (cipheredData.length < kCipheredDataMinSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooSmall];
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

+ (BOOL)canCipheredDataBeUnwrappedWithPadding:(NSData *)cipheredData error:(NSError **)error
{
    if (cipheredData.length < kWrapWithPaddingCipheredDataMinSize)
    {
        if (error)
        {
            *error = [AKWErrorFactory errorInputDataTooSmall];
        }

        return NO;
    }

    if (cipheredData.length > kWrapWithPaddingCipheredDataMaxSize)
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
            *error = [AKWErrorFactory errorIntegrityCheckingOfInitialValueFailed];
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
            *error = [AKWErrorFactory errorIntegrityCheckingOfInitialValueFailed];
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
                *error = [AKWErrorFactory errorIntegrityCheckingOfInitialValueFailed];
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
   byMultipliyingSize:(AKWAesKeyWrapSizeType)value1
           withUInt32:(AKWAesKeyWrapUInt32BitType)value2
        andAddingSize:(AKWAesKeyWrapSizeType)value3
                error:(NSError **)error
{
    if ([AKWAesKeyWrap doesUInt64OverflowByMultipliyingSize:value1 andUInt32:value2])
    {
        if (error)
        {
            *error = [AKWErrorFactory errorOverflow];
        }

        return NO;
    }
    AKWAesKeyWrapUInt64BitType multipliedValue = ((AKWAesKeyWrapUInt64BitType)value1 *
                                                  (AKWAesKeyWrapUInt64BitType)value2);

    if ([AKWAesKeyWrap doesUInt64OverflowByByAddingSize:value3 toUInt64:multipliedValue])
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

+ (BOOL)doesUInt64OverflowByMultipliyingSize:(AKWAesKeyWrapSizeType)value1
                                   andUInt32:(AKWAesKeyWrapUInt32BitType)value2
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return ((kUInt64BitMax / value1) < value2);
}

+ (BOOL)doesUInt64OverflowByByAddingSize:(AKWAesKeyWrapSizeType)sizeValue
                                toUInt64:(AKWAesKeyWrapUInt64BitType)uint64Value
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return (sizeValue > (kUInt64BitMax - uint64Value));
}

+ (BOOL)doesSizeOverflowByByAddingUInt32:(AKWAesKeyWrapUInt32BitType)value1
                                toUInt32:(AKWAesKeyWrapUInt32BitType)value2
{
    // NOTE: Compiler will automatically convert both operands to the wider type.

    return (value1 > (kSizeMax - value2));
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
