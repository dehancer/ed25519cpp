//
//  MileWalletBridge.h
//  mile-ios-sdk
//
//  Created by denis svinarchuk on 18.06.2018.
//  Copyright © 2018 Mile Core. All rights reserved.
//

#import <Foundation/Foundation.h>

#define NSEd25519ErrorDomain @"NSEd25519ErrorDomain"

@protocol ProtectedBase58 <NSObject>
- (_Nullable instancetype) initWithBase58:(nonnull NSString *)base58 error:(NSError * _Nullable*_Nullable)error;
- (nonnull NSString *) encode;
@end

@protocol Base58 <ProtectedBase58>
- (BOOL) decode:(nonnull NSString *)base58 error:(NSError * _Nullable*_Nullable)error;
@end

@interface Seed : NSObject<Base58>
- (nonnull instancetype) initWithSecret:(nonnull NSString *)phrase;
- (nonnull instancetype) init;
@end

@interface PublicKey : NSObject<ProtectedBase58>
@end

@interface PrivateKey : NSObject<ProtectedBase58>
@end

@interface Digest : NSObject<Base58>
@end

@interface DigestCalculator : NSObject
- (nonnull instancetype) appendBool:(bool)value;
- (nonnull instancetype) appendUInt8:(uint8)value;
- (nonnull instancetype) appendInt16:(int16_t)value;
- (nonnull instancetype) appendPublicKey:(PublicKey *_Nonnull)value;
- (nonnull instancetype) appendPrivateKey:(PrivateKey *_Nonnull)value;
- (nonnull instancetype) appendSeed:(Seed *_Nonnull)value;
- (nonnull instancetype) appendDigest:(Digest *_Nonnull)value;
- (nonnull instancetype) appendInteger:(NSInteger)value;
- (nonnull instancetype) appendString:(NSString * _Nonnull )value;
@end

typedef void (^DigestCalculatorType)(DigestCalculator*_Nonnull);

@interface Digest()
- (nonnull instancetype) initWithCalculator:(DigestCalculatorType _Nonnull )calculator;
@end

@interface Signature : NSObject<ProtectedBase58>
- (BOOL) verifyWithPublic:(nonnull PublicKey*)publicKey message:(nonnull NSData *)message  ;
- (BOOL) verifyWithPublic:(nonnull PublicKey*)publicKey string:(nonnull NSString *)string ;
- (BOOL) verifyWithPublic:(nonnull PublicKey*)publicKey digest:(nonnull Digest *)digest ;
@end

@interface Pair: NSObject

@property (readonly,atomic) PublicKey * _Nonnull publicKey;
@property (readonly,atomic) PrivateKey * _Nonnull privateKey;

/**
 * Create new wallet pair: public and private keys
 *
 * @return wallet pair keys
 */
+(nonnull instancetype)Random;

/**
* Create new wallet pair with as secret phrase
*
* @param phrase - secret phrase
* @param error - handle error if pair could not be created
* @return wallet pair keys
*/
 - (nullable instancetype)initWithSecretPhrase:(nonnull NSString*)phrase
                                   error:(NSError *_Null_unspecified __autoreleasing *_Null_unspecified)error;


/**
 * Restore wallet pair from private key
 *
 * @param privateKey - wallet private key
 * @param error - handle error if pair could not be created
 * @return wallet pair keys
 */
- (nullable instancetype)initFromPrivateKey:(nonnull NSString*)privateKey
                                 error:(NSError *_Null_unspecified __autoreleasing *_Null_unspecified)error;

- (nonnull Signature*) signMessage:(nonnull NSData*)message;
- (nonnull Signature*) signString:(nonnull NSString*)string;
- (nonnull Signature*) signDigest:(nonnull Digest*)digest;
@end
