//
//  MileWalletBridge.m
//  mile-ios-sdk
//
//  Created by denis svinarchuk on 18.06.2018.
//  Copyright © 2018 Mile Core. All rights reserved.
//

#include <stdio.h>
#include <ed25519.hpp>
#include <iostream>

#import "ed25519_wrapper.h"

@interface DigestCalculator()
- (instancetype) initWithC:(ed25519::Digest::Calculator *)c;
@end

@interface PublicKey ()
- (std::optional<ed25519::keys::Public>) data;
- (instancetype) initWithKey:(std::optional<ed25519::keys::Public>) key;
@end

@interface PrivateKey ()
- (std::optional<ed25519::keys::Private>) data;
- (instancetype) initWithKey:(std::optional<ed25519::keys::Private>) key;
@end

@interface Seed ()
- (std::optional<ed25519::Seed>) data;
@end

@interface Digest ()
- (std::optional<ed25519::Digest>) data;
@end

@interface Signature ()
- (instancetype) initWithSignature:(std::optional<ed25519::Signature>) signature;
@end

inline NSError *error2NSError(const std::error_code &code){
    
    NSDictionary *userInfo = @{
                               NSLocalizedDescriptionKey: NSLocalizedString([NSString stringWithUTF8String:code.message().c_str()], nil),
                               NSLocalizedFailureReasonErrorKey: NSLocalizedString(@"ed25512 error", nil)
                               };
    
     return [NSError errorWithDomain:NSEd25519ErrorDomain code:(NSInteger)(code.value())
                                     userInfo:userInfo];
}


@implementation Seed
{
    ed25519::Seed* seed;
}

- (void)dealloc
{
    delete seed;
}

- (std::optional<ed25519::Seed>) data {
    return *seed;
}

- (_Nullable instancetype) initWithBase58:(nonnull NSString *)base58 error:(NSError * _Nullable*_Nullable)error {
    self = [[Seed alloc] init];
    if (self){
        if([self decode:base58 error:error]) {
            return self;
        }
        else {
            return nil;
        }
    }
    return self;
}

- (instancetype) init {
    self = [super init];
    if (self) {
        seed = new ed25519::Seed();
    }
    return self;
}

- (instancetype) initWithSecret:(NSString *)phrase {
    self = [super init];
    if (self) {
        seed = new ed25519::Seed([phrase UTF8String]);
    }
    return self;
}

- (BOOL)decode:(NSString *)base58 error:(NSError **)error {
    return seed->decode([base58 UTF8String],
                        [error](const std::error_code &code){
                            if (error)
                                *error = error2NSError(code);
                        });
}

- (NSString *)encode {
    return [NSString stringWithUTF8String:seed->encode().c_str()];
}

@end


@implementation PublicKey
{
    std::optional<ed25519::keys::Public> key;
}

- (instancetype) initWithKey:(std::optional<ed25519::keys::Public>) inkey{
    self = [[PublicKey alloc] init];
    if (self){
        key = inkey;
    }
    return self;
}

- (std::optional<ed25519::keys::Public>) data {
    return key;
}

- (_Nullable instancetype) initWithBase58:(nonnull NSString *)base58 error:(NSError * _Nullable*_Nullable)error {
    self = [[PublicKey alloc] init];
    if (self){
        key = ed25519::keys::Public::Decode([base58 UTF8String],
                                            [error](const std::error_code &code){
                                                if (error)
                                                    *error = error2NSError(code);
                                            });
        if (key) {
            return self;
        }
        return nil;
 
    }
    return self;
}


- (NSString *)encode {
    return [NSString stringWithUTF8String:key->encode().c_str()];
}

@end

@implementation PrivateKey
{
    std::optional<ed25519::keys::Private> key;
}

- (instancetype) initWithKey:(std::optional<ed25519::keys::Private>) inkey{
    self = [[PrivateKey alloc] init];
    if (self){
        key = inkey;
    }
    return self;
}

- (std::optional<ed25519::keys::Private>) data {
    return key;
}

- (_Nullable instancetype) initWithBase58:(nonnull NSString *)base58 error:(NSError * _Nullable*_Nullable)error {
    self = [[PrivateKey alloc] init];
    if (self){
        key = ed25519::keys::Private::Decode([base58 UTF8String],
                                            [error](const std::error_code &code){
                                                if (error)
                                                    *error = error2NSError(code);
                                            });
        if (key) {
            return self;
        }
        return nil;
        
    }
    return self;
}


- (NSString *)encode {
    return [NSString stringWithUTF8String:key->encode().c_str()];
}

@end

@implementation Digest
{
    std::optional<ed25519::Digest> digest;
}

- (std::optional<ed25519::Digest>) data {
    return digest;
}

- (instancetype) initWithCalculator:(DigestCalculatorType)calculator{
    
    self = [[Digest alloc] init];
    if (self){
        
        ed25519::Digest d = ed25519::Digest([&calculator](ed25519::Digest::Calculator &_calculator){
            DigestCalculator *digest_calculator = [[DigestCalculator alloc] initWithC:&_calculator];
            calculator(digest_calculator);
        });
        
        digest = std::make_optional(d);
        return self;
    }
    return self;
    
}

- (nonnull NSString *)encode {
    return [NSString stringWithUTF8String:digest->encode().c_str()];
}

- (instancetype _Nullable)initWithBase58:(nonnull NSString *)base58 error:(NSError *__autoreleasing  _Nullable * _Nullable)error {
    self = [[Digest alloc] init];
    if (self){
        digest = ed25519::Digest::Decode([base58 UTF8String],
                                         [error](const std::error_code &code){
                                             if (error)
                                                 *error = error2NSError(code);
                                         });
        if (digest) {
            return self;
        }
        return nil;
        
    }
    return self;
}

- (BOOL)decode:(nonnull NSString *)base58 error:(NSError *__autoreleasing  _Nullable * _Nullable)error {
    return digest->decode([base58 UTF8String],
                          [error](const std::error_code &code){
                              if (error)
                                  *error = error2NSError(code);
                          });
}

@end

@implementation DigestCalculator
{
    ed25519::Digest::Calculator *calculator;
}

- (instancetype) initWithC:(ed25519::Digest::Calculator *)c{
    self = [super init];
    if (self){
        calculator = c;
    }
    return self;
}

- (instancetype) appendInteger:(NSInteger)integer{
    calculator->append((int)integer);
    return self;
}

- (instancetype) appendString:(NSString*)string {
    calculator->append([string UTF8String]);
    return self;
}

- (nonnull instancetype) appendBool:(bool)value {
    calculator->append(value);
    return self;
}

- (nonnull instancetype) appendUInt8:(uint8)value {
    calculator->append(value);
    return self;
}

- (nonnull instancetype) appendInt16:(int16_t)value {
    calculator->append(value);
    return self;
}

- (nonnull instancetype) appendPublicKey:(PublicKey *_Nonnull)value {
    calculator->append(*[value data]);
    return self;
}

- (nonnull instancetype) appendPrivateKey:(PrivateKey *_Nonnull)value {
    calculator->append(*[value data]);
    return self;
}

- (nonnull instancetype) appendSeed:(Seed *_Nonnull)value{
    calculator->append(*[value data]);
    return self;
}

- (nonnull instancetype) appendDigest:(Digest *_Nonnull)value{
    calculator->append(*[value data]);
    return self;
}

@end

@implementation Signature
{
    std::optional<ed25519::Signature> signature;
}

- (instancetype) initWithSignature:(std::optional<ed25519::Signature>) inSignature{
    self = [[Signature alloc] init];
    if (self){
        signature = inSignature;
    }
    return self;
}

- (_Nullable instancetype) initWithBase58:(nonnull NSString *)base58 error:(NSError * _Nullable*_Nullable)error {
    self = [[Signature alloc] init];
    if (self){
        signature = ed25519::Signature::Decode([base58 UTF8String],
                                             [error](const std::error_code &code){
                                                 if (error)
                                                     *error = error2NSError(code);
                                             });
        if (signature) {
            return self;
        }
        return nil;
        
    }
    return self;
}

- (nonnull NSString *)encode {
    return [NSString stringWithUTF8String:signature->encode().c_str()];
}


- (BOOL) verifyWithPublic:(nonnull PublicKey*)publicKey message:(nonnull NSData *)message  {
    size_t len = [message length];

    std::vector<unsigned char> v; v.resize(len,0);
    
    [message getBytes:v.data() length:len];
    
    return signature->verify(v, *[publicKey data]);
}

- (BOOL) verifyWithPublic:(nonnull PublicKey*)publicKey string:(nonnull NSString *)string {
    return signature->verify([string UTF8String], *[publicKey data]);
}

- (BOOL) verifyWithPublic:(nonnull PublicKey*)publicKey digest:(nonnull Digest *)digest {
    return signature->verify(*[digest data], *[publicKey data]);
}

@end

@implementation Pair
{
    std::optional<ed25519::keys::Pair> pair;
    PublicKey  *pk;
    PrivateKey *pvk;
}

- (PublicKey*) publicKey {
    return pk;
}

- (PrivateKey*) privateKey {
    return pvk;
}

- (instancetype) init {
    self = [super init];
    return self;
}

+(instancetype)Random {
    Pair *p = [[Pair alloc ] init];
    p->pair = ed25519::keys::Pair::Random();
    p->pk = [[PublicKey alloc] initWithKey:p->pair->get_public_key()];
    p->pvk = [[PrivateKey alloc] initWithKey:p->pair->get_private_key()];
    return p;
}

- (nullable instancetype)initWithSecretPhrase:(nonnull NSString*)phrase
                                        error:(NSError *_Null_unspecified __autoreleasing *_Null_unspecified)error {
    pair = ed25519::keys
    ::Pair::WithSecret([phrase UTF8String],
                       
                       [error](const std::error_code &code){
                           if (error)
                               *error = error2NSError(code);
                       });
    
    if (pair) {
        
        self = [super init];
        pk = [[PublicKey alloc] initWithKey:pair->get_public_key()];
        pvk = [[PrivateKey alloc] initWithKey:pair->get_private_key()];
        
        return self;
    }
    
    return nil;
}

- (nullable instancetype)initFromPrivateKey:(nonnull NSString*)privateKey
                                 error:(NSError *_Null_unspecified __autoreleasing *_Null_unspecified)error{
    
    pair = ed25519 ::keys::Pair
    ::FromPrivateKey ([privateKey UTF8String],
                      
                      [error](const std::error_code &code){
                          if (error)
                              *error = error2NSError(code);
                      });
    
    if (pair) {
        
        self = [super init];
        pk = [[PublicKey alloc] initWithKey:pair->get_public_key()];
        pvk = [[PrivateKey alloc] initWithKey:pair->get_private_key()];
        
        return self;
    }
    
    return nil;
}

- (nonnull Signature*) signMessage:(nonnull NSData*)message {
   
    size_t len = [message length];
    std::vector<unsigned char> v; v.resize(len,0);
    [message getBytes:v.data() length:len];

    return [[Signature alloc] initWithSignature:*std::move(pair->sign(v))];
}

- (nonnull Signature*) signString:(nonnull NSString*)message{
    return [[Signature alloc] initWithSignature:*std::move(pair->sign([message UTF8String]))];
}

- (nonnull Signature*) signDigest:(nonnull Digest*)digest{
    auto s = pair->sign(*[digest data]);
    return [[Signature alloc] initWithSignature:*std::move(s)];
}

- (NSString *) description {
    return [NSString stringWithFormat:@"%@:%@", [pk encode], [pvk encode] ];
}

@end
