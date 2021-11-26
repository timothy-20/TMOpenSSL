//
//  TMCryptoRSA.m
//  TMOpenSSL
//
//  Created by 임정운 on 2021/11/25.
//

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#import "TMCryptoRSA.h"

@implementation TMCryptoRSA

-(EVP_PKEY *)modulus:(NSString *)modulus_str exponent:(NSString *)exponent_str
{
    unsigned long rsa_modulus = modulus_str.longLongValue;
    NSLog(@"%lu", rsa_modulus);
    
    unsigned long rsa_exponent;
    
    OSSL_PARAM params[] = {
        OSSL_PARAM_ulong("n", &rsa_modulus),
        OSSL_PARAM_ulong("e", &rsa_exponent),
        OSSL_PARAM_END
    };
    
    @try {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        EVP_PKEY *public_key = NULL;
        
        if (ctx == NULL
            || EVP_PKEY_fromdata_init(ctx) <= 0
            || EVP_PKEY_fromdata(ctx, &public_key, EVP_PKEY_KEYPAIR, params) < 0) {
            
            dispatch_async(dispatch_get_main_queue(), ^{
                exit(1);
            });
        }
        
        EVP_PKEY_free(public_key);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        
        return public_key;
        
    } @catch (NSException *exception) {
        NSLog(@"Error.name: %@  Error.reason: %@", exception.name, exception.reason);
        return nil;

    } @finally {
        
    }
}

-(NSData *)plain_text:(NSString *)text public_key:(EVP_PKEY *)public_key error:(NSError **)error
{
    EVP_PKEY_CTX *ctx = NULL;
    ENGINE *engine = NULL;
    
    const char *in_data = NULL;
    unsigned char *out_data = NULL;
    size_t in_length = 0, out_length = 0;
    
    @try {
        out_length = EVP_PKEY_get_size(public_key);
        
        in_data = (const char *)text.UTF8String;
        in_length = strlen(in_data);
        
        ctx = EVP_PKEY_CTX_new(public_key, engine);
        
        if (!ctx) {
            NSLog(@"Error.ocurred:");
            *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                                code:101
                                            userInfo:@{NSLocalizedDescriptionKey : @""}];
            
            return nil;
        }
        
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            NSLog(@"Error.ocurred:");
            *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                                code:102
                                            userInfo:@{NSLocalizedDescriptionKey : @""}];
            
            return nil;
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            NSLog(@"Error.ocurred:");
            *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                                code:103
                                            userInfo:@{NSLocalizedDescriptionKey : @""}];
            
            return nil;
        }
        
        if (EVP_PKEY_encrypt(ctx, NULL, &out_length, (const unsigned char *)in_data, in_length) < 0) {
            NSLog(@"Error.ocurred:");
            *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                                code:104
                                            userInfo:@{NSLocalizedDescriptionKey : @""}];
            
            return nil;
        }
        
        out_data = OPENSSL_malloc(out_length);
        
        if (!out_data) {
            
            NSLog(@"Error.ocurred: OpenSSL malloc fail.");
            *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                                code:105
                                            userInfo:@{NSLocalizedDescriptionKey : @""}];
            
            return nil;
        }
        
        if (EVP_PKEY_encrypt(ctx, out_data, &out_length, (const unsigned char *)in_data, in_length) <= 0) {
            NSLog(@"Error.oucrred: ");
            *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                                code:106
                                            userInfo:@{NSLocalizedDescriptionKey : @""}];
            
            return nil;
        }
        
        return [[NSData alloc] initWithBytes:out_data length:out_length];
        
    } @catch (NSException *exception) {
        NSLog(@"Error.name: %@  Error.reason: %@", exception.name, exception.reason);
        *error = [[NSError alloc] initWithDomain:@"timothy.openssl.rsa"
                                            code:500
                                        userInfo:@{NSLocalizedDescriptionKey : exception.reason}];
        
        return nil;
        
    } @finally {
        
    }
}

@end
