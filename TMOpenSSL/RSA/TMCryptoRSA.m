//
//  TMCryptoRSA.m
//  TMOpenSSL
//
//  Created by 임정운 on 2021/11/25.
//

#include <openssl/evp.h>

#import "TMCryptoRSA.h"

@implementation TMCryptoRSA

-(void)modulus:(NSString *)modulus_str exponent:(NSString *)exponent_str
{
    unsigned long rsa_modulus;
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
            || evp) {
            <#statements#>
        }
        
    } @catch (NSException *exception) {
        
    } @finally {
        
    }
}

@end
