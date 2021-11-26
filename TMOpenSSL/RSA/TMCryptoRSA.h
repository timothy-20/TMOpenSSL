//
//  TMCryptoRSA.h
//  TMOpenSSL
//
//  Created by 임정운 on 2021/11/25.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TMCryptoRSA : NSObject

- (id)modulus:(NSString *)modulus_str exponent:(NSString *)exponent_str;
- (NSData *)plain_text:(NSString *)text public_key:(id)public_key error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
