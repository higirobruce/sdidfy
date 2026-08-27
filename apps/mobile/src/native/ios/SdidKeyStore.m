#import <React/RCTBridgeModule.h>

// Bridges the Swift SdidKeyStore class to the JS side. `RCT_EXTERN_MODULE`
// and `RCT_EXTERN_METHOD` only exist in Objective-C, so a pure-Swift native
// module still needs a file like this one — it declares no logic of its own,
// only the selectors SdidKeyStore.swift implements.
//
// Also never compiled — see ../ios/README.md.

@interface RCT_EXTERN_MODULE(SdidKeyStore, NSObject)

RCT_EXTERN_METHOD(capabilities:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(hasKey:(NSString *)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generate:(NSString *)alias
                  attestationChallenge:(NSString *)attestationChallenge
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(exportPublicKey:(NSString *)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sign:(NSString *)alias
                  payload:(NSString *)payload
                  promptTitle:(NSString *)promptTitle
                  promptSubtitle:(NSString *)promptSubtitle
                  cancelLabel:(NSString *)cancelLabel
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deleteKey:(NSString *)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

@end
