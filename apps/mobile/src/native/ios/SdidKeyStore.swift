import Foundation
import LocalAuthentication
import Security

/// `SdidKeyStore` — CONTRACT.md §1.2/§1.3/§1.4/§1.5. Written against the six
/// methods `SdidKeyStoreNativeModule` declares in `../contract.ts`; never
/// compiled or run — see `../ios/README.md` for exactly what's missing
/// before it can be. Exported to the bridge by `SdidKeyStore.m`, since the
/// `RCT_EXTERN_MODULE`/`RCT_EXTERN_METHOD` macros only exist in
/// Objective-C.
@objc(SdidKeyStore)
class SdidKeyStore: NSObject {

  private static let coordinateLength = 32

  /// Nothing here touches AppKit/UIKit directly — Security and
  /// LocalAuthentication hop to the main thread internally when they need
  /// to show UI, so this module doesn't need main-queue init itself.
  @objc static func requiresMainQueueSetup() -> Bool { false }

  // MARK: capabilities

  /// A best-effort STATIC probe — it does not generate a key. iOS has no
  /// StrongBox equivalent (Secure Enclave only), so a real key is always
  /// "tee" once generation actually succeeds; `supportsKeyAttestation` is
  /// always false here because iOS carries key attestation through App
  /// Attest (`SdidAttestation`, §2.2), never through this module.
  @objc(capabilities:reject:)
  func capabilities(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    #if targetEnvironment(simulator)
    let available = false
    #else
    let available = true
    #endif
    resolve([
      "available": available,
      "securityLevel": available ? "tee" : "software",
      "supportsKeyAttestation": false,
    ] as [String: Any])
  }

  // MARK: hasKey

  @objc(hasKey:resolve:reject:)
  func hasKey(
    _ alias: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: false,
    ]
    resolve(SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess)
  }

  // MARK: generate

  /// `attestationChallenge` is accepted but unused — CONTRACT.md §1.2 is
  /// explicit that iOS does not bind the attestation challenge here; it's
  /// bound at App Attest time instead (§2.2), via `clientData`, not this key.
  @objc(generate:attestationChallenge:resolve:reject:)
  func generate(
    _ alias: String,
    attestationChallenge: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    #if targetEnvironment(simulator)
    // Ground rule (CONTRACT.md §0, T3): refuse trust-bearing output on a
    // simulator rather than silently degrading. In practice
    // SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave simply fails on
    // the simulator anyway — this guard just fails faster and clearer.
    reject("E_SECURE_HARDWARE_UNAVAILABLE", "no Secure Enclave on the simulator", nil)
    return
    #else
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage, .biometryCurrentSet],
      &accessError
    ) else {
      reject("E_KEYSTORE", "SecAccessControlCreateWithFlags failed: \(describeCFError(accessError))", nil)
      return
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: Data(alias.utf8),
        kSecAttrAccessControl as String: access,
      ],
    ]

    var createError: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) else {
      reject("E_SECURE_HARDWARE_UNAVAILABLE", "SecKeyCreateRandomKey failed: \(describeCFError(createError))", nil)
      return
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey),
          let (x, y) = Self.rawCoordinates(publicKey)
    else {
      reject("E_KEYSTORE", "could not derive the public key point", nil)
      return
    }

    resolve([
      "publicKeyX": Self.base64Url(x),
      "publicKeyY": Self.base64Url(y),
      "securityLevel": "tee",
      // No "keyAttestation" field — App Attest carries it instead (§2.2).
    ] as [String: Any])
    #endif
  }

  // MARK: exportPublicKey

  @objc(exportPublicKey:resolve:reject:)
  func exportPublicKey(
    _ alias: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let privateKey = Self.copyPrivateKey(alias: alias),
          let publicKey = SecKeyCopyPublicKey(privateKey),
          let (x, y) = Self.rawCoordinates(publicKey)
    else {
      reject("E_KEY_NOT_FOUND", "no key for \(alias)", nil)
      return
    }
    resolve(["publicKeyX": Self.base64Url(x), "publicKeyY": Self.base64Url(y)] as [String: Any])
  }

  // MARK: sign

  /// The prompt is raised INSIDE this call — there is deliberately no
  /// separate unlock step (T1, T7): fetching the key with an
  /// authentication-context-bound query, then calling
  /// `SecKeyCreateSignature` on THAT key reference, is what makes the
  /// biometric evaluation and the signature happen as one operation with no
  /// gap between them for anything to race into.
  @objc(sign:payload:promptTitle:promptSubtitle:cancelLabel:resolve:reject:)
  func sign(
    _ alias: String,
    payload: String,
    promptTitle: String,
    promptSubtitle: String,
    cancelLabel: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let payloadData = payload.data(using: .utf8) else {
      reject("E_KEYSTORE", "payload is not valid UTF-8", nil)
      return
    }

    let context = LAContext()
    // Rendered verbatim — already localised (05 §7); no English default here.
    context.localizedCancelTitle = cancelLabel
    let operationPrompt = promptSubtitle.isEmpty ? promptTitle : promptSubtitle

    // NOTE — found while implementing, NOT verified on a real device:
    // CONTRACT.md §1.3 describes "an LAContext with localizedReason via
    // kSecUseAuthenticationContext". LAContext has no settable
    // `localizedReason` property — that string only exists as a parameter to
    // `evaluatePolicy(_:localizedReason:reply:)`, which this method must NOT
    // call separately (that would be exactly the "authenticate, then sign"
    // race T1/T7 forbid). The pattern below instead binds the reason text
    // (`kSecUseOperationPrompt`) and the cancel-button context
    // (`kSecUseAuthenticationContext`) to the QUERY that fetches the key
    // reference; `SecKeyCreateSignature` on the returned reference then
    // triggers Face ID/Touch ID using that binding, still with no separate
    // evaluate call. This is Apple's documented shape for prompting on a
    // biometry-gated Keychain key, but nothing here has run on hardware —
    // treat the exact prompt text/behaviour as unverified until it has.
    guard let privateKey = Self.copyPrivateKeyForSigning(
      alias: alias,
      context: context,
      operationPrompt: operationPrompt
    ) else {
      reject("E_KEY_NOT_FOUND", "no key for \(alias)", nil)
      return
    }

    var signError: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
      privateKey,
      .ecdsaSignatureMessageX962SHA256,
      payloadData as CFData,
      &signError
    ) as Data? else {
      let nsError = signError?.takeRetainedValue()
      reject(Self.mapSigningError(nsError), "SecKeyCreateSignature failed: \(describeCFError(signError))", nil)
      return
    }

    guard let raw = Self.derToRawRs(Array(signature)) else {
      reject("E_KEYSTORE", "DER to raw r||s conversion failed", nil)
      return
    }
    resolve(Self.base64Url(Data(raw)))
  }

  // MARK: deleteKey

  /// Irreversible, and a no-op (not an error) if the alias is already gone —
  /// must succeed even after a biometric re-enrolment invalidated the key.
  @objc(deleteKey:resolve:reject:)
  func deleteKey(
    _ alias: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
      resolve(NSNull())
    } else {
      reject("E_KEYSTORE", "SecItemDelete failed: OSStatus \(status)", nil)
    }
  }

  // MARK: - shared helpers

  private static func copyPrivateKey(alias: String) -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
    return (item as! SecKey)
  }

  /// Same lookup as `copyPrivateKey`, but binds the auth context and prompt
  /// text to the query itself — see the note in `sign()`.
  private static func copyPrivateKeyForSigning(
    alias: String,
    context: LAContext,
    operationPrompt: String
  ) -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
      kSecUseAuthenticationContext as String: context,
      kSecUseOperationPrompt as String: operationPrompt,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
    return (item as! SecKey)
  }

  /// Uncompressed SEC1 point `0x04 ‖ X(32) ‖ Y(32)` → the two raw coordinates.
  /// `SecKeyCopyExternalRepresentation` works here because this is the
  /// PUBLIC half — Secure Enclave private keys are non-exportable by
  /// construction, and this file never calls it on one.
  private static func rawCoordinates(_ key: SecKey) -> (Data, Data)? {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return nil }
    guard data.count == 1 + 2 * coordinateLength, data.first == 0x04 else { return nil }
    let x = data.subdata(in: 1..<(1 + coordinateLength))
    let y = data.subdata(in: (1 + coordinateLength)..<(1 + 2 * coordinateLength))
    return (x, y)
  }

  private static func base64Url(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  /// Best-effort mapping — not verified against a real device's actual error
  /// domain/code combinations. `LAError`'s domain surfaces even through
  /// Security-framework-triggered evaluation, since Security delegates the
  /// biometric prompt to LocalAuthentication under the hood.
  private static func mapSigningError(_ error: Error?) -> String {
    guard let nsError = error as NSError? else { return "E_KEYSTORE" }
    if nsError.domain == LAError.errorDomain {
      switch LAError.Code(rawValue: nsError.code) {
      case .userCancel, .systemCancel, .appCancel:
        return "E_BIOMETRIC_CANCELLED"
      case .biometryLockout:
        return "E_BIOMETRIC_LOCKOUT"
      case .biometryNotEnrolled:
        return "E_BIOMETRIC_NOT_ENROLLED"
      case .biometryNotAvailable:
        return "E_SECURE_HARDWARE_UNAVAILABLE"
      default:
        return "E_BIOMETRIC_FAILED"
      }
    }
    if nsError.domain == NSOSStatusErrorDomain, nsError.code == Int(errSecUserCanceled) {
      return "E_BIOMETRIC_CANCELLED"
    }
    return "E_KEYSTORE"
  }

  /// DER `SEQUENCE { INTEGER r, INTEGER s }` → raw `r ‖ s`, each left-padded
  /// to 32 bytes with DER's sign byte stripped (CONTRACT.md §1.4). Hand-rolled
  /// rather than pulling in an ASN.1 library for two fixed-shape INTEGERs —
  /// identical logic to the Android side's `derToRawRs`, on purpose, so a
  /// bug found in one known-vector test suggests looking at the other.
  private static func derToRawRs(_ der: [UInt8]) -> [UInt8]? {
    guard der.first == 0x30 else { return nil }
    var offset = 1
    guard let seqLenSize = derLengthSize(der, offset) else { return nil }
    offset += seqLenSize
    guard let (rValue, rConsumed) = readDerInteger(der, offset) else { return nil }
    offset += rConsumed
    guard let (sValue, _) = readDerInteger(der, offset) else { return nil }
    return normalise(rValue) + normalise(sValue)
  }

  private static func derLengthSize(_ der: [UInt8], _ offset: Int) -> Int? {
    guard offset < der.count else { return nil }
    let first = Int(der[offset])
    return first < 0x80 ? 1 : 1 + (first & 0x7F)
  }

  private static func derLengthValue(_ der: [UInt8], _ offset: Int) -> Int {
    let first = Int(der[offset])
    if first < 0x80 { return first }
    var length = 0
    for i in 1...(first & 0x7F) {
      length = (length << 8) | Int(der[offset + i])
    }
    return length
  }

  private static func readDerInteger(_ der: [UInt8], _ offset: Int) -> ([UInt8], Int)? {
    guard offset < der.count, der[offset] == 0x02 else { return nil }
    guard let lengthSize = derLengthSize(der, offset + 1) else { return nil }
    let length = derLengthValue(der, offset + 1)
    let valueStart = offset + 1 + lengthSize
    guard valueStart + length <= der.count else { return nil }
    return (Array(der[valueStart..<(valueStart + length)]), 1 + lengthSize + length)
  }

  /// Strips a DER sign byte or left-pads to exactly `coordinateLength` bytes.
  private static func normalise(_ value: [UInt8]) -> [UInt8] {
    var trimmed = value
    if trimmed.count > coordinateLength && trimmed.first == 0 {
      trimmed.removeFirst()
    }
    if trimmed.count == coordinateLength { return trimmed }
    var padded = [UInt8](repeating: 0, count: coordinateLength)
    padded.replaceSubrange((coordinateLength - trimmed.count)..<coordinateLength, with: trimmed)
    return padded
  }
}

private func describeCFError(_ error: Unmanaged<CFError>?) -> String {
  guard let error = error?.takeRetainedValue() else { return "unknown" }
  return CFErrorCopyDescription(error) as String? ?? "unknown"
}
