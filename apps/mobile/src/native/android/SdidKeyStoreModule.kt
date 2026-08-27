package com.sdid.authenticator.keystore

// Package name is a placeholder — see ../android/README.md. Rename to match
// whatever `android.package` ends up in app.json (decision pending), and keep
// it identical to the broker's ANDROID_PACKAGE_NAME (runbook.md §10).

import android.app.KeyguardManager
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.concurrent.Executor

/**
 * `SdidKeyStore` — CONTRACT.md §1.1/§1.3/§1.4/§1.5. Written against the six
 * methods `SdidKeyStoreNativeModule` declares in `contract.ts`; never
 * compiled or run — see ../android/README.md for exactly what's missing
 * before it can be.
 *
 * NOT wired into any generated Gradle project. See ../android/README.md.
 */
class SdidKeyStoreModule(
  private val reactContext: ReactApplicationContext,
) : ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = "SdidKeyStore"

  private companion object {
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    const val EC_CURVE = "secp256r1"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    /** P-256 coordinates are always 32 bytes (CONTRACT.md's own rule for the broker side). */
    const val COORD_LENGTH = 32
    /**
     * Settled in CONTRACT.md §1.1: the first API level with
     * setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG).
     */
    const val MIN_API_LEVEL = 30
  }

  private fun androidKeyStore(): KeyStore =
    KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

  private fun reject(promise: Promise, code: String, detail: String) {
    // `message` is developer-only (CONTRACT.md ground rule 2) — never a
    // citizen-facing string, and never logged with argument values.
    promise.reject(code, detail)
  }

  // ── capabilities ──────────────────────────────────────────────────────────

  /**
   * A best-effort STATIC probe — it does not generate a key. The
   * authoritative security level for an actual key comes from `generate()`'s
   * own KeyInfo read, which is what the TS layer's enrolment gate trusts.
   */
  @ReactMethod
  fun capabilities(promise: Promise) {
    val available = Build.VERSION.SDK_INT >= MIN_API_LEVEL
    val hasStrongBox = reactContext.packageManager
      .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    val result: WritableMap = Arguments.createMap().apply {
      putBoolean("available", available)
      // AndroidKeyStore is TEE-backed by CDD mandate on any API-30+ device
      // that ships GMS; StrongBox is the stronger, narrower case.
      putString("securityLevel", if (available && hasStrongBox) "strongbox" else if (available) "tee" else "software")
      putBoolean("supportsKeyAttestation", available)
    }
    promise.resolve(result)
  }

  // ── hasKey ────────────────────────────────────────────────────────────────

  @ReactMethod
  fun hasKey(alias: String, promise: Promise) {
    try {
      promise.resolve(androidKeyStore().containsAlias(alias))
    } catch (e: Exception) {
      reject(promise, "E_KEYSTORE", "hasKey failed: ${e.javaClass.simpleName}")
    }
  }

  // ── generate ──────────────────────────────────────────────────────────────

  @ReactMethod
  fun generate(alias: String, attestationChallenge: String, promise: Promise) {
    if (Build.VERSION.SDK_INT < MIN_API_LEVEL) {
      reject(promise, "E_SECURE_HARDWARE_UNAVAILABLE", "API ${Build.VERSION.SDK_INT} is below the floor of $MIN_API_LEVEL")
      return
    }
    try {
      val keyPair = generateKeyPair(alias, attestationChallenge, strongBox = true)
        ?: generateKeyPair(alias, attestationChallenge, strongBox = false)
        ?: run {
          reject(promise, "E_KEYSTORE", "key generation returned no keypair")
          return
        }

      val ks = androidKeyStore()
      val keyInfo = readKeyInfo(alias)
      val securityLevel = securityLevelOf(keyInfo)
      val chain = ks.getCertificateChain(alias)
        ?: run {
          reject(promise, "E_KEYSTORE", "no certificate chain for $alias")
          return
        }
      // getCertificateChain is leaf-first per the AndroidKeyStore contract —
      // runbook §10 requires leaf-first, so no re-ordering here.
      val chainJson = chain.joinToString(prefix = "[", postfix = "]", separator = ",") { cert ->
        "\"${Base64.getEncoder().encodeToString(cert.encoded)}\""
      }

      val publicKey = keyPair.public as ECPublicKey
      val (x, y) = rawCoordinates(publicKey)

      val result: WritableMap = Arguments.createMap().apply {
        putString("publicKeyX", base64Url(x))
        putString("publicKeyY", base64Url(y))
        putString("securityLevel", securityLevel)
        putString("keyAttestation", chainJson)
      }
      promise.resolve(result)
    } catch (e: Exception) {
      reject(promise, "E_KEYSTORE", "generate failed: ${e.javaClass.simpleName}: ${e.message}")
    }
  }

  /** Returns null on StrongBoxUnavailableException so the caller can retry without it. */
  private fun generateKeyPair(
    alias: String,
    attestationChallenge: String,
    strongBox: Boolean,
  ): java.security.KeyPair? {
    val specBuilder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(EC_CURVE))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setUserAuthenticationRequired(true)
      // Validity duration 0: one authentication authorises exactly one
      // signature (T1) — never widen this.
      .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      .setInvalidatedByBiometricEnrollment(true)

    // The UTF-8 bytes of the nonce STRING, not the base64url-decoded bytes —
    // the exact trap runbook §10 calls out. An empty challenge means "no
    // attestation requested" (mock-mode enrolment, or a retry path that
    // supplies '').
    if (attestationChallenge.isNotEmpty()) {
      specBuilder.setAttestationChallenge(attestationChallenge.toByteArray(Charsets.UTF_8))
    }
    if (strongBox) {
      specBuilder.setIsStrongBoxBacked(true)
    }

    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
    return try {
      generator.initialize(specBuilder.build())
      generator.generateKeyPair()
    } catch (e: StrongBoxUnavailableException) {
      if (strongBox) null else throw e
    }
  }

  private fun readKeyInfo(alias: String): KeyInfo {
    val entry = androidKeyStore().getEntry(alias, null) as KeyStore.PrivateKeyEntry
    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, KEYSTORE_PROVIDER)
    return factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
  }

  /**
   * `KeyInfo.getSecurityLevel()` needs API 31 — CONTRACT.md §1.1 assumes it
   * unconditionally, but our floor is 30 (settled elsewhere in this doc), so
   * there's one API level where it doesn't exist. Found while implementing
   * this method, not guessed: on exactly API 30, fall back to
   * `isInsideSecureHardware`, which can't distinguish StrongBox from TEE, so
   * it's reported as the conservative "tee" rather than guessing "strongbox".
   */
  private fun securityLevelOf(keyInfo: KeyInfo): String {
    if (Build.VERSION.SDK_INT >= 31) {
      return when (keyInfo.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
        else -> "software"
      }
    }
    @Suppress("DEPRECATION")
    return if (keyInfo.isInsideSecureHardware) "tee" else "software"
  }

  // ── exportPublicKey ───────────────────────────────────────────────────────

  @ReactMethod
  fun exportPublicKey(alias: String, promise: Promise) {
    try {
      val cert = androidKeyStore().getCertificate(alias)
        ?: run {
          reject(promise, "E_KEY_NOT_FOUND", "no certificate for $alias")
          return
        }
      val publicKey = cert.publicKey as ECPublicKey
      val (x, y) = rawCoordinates(publicKey)
      val result: WritableMap = Arguments.createMap().apply {
        putString("publicKeyX", base64Url(x))
        putString("publicKeyY", base64Url(y))
      }
      promise.resolve(result)
    } catch (e: Exception) {
      reject(promise, "E_KEY_NOT_FOUND", "exportPublicKey failed: ${e.javaClass.simpleName}")
    }
  }

  // ── sign ──────────────────────────────────────────────────────────────────

  /**
   * The prompt is raised INSIDE this call, on the CryptoObject's Signature
   * instance — there is deliberately no separate unlock step (T1, T7). Only
   * the Signature handed back in onAuthenticationSucceeded is ever signed
   * with; it is never re-initialised.
   */
  @ReactMethod
  fun sign(
    alias: String,
    payload: String,
    promptTitle: String,
    promptSubtitle: String,
    cancelLabel: String,
    promise: Promise,
  ) {
    val activity = reactContext.currentActivity as? FragmentActivity
    if (activity == null) {
      reject(promise, "E_KEYSTORE", "no FragmentActivity available to host the biometric prompt")
      return
    }

    val entry = try {
      androidKeyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
    } catch (e: Exception) {
      null
    }
    if (entry == null) {
      reject(promise, "E_KEY_NOT_FOUND", "no key for $alias")
      return
    }

    val signature = try {
      Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(entry.privateKey) }
    } catch (e: Exception) {
      reject(promise, "E_KEYSTORE", "initSign failed: ${e.javaClass.simpleName}")
      return
    }

    val cryptoObject = BiometricPrompt.CryptoObject(signature)
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      // Rendered verbatim — these already arrived localised (05 §7); no
      // English fallback is substituted here.
      .setTitle(promptTitle)
      .setSubtitle(promptSubtitle)
      .setNegativeButtonText(cancelLabel)
      .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
      .build()

    val mainExecutor: Executor = ContextCompat.getMainExecutor(reactContext)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        val authorisedSignature = result.cryptoObject?.signature
        if (authorisedSignature == null) {
          reject(promise, "E_KEYSTORE", "authentication succeeded with no CryptoObject.signature")
          return
        }
        try {
          authorisedSignature.update(payload.toByteArray(Charsets.UTF_8))
          val der = authorisedSignature.sign()
          val raw = derToRawRs(der)
          promise.resolve(base64Url(raw))
        } catch (e: Exception) {
          reject(promise, "E_KEYSTORE", "signing failed after authentication: ${e.javaClass.simpleName}")
        }
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        val code = when (errorCode) {
          BiometricPrompt.ERROR_USER_CANCELED,
          BiometricPrompt.ERROR_NEGATIVE_BUTTON,
          BiometricPrompt.ERROR_CANCELED,
          -> "E_BIOMETRIC_CANCELLED"
          BiometricPrompt.ERROR_LOCKOUT,
          BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
          -> "E_BIOMETRIC_LOCKOUT"
          BiometricPrompt.ERROR_NO_BIOMETRICS -> "E_BIOMETRIC_NOT_ENROLLED"
          BiometricPrompt.ERROR_HW_UNAVAILABLE,
          BiometricPrompt.ERROR_HW_NOT_PRESENT,
          BiometricPrompt.ERROR_NO_SPACE,
          -> "E_SECURE_HARDWARE_UNAVAILABLE"
          else -> "E_KEYSTORE"
        }
        // errString is platform text, developer-only per the ground rules —
        // never forwarded as a citizen-facing message.
        reject(promise, code, "onAuthenticationError($errorCode): $errString")
      }

      // Deliberately NOT terminal: one failed attempt (wrong finger, etc.)
      // must let the citizen retry within the same prompt, not fail the call.
      override fun onAuthenticationFailed() = Unit
    }

    activity.runOnUiThread {
      BiometricPrompt(activity, mainExecutor, callback).authenticate(promptInfo, cryptoObject)
    }
  }

  // ── deleteKey ─────────────────────────────────────────────────────────────

  /** Irreversible, and a no-op (not an error) if the alias is already gone. */
  @ReactMethod
  fun deleteKey(alias: String, promise: Promise) {
    try {
      val ks = androidKeyStore()
      if (ks.containsAlias(alias)) {
        ks.deleteEntry(alias)
      }
      promise.resolve(null)
    } catch (e: Exception) {
      reject(promise, "E_KEYSTORE", "deleteKey failed: ${e.javaClass.simpleName}")
    }
  }

  // ── shared helpers ────────────────────────────────────────────────────────

  private fun rawCoordinates(key: ECPublicKey): Pair<ByteArray, ByteArray> {
    val point = key.w
    return bigIntTo32Bytes(point.affineX) to bigIntTo32Bytes(point.affineY)
  }

  /** BigInteger.toByteArray() can be shorter (leading zeros dropped) or one
   * byte longer (a sign byte) than 32 — this normalises to exactly 32,
   * left-padded, matching the broker's fixed-width JWK coordinate contract. */
  private fun bigIntTo32Bytes(value: BigInteger): ByteArray {
    val raw = value.toByteArray()
    val trimmed = if (raw.size > COORD_LENGTH && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
    if (trimmed.size == COORD_LENGTH) return trimmed
    val padded = ByteArray(COORD_LENGTH)
    System.arraycopy(trimmed, 0, padded, COORD_LENGTH - trimmed.size, trimmed.size)
    return padded
  }

  private fun base64Url(bytes: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

  /**
   * DER `SEQUENCE { INTEGER r, INTEGER s }` → raw `r || s`, each left-padded
   * to 32 bytes with DER's sign byte stripped (CONTRACT.md §1.4 — the classic
   * trap: forwarding DER as-is fails verification 100% of the time and looks
   * exactly like a wrong key). Hand-rolled rather than pulling in an ASN.1
   * library for two fixed-shape INTEGERs.
   */
  private fun derToRawRs(der: ByteArray): ByteArray {
    var offset = 0
    require(der[offset] == 0x30.toByte()) { "not a DER SEQUENCE" }
    offset++
    offset += derLengthSize(der, offset) // skip the sequence's own length
    val r = readDerInteger(der, offset)
    offset += r.second
    val s = readDerInteger(der, offset)
    return normaliseToLength(r.first) + normaliseToLength(s.first)
  }

  /** Returns the number of bytes the length field itself occupies, short or long form. */
  private fun derLengthSize(der: ByteArray, offset: Int): Int {
    val first = der[offset].toInt() and 0xFF
    return if (first < 0x80) 1 else 1 + (first and 0x7F)
  }

  private fun derLengthValue(der: ByteArray, offset: Int): Int {
    val first = der[offset].toInt() and 0xFF
    if (first < 0x80) return first
    var length = 0
    for (i in 1..(first and 0x7F)) {
      length = (length shl 8) or (der[offset + i].toInt() and 0xFF)
    }
    return length
  }

  /** Reads one `INTEGER`, returns its value bytes plus the total bytes consumed (tag+len+value). */
  private fun readDerInteger(der: ByteArray, offset: Int): Pair<ByteArray, Int> {
    require(der[offset] == 0x02.toByte()) { "expected DER INTEGER" }
    val lengthSize = derLengthSize(der, offset + 1)
    val length = derLengthValue(der, offset + 1)
    val valueStart = offset + 1 + lengthSize
    val value = der.copyOfRange(valueStart, valueStart + length)
    return value to (1 + lengthSize + length)
  }

  private fun normaliseToLength(value: ByteArray): ByteArray = bigIntTo32Bytes(BigInteger(1, value))
}
