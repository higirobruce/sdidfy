import { Injectable } from '@nestjs/common';
import { webcrypto } from 'node:crypto';
import { BridgeError } from '@sdid/shared';
import { MetricsService, type SignatureContext } from '../observability/metrics.service.js';

/**
 * Verifies device signatures — the heart of the trust chain (01 §2.2).
 * Devices sign the UTF-8 bytes of a challenge payload with their
 * hardware-backed EC P-256 key; signatures arrive base64url-encoded in
 * WebCrypto raw (r||s) form.
 */
@Injectable()
export class SignatureService {
  constructor(private readonly metrics: MetricsService) {}

  /**
   * `context` names the flow doing the verifying (activation / login / CIBA
   * decision) so a failure spike can be attributed to one leg of the trust
   * chain. It is a bounded enum, never the binding id — per-binding bursts are
   * the anomaly detector's job (06 §5), not a metric label.
   */
  async verifyDeviceSignature(
    devicePublicKeyJwk: { kty: string; crv: string; x: string; y: string },
    payload: string,
    signatureB64url: string,
    context: SignatureContext = 'unspecified',
  ): Promise<void> {
    if (devicePublicKeyJwk.kty !== 'EC' || devicePublicKeyJwk.crv !== 'P-256') {
      this.metrics.recordSignatureFailure(context);
      throw new BridgeError('signature_invalid', 'Unsupported device key type', 400);
    }
    let ok = false;
    try {
      const key = await webcrypto.subtle.importKey(
        'jwk',
        devicePublicKeyJwk as unknown as import('node:crypto').webcrypto.JsonWebKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      const signature = Buffer.from(signatureB64url, 'base64url');
      ok = await webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        signature,
        Buffer.from(payload, 'utf8'),
      );
    } catch {
      ok = false;
    }
    if (!ok) {
      this.metrics.recordSignatureFailure(context);
      throw new BridgeError('signature_invalid', 'Device signature verification failed', 401);
    }
  }
}
