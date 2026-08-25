/**
 * Pinned platform trust anchors for attestation chains (spec 05 §4, 06 T2/T3).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PROVENANCE — READ BEFORE PRODUCTION DEPLOYMENT
 * ─────────────────────────────────────────────────────────────────────────────
 * These roots decide whether a certificate chain is Google's/Apple's or an
 * attacker's. They were obtained during development as follows, on 2026-08-25:
 *
 *   - Google: fetched from Google's published endpoint
 *     `https://android.googleapis.com/attestation/root`, then cross-checked
 *     byte-for-byte against the copies embedded in five unrelated open-source
 *     projects (SimpleWebAuthn, py_webauthn, go-webauthn, quarkslab's
 *     android-hardware-attestation-demo, worldcoin's attestation-gateway).
 *   - Apple: Apple's own host was unreachable from the build environment, so
 *     the certificate was taken from five unrelated open-source projects
 *     (node-app-attest, writer/cerebro, pagopa/io-react-native-integrity,
 *     react-native-secure-enclave-operations, ios-app-attest-ruby) that agree
 *     byte-for-byte.
 *
 * Every fetch above traversed a TLS-intercepting egress proxy, so **none of it
 * is end-to-end authenticated to Google or Apple**. Independent agreement
 * across many projects is strong corroboration, not proof.
 *
 * REQUIRED BEFORE PRODUCTION (deployment gate, 06 §8): an operator must verify
 * each SHA-256 fingerprint below out-of-band against the vendor's own
 * publication —
 *   Google: https://developer.android.com/privacy-and-security/security-key-attestation
 *   Apple:  https://www.apple.com/certificateauthority/private/
 * and record the check in the pre-prod security gate. Both verifiers accept a
 * caller-supplied root list which overrides these constants entirely, so a
 * deployment that prefers to inject its own verified pins never has to trust
 * this file.
 *
 * Fingerprints (SHA-256 over the DER):
 *   Google root (RSA-4096, subject serialNumber=f92009e853b6b045, 2022–2042)
 *     ce:db:1c:b6:dc:89:6a:e5:ec:79:73:48:bc:e9:28:67:53:c2:b3:8e:e7:1c:e0:fb:e3:4a:9a:12:48:80:0d:fc
 *   Google "Key Attestation CA1" (ECDSA P-384, 2025–2035)
 *     6d:9d:b4:ce:6c:5c:0b:29:31:66:d0:89:86:e0:57:74:a8:77:6c:eb:52:5d:9e:43:29:52:0d:e1:2b:a4:bc:c0
 *   Apple App Attestation Root CA (ECDSA P-384, 2020–2045)
 *     1c:b9:82:3b:a2:8b:a6:ad:2d:33:a0:06:94:1d:e2:ae:4f:51:3e:f1:d4:e8:31:b9:f7:e0:fa:7b:62:42:c9:32
 *
 * Not covered here: Google also publishes a *revocation* list at
 * `https://android.googleapis.com/attestation/status`, which lists compromised
 * or revoked attestation keys. These verifiers are offline by construction
 * (types.ts) and therefore do NOT consult it; wiring a cached status feed into
 * the broker is tracked as follow-up work and noted in the package README of
 * record. Until then a chain signed by a leaked-but-revoked batch key still
 * verifies.
 */

/**
 * Google hardware attestation roots, mirroring
 * `https://android.googleapis.com/attestation/root` as of 2026-08-25.
 *
 * Two roots are live: the long-standing RSA-4096 root (re-issued in 2022 with
 * the same subject `serialNumber=f92009e853b6b045`; the 2016 issuance expired
 * 2026-05-24) and the newer ECDSA "Key Attestation CA1". Chain verification
 * also accepts a presented root that is *issued by* a pinned root, so a future
 * same-key re-issuance does not break enrolment nationwide.
 */
export const GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM: readonly string[] = [
  `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----`,
];

/**
 * Apple App Attestation Root CA — subject
 * `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`,
 * serial 0b:f3:be:0e:f1:cd:d2:e0:fb:8c:6e:72:1f:62:17:98, valid 2020-03-18 to
 * 2045-03-15. Overridable per deployment via `IosVerifierConfig.rootCertificatesPem`.
 */
export const APPLE_APP_ATTEST_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;
