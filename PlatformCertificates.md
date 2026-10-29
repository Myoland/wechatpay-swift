# Platform certificate rotation and public-key verification

Use one `WechatPayPlatformCertificateStore` per merchant. The application owns
channel/merchant scoping and configuration; do not share one store across
unrelated merchant credentials.

The merchant API certificate serial signs outgoing requests. The platform
certificate serial or `PUB_KEY_ID_*` from `Wechatpay-Serial` selects the key that
verifies incoming notifications and API responses. They are different identities.

## Configure trusted material

`WechatPayPlatformCertificate(pem:expectedSerialNumber:)` parses X.509 with Swift
Certificates and exposes `serialNumber`, `notValidBefore`, `notValidAfter`, and
canonical `pem`. Parsing alone does not establish provenance. Use trusted
configuration or the authenticated downloader; never load arbitrary cache PEMs
as trust anchors.

`TrustedWechatPublicKey(id:pem:)` accepts an explicitly configured `PUB_KEY_ID_*`
and SPKI `BEGIN PUBLIC KEY` RSA PEM. PKCS#1 `BEGIN RSA PUBLIC KEY`, private keys, malformed PEM, certificate PEM, and malformed
IDs are rejected. Unknown public-key IDs are rejected without certificate
refresh. Public keys are never learned from a notification or certificate payload.

The store accepts `certificates:`, `refresh:`, `clock:`,
`minimumRefreshInterval:`, and `publicKeys:`. There is no PEM-list persistence hook. The asynchronous
`certificate(for:)` selects the exact normalized certificate serial and checks
its current validity. `verificationKey(for:)` also supports configured platform
public-key IDs. The provider protocol has a default certificate adapter so
existing certificate providers remain source compatible.

The new `WechatPay` initializer retains the original merchant arguments and adds
`certificateProvider:`. A public-key-only client can pass an empty
`wxCertificateContent` when this provider is supplied; it does not need a seed
certificate or a certificate refresh closure. All `WechatPay` constructors and the validator accept a trailing `clock:` closure (default: `Date()`). Use the same clock for the store and client.

## Notification and response validation

Call `verifyNotification(serialNumber:timestamp:nonce:body:signature:)` and pass
the exact single `Wechatpay-Serial` header and original request body. Reject
missing or duplicate signature headers at the HTTP boundary. A failed key lookup
throws; an invalid cryptographic signature returns false. Never continue payment
or refund processing in either case.

The asynchronous verifier rejects non-decimal, non-positive, overflowing, stale, and future timestamps before looking up any key. Its injected clock must differ from the signed epoch seconds by strictly less than 300 seconds: exactly ±300 seconds is rejected, following the official Java response validator. Malformed Base64 signatures are also rejected before lookup. The application remains responsible for nonce/event deduplication and idempotent payment processing; the time window alone does not prevent replay within that window.

Normal SDK API responses require all four signature headers, reject duplicates,
and use the same serial-selecting provider. There is no general validation-disable
argument in the ordinary API request path.

The old synchronous single-PEM `verify` overload is deprecated and remains for source compatibility; it does not check the time window or select by serial. Migrate notifications to the asynchronous API.

Notification resource decryption throws redacted `WechatPayDecryptionError` values for an invalid APIv3 key, malformed/truncated ciphertext, invalid nonce, authentication failure, or non-UTF8 plaintext. It never substitutes an empty plaintext. Verify the notification before decrypting or processing it.

## Refresh and authenticated caching

`WechatPayPlatformCertificateDownloader` is independent of `WechatPay` and the
store, so a store refresh closure can capture it without a reference cycle. It
uses only `https://api.mch.weixin.qq.com/v3/certificates`, verifies TLS, disallows
redirects, bounds the response to 1 MiB, and closes its HTTP client asynchronously.
Its request deadline is 30 seconds. The production endpoint cannot be replaced by
an application-provided URL.

`download()` returns `WechatPayVerifiedPlatformCertificateBundle`, containing
`.certificates` and `.envelope`. It authenticates the APIv3 AES-GCM payload, parses
X.509, checks actual serial/validity against the encrypted response metadata, and
verifies the original response signature. If the response uses a public-key ID,
that key must already be in `trustedPublicKeys:`. The bootstrap exception exists
only in this certificate downloader; an ordinary API response cannot introduce a
new trust anchor.

The Codable `WechatPayPlatformCertificateEnvelope` holds the original encrypted
body and its signature headers. Persist that envelope atomically under the
merchant scope. A trusted seed PEM provisioned by an operator is configuration, not an authenticated cache; parsing a PEM never establishes its provenance. Re-read cached envelopes through `verifyCachedEnvelope` or
`verifyCachedEnvelopeBundle`; corrupt data, a different APIv3 key, altered
metadata, and unknown public-key IDs fail validation. Reject a conflicting
certificate under a previously trusted serial before committing a cache update.

A cached response is authenticated at its signed download timestamp. Its signer
may since have expired while another certificate from that same envelope remains
current. This preserves the still-valid certificate; current notification/API
validation still rejects an expired certificate.

`refresh()` supports startup and periodic refresh. Concurrent unknown-certificate
requests share a refresh, and attempts have a cooldown (60 seconds by default).
A new response does not evict unexpired old certificates merely because it omits
them. Download failure retains valid old material. If a custom refresh closure persists an authenticated envelope before returning certificates, a persistence error rejects that refresh and retains old certificates; this is a deliberate caller policy rather than a built-in plaintext cache. Bound any custom refresh/persistence work; do not return unverified certificates. A
public-key-only configuration need not call the certificate endpoint.

## Compatibility and validation

The manifest uses Swift tools 5.8 and Swift Certificates 1.6.1. The recorded
standalone validation lock uses public dependencies with tools 5.9 requirements;
the executed offline suite used Swift 6.1.3 on Linux x86_64. Minimum-toolchain and
other-platform compilation are separate checks, not implied by this result.

`swift test --filter PlatformCertificateTests` exercises generated A/B RSA keys,
old/new serial coexistence, strict response headers, forgery/unknown IDs,
single-flight and failure handling, encrypted-cache reload, signer expiry,
public-key-only/hybrid modes, and authenticated certificate bootstrap. No merchant
API, real transaction, database, or real merchant key is needed.

## Primary references

- [Official automatic certificate service](https://github.com/wechatpay-apiv3/wechatpay-java/blob/main/core/src/main/java/com/wechat/pay/java/core/certificate/AutoCertificateService.java)
- [Official certificate downloader](https://github.com/wechatpay-apiv3/wechatpay-java/blob/main/core/src/main/java/com/wechat/pay/java/core/certificate/CertificateDownloader.java)
- [Official response timestamp validation](https://github.com/wechatpay-apiv3/wechatpay-java/blob/main/core/src/main/java/com/wechat/pay/java/core/auth/WechatPay2Validator.java)
- [Official public-key configuration](https://github.com/wechatpay-apiv3/wechatpay-java/blob/main/core/src/main/java/com/wechat/pay/java/core/RSAPublicKeyConfig.java)
