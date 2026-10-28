# Offline test material

All keys and certificates in this directory were generated for these tests. They
are published test data, not merchant credentials or trusted production material.
The SDK never runs OpenSSL or parses ASN.1 itself: its certificate parser is
Swift Certificates and its RSA parser/verifier is JWTKit.

- `platform-a`: RSA test key, certificate serial A1, one-day validity.
- `platform-b`: a different RSA test key, certificate serial B2, ten-year validity.
- `platform-conflict`: B's public key under serial A1, to test serial conflicts.
- `*.public.pem`: public-key-mode fixtures exported from those same test keys.

Tests inject a clock within A's validity; they do not depend on the current date.
The shorter A validity tests cache reload after the original download signer has
expired while B remains usable. No test talks to a merchant API or database.
