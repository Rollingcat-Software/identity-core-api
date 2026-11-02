# Pinned Google hardware attestation roots

`google-hardware-attestation-roots.pem` holds the Google root certificates that
Android Key Attestation chains must terminate at (see
`docs/ATTESTED_PUZZLE_BINDING.md`). The verifier pins the **SubjectPublicKeyInfo**
of these certificates, so a re-issued root certificate over the same key (Google
has re-issued the RSA root in 2016, 2019 and 2022) is accepted.

| # | Subject | Key | SHA-256 (cert) |
|---|---------|-----|----------------|
| 1 | `serialNumber=f92009e853b6b045` (2022-03-20 .. 2042-03-15) | RSA-4096 | `CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC` |
| 2 | `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` (2025-07-17 .. 2035-07-15) | ECDSA P-384 | `6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0` |

Source: `roots.json` of https://github.com/android/keyattestation (Apache-2.0),
commit `0e3ac2fdd54799d779e1979a96fbcba0361b2089` (2026-10-30). Google also
publishes the roots at
https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate.

When Google announces a new root, append it here (and to the test fixtures), ship,
and only then start accepting devices provisioned under it.
