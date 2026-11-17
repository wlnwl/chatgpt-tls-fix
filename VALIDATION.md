# 1.2 validation

Validated on 2026-11-17 with Android 16 / ARM64, LSPosed, and ChatGPT 1.2026.307 (2630718).

- Version 1.2 / code 3 was built, verified with the existing signing identity, and installed in place.
- APK SHA-256: `a1a37552c4d0933bda119feb73b434acba39a4005344cf9aaae4302a5edc5fa3`.
- 49 host behavior tests passed: 24 existing verification/logging cases and 25 transport classification/state-scope cases. All 90 captured sink records parsed as JSON.
- Eight assertions passed inside the actual injected process. Conscrypt failure and replacement records shared an invocation ID. The device Cronet branch remained original-exception preservation, not proof of a successful Cronet bypass.
- The final automated live start passed with the exact-version transport guard registered, separate live/self-test sessions, a periodic summary, the ChatGPT composer visible, and no certificate error screen.
- The original Android API certificate validation succeeded. The automatic recovery check additionally found an HTTP 200 from android.chat.openai.com after that live process started.
- Evidence parser checks rejected empty/incomplete/misclassified certificate traces and stale/foreign/403/malformed HTTP evidence. HTTP artifacts contain timestamp, host and status only; UI text is not persisted by the test script.

The initial proxy route produced interrupted TLS handshakes. An existing alternate route became usable after the VPN was reloaded. Independent TLS verification and application HTTP responses then succeeded. The profile contents were restored after diagnosis; the selected ChatGPT route is the persistent network change.

Static analysis also confirmed that this client maps any SSLHandshakeException into a global certificate-error state. The new guard prevents that state write only for positively classified transport-only errors, with exact version, reflection shape, state identity and invocation scope checks. Host tests cover preservation of certificate/pinning/hostname failures, nested scopes, thread isolation, cycles, oversized error graphs and unsupported evidence.

The final live sample did **not** contain transport_error_state_suppressed or live verification_failed/verification_bypassed. Therefore it proves working startup/API connectivity and runtime guard registration, but not that a real live failure was suppressed in that sample. No chat message was sent; generated replies and sustained long-term reliability were not tested.

Local evidence is retained under `build/device-test-<UTC timestamp>/` and is excluded from publication.

## Prior 1.1 validation

Validated on 2026-11-17 with Android 16 / ARM64, LSPosed, and ChatGPT 1.2026.307.

## Results

- APK built with Android SDK 35, signed with the existing module certificate, signature verified, and updated in place as versionName 1.1 / versionCode 2.
- 24 host behavior cases passed. All 90 captured sink records parsed as JSON, including bounded certificate metadata.
- 8 assertions passed inside the actual injected Android process using a public self-signed fixture and no network requests or CA installation.
- Five evidence-validation checks passed: the actual trace was accepted, while empty, missing-Cronet, missing-bypass and live-only traces were rejected.
- A separate 35-second live cold start contained versioned load, all three hook registrations, a periodic summary and no self-test records.
- No private key or test logs are included in source control or the APK. The fixture's public certificate is deliberately included.

## What the device test established

The original system Conscrypt verifier rejected the fixture with CertificateException / CertPathValidatorException (trust anchor missing). The hooked call then emitted verification_failed and verification_bypassed with the same invocation_id and certificate SHA-256. An out-of-scope hostname retained its original failure; an explicitly trusted in-memory chain retained success.

The shipped Cronet Java verifier exposed a five-argument signature and threw NullPointerException from its certificate parser when called directly. Its device test therefore verified that the exception was logged and preserved, and explicitly reported original_verifier_throws. **This is not evidence of a successful Cronet bypass on this device.** The nonzero-status bypass branch is covered by the host callback tests.

The handshake observer was exercised without changing the exception. Its events describe construction, not proof that a request failed or that an exception was thrown.

## Live network result

The final live sample contained 24 handshake_exception records classified as handshake_terminated, no live verification_failed or verification_bypassed events, and the same network configuration error screen. This confirms observability of the handshake symptom; it does not establish a failed server certificate or repair the independently observed proxy-route failure.

## Repeatability

Run test.ps1 for host tests. Build with build.ps1 and the original signing key for an in-place update. Run test-device.py with an explicitly selected authorized rooted device; it saves the previous module APK, requests the one-shot test, removes the marker, restarts the app again, and checks separate session identities and backend-specific evidence.

Local runtime evidence is intentionally excluded from git under build/host-tests and build/device-test-<UTC timestamp>. The test-device report states which Cronet capability branch ran. A green self-test means the tested logging and preservation behavior passed, not that ChatGPT connectivity recovered.
