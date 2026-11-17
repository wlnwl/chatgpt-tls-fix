# Host callback regression tests

Run from PowerShell with an existing JDK:

```powershell
.\test.ps1 -JdkRoot $env:JAVA_HOME -FixturePath '.\assets\selftest-cert.der'
```

Omit `-FixturePath` to generate an ephemeral self-signed certificate under `build/host-tests`. The script never installs a certificate, starts a network request, or touches an Android device. Outputs and any ephemeral fixture private key remain in the ignored build directory.

The suite compiles the actual `TlsHook` and `DiagnosticLog` sources against small host-only Xposed and Android logging doubles. It captures callbacks registered by the production entry point, seeds each callback with an original result or exception, and asserts both observable diagnostic events and preserved/changed result identity. The production `DiagnosticSelfTest` and `TransportErrorGuard` Android installation adapters are replaced with test doubles; the device test checks their runtime installation separately.

The 24 cases cover:

- Package and hostname scope, including deceptive suffixes.
- Original certificate failure logged before a compatibility replacement.
- Accepted certificate results remaining identical.
- Out-of-scope errors, empty chains, and unexpected exceptions preserved.
- Cronet status failures, direct throws, null results, malformed DER and missing reflection APIs.
- Later failures remaining visible after more than 30 successful verifications.
- Raw exception credential text excluded from logs.
- Either/both logging sinks failing without changing verification behavior.
- Controlled-test counters isolated from real-request counters, including the original-baseline gate.
- Handshake exception constructor observation remaining read-only.

PowerShell additionally parses every captured record as JSON and checks required fields and SHA-256/subject/issuer metadata on a failed certificate. Captured events are written to `build/host-tests/events.jsonl`. The two logging sinks intentionally produce duplicate session/sequence records.

Another 25 cases exercise the actual `TransportFailureClassifier` and `TransportErrorScope`: certificate and security errors take precedence over transport evidence, exception graph inspection is bounded, state objects must match by identity, and nested calls and separate threads cannot inherit an unrelated suppression scope. This brings the host total to 49 cases.

These tests validate hook callback behavior and logging invariants. They do not establish real Android hook installation, application connectivity, or successful TLS communication. Use `test-device.py` for the separately labeled controlled on-device verification and live startup observation.
