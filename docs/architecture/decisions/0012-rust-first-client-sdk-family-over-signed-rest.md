# ADR-0012: Rust-first client SDK family over the signed REST contract

- Status: Accepted
- Date: 2026-08-29
- Deciders: Project owner
- Complements: [ADR-0003](0003-direct-signed-service-rest.md), [ADR-0007](0007-expose-no-sql-command-surface.md), [ADR-0011](0011-move-scheduling-policy-outside-the-kernel.md)
- Related: ILK-001, ILK-002, ILK-013

## Context

[ADR-0003](0003-direct-signed-service-rest.md) already settled the kernel's
wire protocol: direct, signed HTTPS REST using the Ed25519/RFC 9421 HTTP
Message Signatures profile with JSON bodies. This ADR does not reopen that
choice. What it decides is how callers in languages other than Rust are meant
to reach that protocol, now that more than one client (`infernal-taskmaster-simple`,
and future workers in other languages) needs to.

The tempting shortcut is to compile the kernel's Rust code into a shared
library and let other languages link it in-process through a C ABI. That
would be a mistake for this project specifically: [ILK-013](../minimum-viable-kernel.md#ilk-013-mediation)
requires that identity, replay, admission, schema approval, authority,
validation, idempotency, versioning, audit, and event rules all be enforced
*at the mediation boundary*, uniformly, for every caller. A caller that links
kernel internals in-process is no longer going through that boundary — it is
inside it, free to skip, patch, or fork whatever checks the linked code
happens to perform. The kernel must stay a service you call, never a library
you embed.

## Decision

The kernel exposes exactly one public contract: the signed REST/JSON protocol
from ADR-0003. Every language reaches the kernel exclusively over that
authenticated network boundary. No language links kernel code in-process, and
no client library is permitted to shortcut, mock, or bypass the network call
it exists to make.

```text
                 Infernal Law Kernel
                        Rust
                         |
                  signed REST (ADR-0003)
                         |
        +----------------+----------------+
        v                v                v
    Rust SDK         Python SDK       Java SDK
  (client-rs)        (client-py)    (client-java)
                                          |
                                     JS/TS SDK
                                    (client-js)
```

### Rust is the reference client

`infernal-client-rs` is the native Rust crate and the reference
implementation: typed requests, Ed25519 signing and RFC 9421 signature-base
construction, nonce/idempotency handling, retries, and schema validation.
Every other language's SDK is checked for wire-level compatibility against
this crate, not against each other.

### Portable SDKs implement the same wire contract natively

`infernal-client-py`, `infernal-client-java`, and `infernal-client-js`
implement the identical signed-REST contract using each language's own
tooling (for example Python's `cryptography` package, the JVM's `java.security`
Ed25519 support added in JDK 15+, or Node's built-in `crypto` module for
Ed25519). This ADR does not mandate one FFI strategy for every language:

- Python MAY bind `infernal-client-rs` directly with PyO3 instead of
  reimplementing signing in pure Python, since PyO3 produces a native
  extension module without going through a hand-rolled C ABI.
- Java MAY link `infernal-client-rs` through a small JNI shim instead of a
  pure-Java implementation.
- JavaScript, if it links native code at all, uses a Node N-API addon, not a
  raw `.so`/`.dll` load — Node cannot use `ctypes`-style dynamic loading the
  way Python or a JVM's JNA can.

Whichever strategy a given SDK repository chooses is that repository's
decision to make and document; the only fixed rule is that it terminates in a
real signed HTTPS call to the kernel, never a shortcut into kernel internals
or a mocked transport shipped as if it were real.

### The C ABI wraps the client crate, not the kernel

`infernal-client-c` is optional and narrow. It exists for callers that
genuinely need in-process native integration and cannot conveniently make
their own signed HTTPS calls — a legacy C/C++ engineering application, a
plugin host, NX/CATIA-style native integration, or an embedded/native worker.
It wraps `infernal-client-rs`; it does not talk to kernel internals and does
not reimplement signing:

```text
Good:                                  Avoid:
Python/C++                             Python/C++
    |                                      |
    v                                      v
C ABI / Rust client crate               C ABI
    |                                      |
    v                                      v
authenticated request                direct calls into
    |                                  kernel internals
    v
Kernel service
```

The ABI itself must stay boring. Only these cross the boundary: integers,
byte buffers with explicit lengths, UTF-8 strings, opaque pointers, and
simple integer status/error codes. No Rust-native type — no `Result`, no
enum, no struct layout, no lifetime — is ever exposed across `extern "C"`.
For example:

```rust
// Not this: Request/Response/Error have no stable C ABI.
pub extern "C" fn submit(req: Request) -> Result<Response, Error>;

// This: only boring, stable-layout types cross the boundary.
pub extern "C" fn infernal_submit(
    client: *mut InfernalClient,
    request_json: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
) -> i32;
```

The foreign caller sees `InfernalClient` only as an opaque pointer; the Rust
client crate owns all parsing, validation, signing, and transport behind it.
A caller that goes through `infernal-client-c` is therefore indistinguishable,
from the kernel's point of view, from any other signed REST caller.

### Repository layout

```text
infernal-law            Rust kernel service (this repository)
infernal-client-rs      native Rust client crate; reference implementation
infernal-client-c       optional extern "C" ABI wrapper over infernal-client-rs
infernal-client-py      Python SDK
infernal-client-java    Java SDK
infernal-client-js      Node/TypeScript SDK
```

Client repositories depend on the kernel's published protocol (signed-REST
message profile, request/response JSON shapes, and the OpenAPI/schema
documents that describe them once those exist), never on kernel source. None
of them may vendor or embed kernel code.

## Consequences

### Positive

- The mediation boundary in ILK-013 applies uniformly to every language;
  no caller gets an in-process shortcut around identity, replay, admission,
  authority, or audit checks.
- Rust callers (including `infernal-taskmaster-simple` and future Rust
  workers) get a first-class, ergonomic, typed client with no FFI overhead.
- `infernal-client-c` is a well-scoped, separately reviewable project that
  demonstrates FFI, ABI stability, and cross-language ownership/lifetime
  handling without putting any of that complexity in the kernel.
- Each portable SDK can choose the binding strategy that fits its ecosystem
  (native reimplementation, PyO3, JNI, N-API) without the kernel caring.

### Negative

- Signing logic (Ed25519 + RFC 9421 signature-base construction) must be
  correctly reimplemented, or correctly FFI-bound, in every language that
  gets a portable SDK. That is real, repeated work with real room for
  subtle divergence from the Rust reference.
- Five additional repositories means five more places to version, test, and
  keep compatible with the kernel's wire contract as it evolves.
- Until the kernel publishes a stable schema document (OpenAPI or equivalent),
  every SDK is hand-written against ADR-0003's fixed profile and the kernel's
  own contract tests, with no generated-client shortcut.

## Validation

The decision is working when: no client repository imports or vendors kernel
source; `infernal-client-rs`, `infernal-client-py`, `infernal-client-java`,
and `infernal-client-js` each produce a request the kernel accepts as a
correctly signed, ordinary REST call indistinguishable from any other
caller's; `infernal-client-c` exposes no Rust-native type across its
`extern "C"` boundary; and removing the C ABI or any one portable SDK never
requires a kernel change, because none of them is anything other than an
ordinary authenticated network caller.
