# privacypass-batched-compat.patch

Wire format compatibility patch for `privacypass` servers that have not yet been upgraded past
commit `35207d3` (the last release to include `BatchedTokenRistretto255`).

Those servers issue `TokenChallenge`s with `token_type = 0xF91A` and expect the corresponding
encoding for requests and responses. Starting from commit `bbcd7a6` ("Rename protocols"),
the library replaced the dedicated `BatchedTokenRistretto255` type with the generic
`AmortizedBatchToken<Ristretto255>`, and removed `0xF91A` from the `TokenType` enum entirely.
This patch restores compatibility without rolling back any other change.

## Part 1 — `src/lib.rs`: restore `BatchedTokenRistretto255 = 0xF91A`

The root cause of all incompatibility. `TokenType` is a `#[repr(u16)]` enum derived with
`TlsSerialize`/`TlsDeserialize`. Any byte stream carrying `0xF91A` — a `TokenChallenge` from
the old server, an incoming `AmortizedBatchTokenRequest`, a stored `Token` — will fail to
deserialize with an unknown-discriminant error unless the variant is present.

Adding the variant is sufficient to unblock parsing. All downstream code that reads
`challenge.token_type()` and threads it through (into `TokenInput`, `TokenRequest`, and
the final `Token`) already does the right thing automatically: no other code hardcodes
`0xF91A`, so the value flows from the challenge to the wire and into the authenticator
scope without further changes.

## Part 2 — `src/amortized_tokens/request.rs`: replace derived TLS with manual `TlsVecU16` impls

The old `BatchedTokenRequest` declared `blinded_elements` as `TlsVecU16<BlindedElement>`,
which serializes as a plain 2-byte big-endian byte count followed by the raw elements.

The new `AmortizedBatchTokenRequest` uses `Vec<BlindedElement<CS>>` with the `TlsDeserialize`/
`TlsSerialize`/`TlsSize` derive macros. Those macros delegate to `tls_codec`'s built-in `Vec<T>`
impl, which uses QUIC variable-length encoding: the top 2 bits of the first length byte encode
the width of the prefix itself (`0x00` = 1 byte, `0x40` = 2 bytes, `0x80` = 4 bytes). For
example, for 1 blinded element (32 bytes):

- `TlsVecU16`:  `00 20` — plain 2-byte big-endian count of bytes
- QUIC VLN:     `20`    — single byte (32 ≤ 63, so top 2 bits are `00`)

These are incompatible at every batch size. The manual impls replace the derive and write/read
a fixed 2-byte big-endian byte count, matching the old server's expected format.

## Part 3 — `src/amortized_tokens/response.rs`: replace `Vec` TLS with manual `TlsVecU16` impls

Same issue as Part 2, on the response side. The old `BatchedTokenResponse` declared
`evaluated_elements` as `TlsVecU16<EvaluatedElement>`. The new code's manual `Serialize` and
`Deserialize` impls called `self.evaluated_elements.tls_serialize(writer)` and
`Vec::<EvaluatedElement<CS>>::tls_deserialize(bytes)`, both of which use QUIC VLN.

The `Size` impl was also wrong: it called `self.evaluated_elements.tls_serialized_len()` which
accounts for the QUIC prefix width (variable), rather than the fixed 2-byte `TlsVecU16` prefix.

The manual impls write and read a 2-byte big-endian byte count, matching the old format.

## Part 4 — `src/amortized_tokens/server.rs`: accept `0xF91A` in token type guards

Two functions in the server guard against mismatched token types:

- `issue_token_response` rejects requests whose `token_type` does not equal `CS::token_type()`.
- `redeem_token` rejects tokens whose `token_type` does not equal `CS::token_type()`.

With `CS = voprf::Ristretto255`, `CS::token_type()` returns `TokenType::PrivateRistretto255 = 5`.
Requests and tokens carrying `0xF91A` would therefore always be rejected at the guard, even
though the underlying cryptography is identical.

The patch widens the check to also accept `BatchedTokenRistretto255` when the cipher suite is
`PrivateRistretto255`, reflecting that the two token types share the same VOPRF construction and
differ only in the wire label.

## Part 5 — `src/generic_tokens/request.rs`: exhaustive match on `TokenType`

`GenericTokenRequest::tls_deserialize` matches on `TokenType` to dispatch to the appropriate
request parser. Rust's exhaustive pattern matching requires every variant to be handled, so
adding `BatchedTokenRistretto255` to the enum without a corresponding arm would be a compile
error. The new arm returns a decoding error, since `0xF91A` is not a valid generic token type.
