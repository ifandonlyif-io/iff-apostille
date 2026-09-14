# Apostille Go hosted client

Use `client.New(Config{BaseURL: apiURL, Issuer: exactIssuer,
TrustedKeyIDs: []string{independentKeyID}})` for an explicit online client.
`TrustedKeyIDs` is optional and copied during construction.

`GetBundle` returns `VerifiedBundle{Bundle, Verification}`; `GetPublicCertificate`
returns its public record with `Verification`. Both reject invalid certificates,
issuer mismatches and configured key-pin mismatches with `APIError.Code ==
"invalid_certificate_response"`. Submit responses use the same issuer/key policy.
Without a key pin, matching issuer certificates return `IssuerTrust: "untrusted"`;
a matching independent pin returns `"accepted_by_policy"`. Freshness is evaluated
at download time. No key directory is automatically trusted, and offline
verification never proves content truth or current revocation status.

See [the integration guide](../../docs/apostille/SDK.md) for signing and login.
