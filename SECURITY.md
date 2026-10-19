# Security policy

Hourglass must never publish a segment whose proof does not verify, never let a record claim
more sequential work than its checks guarantee, and never let two different roots of the same
segment go unnoticed. A way to make the verifier accept an invalid chain or less work than
claimed, or to make the prover publish a second branch of the same genesis, is a vulnerability.
Please report it privately by e-mail to **kontakt@advena-partners.com** (English, German or
Polish), as listed in <https://sigelith.org/.well-known/security.txt>, and do not open a public
issue for it.

Only the latest version on `main` is supported.
