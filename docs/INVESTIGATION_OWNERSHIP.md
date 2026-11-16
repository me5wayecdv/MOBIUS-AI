# Investigation ownership boundary

Every investigation read and mutation endpoint now checks the investigation's
`created_by` identity against the request identity. Investigation listing is filtered
by the same owner. A foreign investigation is returned as the same 404 as an unknown ID,
so the API does not disclose whether another analyst's identifier exists.

This is an authorization boundary only when the request identity is trustworthy. The
current `X-Analyst-Id` identity provider is explicitly a development/test stub and is
trivially spoofable; production startup is blocked until real authentication is deployed.
Do not expose this header-based mode to an untrusted network.
