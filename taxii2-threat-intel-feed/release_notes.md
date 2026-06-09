#### The following enhancements have been made to the TAXII Threat Intel Feed Connector in version 2.0.0:

- Added an `Authentication Type` configuration picklist with the following options:
    - `Basic` (existing behavior — username + password)
    - `Bearer Token` (sent as `Authorization: Bearer <token>` on every request)
    - `API Key Header` (configurable header name, e.g. `X-API-Key`, with a masked password-typed value)
    - `None` (unauthenticated)
- The `Headers` configuration field has been renamed to `Custom Headers`.
- Connection-level custom headers are now automatically merged into every outgoing TAXII request (previously they were
  only applied when supplied per-action).
- Per-action `Headers` overrides now augment the default TAXII content-negotiation headers (`Content-Type`, `Accept`)
  instead of replacing them, preventing accidental breakage of TAXII v2.1 content negotiation when a user supplies an
  unrelated custom header.