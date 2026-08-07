#### The following enhancements have been made to the TAXII Threat Intel Feed Connector in version 2.0.0:

- Added an `Authentication Type` field to `Configuration Parameters` with the following options:
    - `Basic` (existing behavior): Authenticates using a username/API key and password/API password.
    - `Bearer Token`: Sends the bearer token in the Authorization: Bearer <token> header on every request.
    - `API Key Header`: Sends an API key in a configurable HTTP header (for example, X-API-Key or X-Auth-Token). The API
      key value is stored as a masked password-type field.
    - `None`: Connects to the TAXII server without authentication.
- Renamed the `Headers` field to `Custom Headers` in `Configuration Parameters` for improved clarity.
- Connection-level `Custom Headers` are now automatically included in every outgoing TAXII request. Previously, these
  headers were applied only when specified on individual actions.
- Per-action `Headers` now augment the default TAXII content negotiation
  headers (Content-Type and Accept) instead of replacing them. This prevents
  users from unintentionally breaking TAXII v2.1 content negotiation when
  specifying additional, unrelated custom headers.