# Troubleshooting

The browser receives Shield's generic authentication error. For failed
directory sign-ins that reach the transport or resolver, Shield LDAP emits
the debug message `Shield LDAP login rejected ({reason}).` with a short
reason code. Use an appropriately restricted log when troubleshooting.
The [diagnostics API](../references/diagnostics.md) also exposes reason codes
without returning native LDAP diagnostic messages to the browser.

## LDAP Client and TLS

Check the PHP process serving the application for the `ldap` extension
and its OpenLDAP TLS settings. The CLI and web server can load different
PHP configurations.

```console
php --ri ldap
```

- `extension_unavailable` or `unsupported_ldap_client` means the runtime
  needs the PHP LDAP extension and a supported OpenLDAP client.
- For `tls_verification_required`, `tls_failed`, or
  `certificate_verification_failed`, check the CA chain, hostname in the
  certificate's subject alternative name, and client trust settings.
- For `directory_unavailable` or `connection_timeout`, check hostname
  resolution, network access, and the endpoint port. Some runtime TLS
  errors also appear as `directory_unavailable`. Verify trust settings
  before assuming a network failure.

Use the same endpoint, service DN, and client trust settings as the web
runtime. This command prompts for the service password.

```console
ldapsearch -H ldaps://dc01.example.com:636 -x \
  -D 'CN=shield-reader,OU=Service Accounts,DC=example,DC=com' -W \
  -b 'DC=example,DC=com' -s base '(objectClass=*)' dn
```

For StartTLS, use an `ldap://` URI and `-ZZ` to require the TLS upgrade.

```console
ldapsearch -H ldap://ldap.example.org:389 -ZZ -x \
  -D 'cn=shield-reader,ou=services,dc=example,dc=org' -W \
  -b 'dc=example,dc=org' -s base '(objectClass=*)' dn
```

## Service Bind and Directory Search

For `service_bind_failed`, verify the service DN, deployed credential,
and directory policy. For `invalid_bind_secret`, confirm that the
connection defines a nonempty bind password and that the environment
overrides the correct configuration key. [Configuration](../getting_started/configuration.md)

For `search_timeout` or `incomplete_search`, check the user search base,
directory size limits, and whether the search spans naming contexts.
Use a more selective base or filter. The native transport rejects
referrals and incomplete login result sets.

For `user_not_found`, `ambiguous_user`, or `ineligible_user`, preview the
login and eligibility filters with the same service account. Check the
search base, readable login attributes, and rules that determine account
eligibility. An identifier must resolve to exactly one entry.
[Login Eligibility](login_eligibility.md)

## Shield User and Login Action

- `invalid_external_identity` or `invalid_identity` indicates a missing,
  multi-valued, or malformed identifier on the matched entry. Confirm that
  the configured attribute is readable and single-valued. For Active
  Directory, the expected `objectGUID` is a 16-byte value.
- `user_not_provisioned` means the entry has no Shield identity link and
  provisioning is off. Follow the [account linking procedure](user_management.md#linking-an-existing-shield-user).
- For `identity_conflict`, `invalid_profile`, or
  `synchronization_conflict`, check for a username collision, multi-valued
  attributes, and profile fields permitted by the user provider. The
  user model and identity model must share the same Shield database
  connection.
- If directory credentials pass, also check the local Shield user for a
  ban or pending activation. If sign-in reaches a login action, verify
  that its routes and the required user contact identity are configured.
  [Shield web login](../quick_start_guide/using_ldap_auth.md)
