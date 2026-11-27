# Configuration Reference

Define LDAP settings in **app/Config/AuthLDAP.php**. Each entry in
`$connections` is an array of options for one directory. The array key becomes
the connection ID. See the [configuration guide](../getting_started/configuration.md)
for complete Active Directory and OpenLDAP examples.

## AuthLDAP

| Property | Default | Description |
| --- | --- | --- |
| `$enabled` | `false` | Enables password sign-in through the LDAP authenticator. |
| `$defaultConnection` | `''` | Selects a connection for login identifiers without a mapped UPN suffix. |
| `$connections` | `[]` | Directory settings keyed by connection ID. Use 1 to 64 ASCII letters, digits, underscores, or hyphens. Start with a letter or digit. |
| `$loginDomains` | `[]` | Maps lowercase UPN suffixes to connection IDs. The full submitted identifier is still used for the directory search. |
| `$localAccounts` | `[]` | Maps reserved login identifiers to Shield user IDs for [hybrid login](../guides/user_management.md#local-ldap-and-hybrid-login). Identifiers are matched case-insensitively. |

The default config builds and validates a connection when `getConnection()`
is called. Use `connectionIds()` to list configured IDs.

## Connection Options

| Option | Default | Description |
| --- | --- | --- |
| `hosts` | Required | Ordered list of 1 to 10 hostnames or IP addresses. Specify IPv6 addresses without brackets. |
| `baseDn` | Required | Base DN of the directory naming context. |
| `bindDn` | Required | DN of the read-only lookup account. |
| `bindPassword` | Required | Nonempty service-account password. Use an [environment override](../getting_started/configuration.md#environment-overrides) or an [application-owned provider](diagnostics.md#custom-connection-providers). |
| `encryption` | `'ldaps'` | Use `'ldaps'` or `'starttls'`. |
| `port` | `null` | Integer from 1 to 65535. With `null`, LDAPS uses 636 and StartTLS uses 389. |
| `connectTimeout` | `5` | Network connection timeout in seconds, from 1 to 60. |
| `searchTimeout` | `5` | LDAP operation and search time limit in seconds, from 1 to 60. |
| `userBaseDn` | `null` | Base DN for user lookups. With `null`, lookups use `baseDn`. |
| `loginFilter` | `'(objectClass=person)'` | Trusted LDAP filter for the initial user lookup. |
| `loginAttributes` | `['uid']` | List of 1 to 10 LDAP attributes accepted as a login identifier. The directory evaluates equality using its schema rules. |
| `externalIdAttribute` | `'entryUUID'` | Immutable, single-valued LDAP attribute used to link the Shield user. Use `objectGUID` for Active Directory. |
| `profileAttributes` | `[]` | Map of writable Shield user fields to single-valued directory attributes. Map `username` when provisioning users. |
| `accountLinks` | `[]` | Map of hyphenated Active Directory GUIDs to existing Shield user IDs. Requires `externalIdAttribute` set to `objectGUID`. A successful directory sign-in can create a verified link with `provisionUsers` disabled. See [Linking Active Directory at Sign-in](../guides/user_management.md#linking-active-directory-at-sign-in). |
| `provisionUsers` | `false` | Creates a Shield user on successful LDAP sign-in when there is no existing link. |
| `eligibilityFilter` | `'(objectClass=*)'` | Additional trusted filter evaluated on the matched entry after password verification. |
| `updateProfile` | `true` | Updates mapped attributes on existing linked users during successful directory checks. When `false`, mappings still apply on provisioning. |

Keep endpoints in a connection within one logical directory and apply equivalent
access policies on every endpoint. The native transport tries endpoints in the
listed order during connection setup. An unavailable endpoint or a timeout can
advance to the next endpoint. Certificate verification failures stop the
operation. After the initial service bind, the user lookup, password
verification, and eligibility check stay on that endpoint. See
[Troubleshooting](../guides/troubleshooting.md) for common connection errors.

## Login and Eligibility Filters

The initial lookup combines `loginFilter` with an OR of escaped equality tests
for every entry in `loginAttributes`. The native transport requires exactly one
entry, verifies the password, and checks the original lookup filter and
`eligibilityFilter` against the same immutable directory identity.

See [Login Eligibility](../guides/login_eligibility.md) for Active Directory
and OpenLDAP examples, including disabled accounts and group membership.

### Building Filters

`LDAPFilter::validate()` checks syntax, a maximum of 16,384 bytes, and up to
32 nested expressions. Use [directory diagnostics](diagnostics.md) to check
server-side schema, matching rules, and attribute access. See
[Building Filters in Application Code](../guides/login_eligibility.md#building-filters-in-application-code)
for examples using runtime values and DN components.
