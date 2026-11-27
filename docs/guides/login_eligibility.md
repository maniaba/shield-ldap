# Login Eligibility

Configure the filters for each directory in
**app/Config/AuthLDAP.php**. See [Configuration](../getting_started/configuration.md)
for complete Active Directory and OpenLDAP examples.

## Login and Eligibility Filters

- `loginFilter` narrows the initial search for a directory entry. The
  authenticator combines this filter with equality checks for the submitted
  identifier across the configured `loginAttributes`. It requires exactly
  one matching entry. Case matching follows the directory's equality rule.
- `eligibilityFilter` adds an access check after the user bind succeeds. The
  native transport applies both filters to the matched entry and verifies
  its immutable identity again before resolving the Shield user.

Apply rules that define the directory's population to `loginFilter`. Add
application-specific access rules, such as required group membership, to
`eligibilityFilter`. A directory match must still pass Shield's local account
checks and any configured login action.

## Active Directory

Use this `eligibilityFilter` to exclude disabled accounts and require
transitive membership in the `Shield Users` security group. Replace the
group DN with the one used in your directory.

```ldap
(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=CN=Shield Users,OU=Groups,DC=example,DC=com))
```

The bitwise matching rule `1.2.840.113556.1.4.803` tests the disabled bit in
`userAccountControl`. The transitive matching rule `1.2.840.113556.1.4.1941`
follows directory links. Verify that the directory links connect eligible
users to the configured group. AD stores primary group membership separately, so
test it explicitly if an access rule depends on it.
[Active Directory search filter syntax](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)

## OpenLDAP

For OpenLDAP with a `memberOf` overlay, the following `eligibilityFilter`
requires direct membership in `shield-users`. Nested membership depends on
the installed directory schema and overlays.

```ldap
(memberOf=cn=shield-users,ou=groups,dc=example,dc=org)
```

## Building Filters in Application Code

Use trusted configuration for LDAP filter expressions. In application
code, use `LDAPFilter::equal()` for runtime assertion values. It escapes
wildcards and other special bytes according to
[RFC 4515](https://www.rfc-editor.org/rfc/rfc4515). Use `all()`, `any()`,
and `not()` to combine complete filters. Keep attribute names and raw filter
expressions under application control.

```php
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPFilter;

$identifier = 'alice@example.com';

$filter = LDAPFilter::all(
    '(objectClass=inetOrgPerson)',
    LDAPFilter::any(
        LDAPFilter::equal('uid', $identifier),
        LDAPFilter::equal('mail', $identifier),
    ),
);
```

If you construct a DN from a runtime naming value, encode the naming
component with `LDAPFilter::escapeDnComponent()`. Pass the completed DN
to `equal()` to apply filter assertion escaping as well.
[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514)

```php
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPFilter;

$groupName = 'Family, Given';
$groupDn   = 'CN=' . LDAPFilter::escapeDnComponent($groupName)
    . ',OU=Groups,DC=example,DC=com';

$filter = LDAPFilter::equal('memberOf', $groupDn);
```

`LDAPFilter::validate()` checks filter syntax. To verify server-side
schema, matching rules, and access, run a bounded directory search.
[Administrative Diagnostics](../references/diagnostics.md)
