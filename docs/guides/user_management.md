# Managing LDAP Users

Shield LDAP links a Shield user to a directory account by the connection
ID and an immutable directory identifier. Use `objectGUID` for Active
Directory or `entryUUID` for OpenLDAP. Keep connection IDs stable. Place
replicas of one directory under the same connection ID and configure
independent directories under separate IDs. A rename or DN change
preserves the existing link when the entry still meets the directory
search and eligibility rules.

## Provisioning Users at Login

Set `'provisionUsers' => true` in a connection's configuration to create
a Shield user after a successful password bind and eligibility check.
Map the local `username` to a single-valued directory attribute that
produces unique, valid Shield usernames of at most 30 characters.

Configure `profileAttributes` as a map from local fields to LDAP
attributes. For example, after adding `directory_email` and `first_name`
as writable fields in your application's user provider, set the following
connection option. [Shield user provider](https://github.com/codeigniter4/shield/blob/develop/docs/customization/user_provider.md)

```php
'profileAttributes' => [
    'username'        => 'sAMAccountName',
    'directory_email' => 'mail',
    'first_name'      => 'givenName',
],
```

Mapped attributes must have at most one value. If a mapped attribute
has no value, the mapping skips that field. Set `'updateProfile' => false`
to apply the mapping only when provisioning. The mapper leaves
unmapped fields and Shield's password and email identities under
application control. Store directory contact information in a dedicated
profile field such as `directory_email`.

LDAP provisioning assigns Shield's configured `AuthGroups.defaultGroup` to new
users, as Shield's `shield:user create` does. Provisioning does not trigger the
web `register` event. A successful LDAP sign-in still triggers Shield's
standard login event.

!!! note

    Shield may require a local activation step. When registration activation is
    configured, an application operator must activate a newly provisioned user
    through the application's trusted workflow. For login actions, use a
    contact identity verified by your application or an action that supports
    directory-only users. [Shield authentication actions](https://github.com/codeigniter4/shield/blob/develop/docs/references/authentication/auth_actions.md)

## Synchronizing Users from LDAP

Use `shield:ldap-sync` from a trusted administrative shell to preview and apply
provisioning and mapped profile updates in bulk.
[Spark Commands](../commands/index.md#synchronize-users)

## Linking an Existing Shield User

During migration, start with provisioning disabled. You can keep LDAP web
sign-in disabled while using `shield:ldap-link` to preview and link accounts by
username from a trusted administrative shell.
[Spark Commands](../commands/index.md#link-existing-users)

### Linking from Application Code

In an application workflow, verify the directory account and select the Shield
user who owns it. Create the link using the verified external identifier and
selected Shield user ID.

```php
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;

$resolver = new LDAPUserResolver(auth()->getProvider());
$resolver->link('corporate', '00112233-4455-6677-8899-aabbccddeeff', 42);
```

This example links a canonical AD GUID to Shield user ID `42`. If you read
the binary `objectGUID` from LDAP, convert it with
`LDAPUserResolver::normalizeObjectGuid()` first. For OpenLDAP, use the
`entryUUID` returned by the directory.

An existing link to another local user prevents the operation. A username
collision also blocks provisioning or profile updates until the conflict is resolved. The
resolver owns its write transaction, so call it outside any active
transaction on the Shield database connection.

## Local, LDAP, and Hybrid Login

- **Local-only** uses Shield's ordinary `Session` authenticator and login
  routes.
- **LDAP-only** uses the LDAP [web login routes](../quick_start_guide/using_ldap_auth.md)
  and leaves `$localAccounts` empty.
- **Hybrid** uses those LDAP routes and reserves explicit local login
  identifiers in **app/Config/AuthLDAP.php**. Each identifier maps to the
  expected Shield user ID.

```php
public array $localAccounts = ['local-operator' => 10];
```

A reserved identifier is matched case-insensitively and checked against the
named local Shield account. Configure a Shield login MFA action for each
reserved operator and confirm they can complete it during an LDAP outage.
The authenticator requires a pending login action for a reserved account
before establishing a session and issues remember-me tokens only for directory
accounts. Every other identifier is checked by the selected LDAP directory.
Rejected directory credentials and outages both deny a new LDAP login.

Revoke pre-migration remember-me tokens for reserved local accounts before
enabling remembered sign-ins.

## Authorization

Directory group filters control who may sign in. Configure connection-level
[`groupMappings`](../getting_started/configuration.md#map-ldap-groups-to-shield-groups)
to grant existing [Shield groups](https://shield.codeigniter.com/latest/references/authorization/)
to eligible users during LDAP password sign-in. The mapping applies to both
provisioned users and existing linked users, including when `updateProfile`
is disabled.

Assignments are additive and persist in Shield. If someone leaves an LDAP
group, remove their corresponding Shield assignment separately to revoke it.
An existing Shield group assignment also survives removal of its LDAP mapping.

## Account Disabling and Password Recovery

Directory eligibility is checked during password login. When disabling an
account in the directory, use your application's established procedures to
revoke its existing Shield sessions, API tokens, and remember-me tokens when
immediate access removal is required.

The authenticator uses the submitted directory password for verification.
Shield stores the directory identity link and the mapped profile fields. A
directory-only user recovers their password through the directory. Scope
Shield's `force-reset` filter to users with a Shield
email/password identity if your Shield version requires that identity for a
reset check. [Shield force-reset compatibility](https://github.com/codeigniter4/shield/pull/1411)

[Remembered sign-ins](../quick_start_guide/using_ldap_auth.md#remembered-sign-ins)
are restored by Shield using the token and local user record, without rebinding
to LDAP or checking the user's current status in the directory. Shield rotates
the token on restoration and revokes the user's remember-me tokens on logout.
To revoke a user's remember-me tokens from an administrator workflow, pass the
user to `auth('session')->getAuthenticator()->forget($user)`.
