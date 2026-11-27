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

!!! note

    Shield may require a local activation step. When registration activation is
    configured, an application operator must activate a newly provisioned user
    through the application's trusted workflow. For login actions, use a
    contact identity verified by your application or an action that supports
    directory-only users. [Shield authentication actions](https://github.com/codeigniter4/shield/blob/develop/docs/references/authentication/auth_actions.md)

## Linking an Existing Shield User

### Linking Active Directory at Sign-in

Use `accountLinks` to associate an Active Directory account with an existing
Shield user. Obtain the `objectGUID` from the directory configured for the
connection. This example reads it from a known user object with the
ActiveDirectory PowerShell module. [Get-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)

```powershell
(Get-ADUser -Identity 'CN=Alex Rivera,OU=Users,DC=example,DC=com' -Server 'dc01.example.com' -Properties objectGUID).ObjectGUID.ToString()
```

Verify that the directory account belongs to the person who owns the existing
Shield account. For a migration from another LDAP directory, use the Shield
user ID already associated with that person's previous LDAP account. Add the
verified GUID and Shield user ID to the new Active Directory connection in
**app/Config/AuthLDAP.php**.

```php
'externalIdAttribute' => 'objectGUID',
'accountLinks'        => [
    '00112233-4455-6677-8899-aabbccddeeff' => 42,
],
'provisionUsers'      => false,
```

Use GUIDs in hyphenated form. Hexadecimal letters can be uppercase or
lowercase. After the directory verifies the user's password and eligibility,
Shield LDAP stores the link to user `42`. The map uses the verified GUID as
its lookup key, so the AD username can differ from the existing Shield username.
Set `provisionUsers` to `false` during the migration to restrict LDAP sign-ins
to accounts with existing links or verified mappings.

The stored link is used on later sign-ins, including after you remove its map
entry. A map entry targeting a different Shield user than the stored link
blocks sign-in. Profile updates continue to follow `updateProfile`, including
uniqueness checks on mapped usernames.

### Linking from Application Code

In a trusted operator workflow, verify the directory account and select the
Shield user who owns it. Create the link using the verified external identifier
and selected Shield user ID.

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
before establishing a session. Every other identifier is checked by the
selected LDAP directory. Rejected directory credentials and outages both
deny a new LDAP login.

## Authorization

Directory group filters control who may sign in. Manage groups and
permissions with [Shield authorization](https://github.com/codeigniter4/shield/blob/develop/docs/references/authorization.md),
including assignment of any groups your application requires for new users.

## Account Disabling and Password Recovery

Directory eligibility is checked during password login. When disabling an
account in the directory, use your application's established procedures to
revoke its existing Shield sessions and API tokens when immediate access
removal is required.

The authenticator uses the submitted directory password for verification.
Shield stores the directory identity link and the mapped profile fields. A
directory-only user recovers their password through the directory. Scope
Shield's `force-reset` filter to users with a Shield
email/password identity if your Shield version requires that identity for a
reset check. [Shield force-reset compatibility](https://github.com/codeigniter4/shield/pull/1411)

For an LDAP-only application, review existing remember-me cookies and
alternative login paths during migration. The LDAP authenticator issues no
remember-me token. Keep Shield's `allowRemembering` disabled and revoke
pre-migration tokens according to your application's policies.
