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

## Synchronizing Users from LDAP

Run the command from a trusted administrative shell. Preview the changes for
the `corporate` connection, then apply them after reviewing the results.

```console
php spark shield:ldap-sync corporate
php spark shield:ldap-sync corporate --apply
```

The command uses the connection's service account over verified TLS. The
directory must support LDAP paged results. The search combines `loginFilter`
and `eligibilityFilter` across the configured user search bases. When
`userBaseDn` is omitted, the search uses `baseDn`.

Synchronization uses the same profile mapping and per-connection policies as
sign-in. Enable `provisionUsers` to create accounts for eligible directory
entries and map `username` in `profileAttributes`. Set `updateProfile` to
`false` to apply mappings only when creating an account. The command skips
reserved local accounts and uses the immutable directory identifier for
existing links. Resolve a username collision through a verified account link.
[Linking an Existing Shield User](#linking-an-existing-shield-user)

The command requires a complete directory scan before applying any writes.
Review duplicate identities and username conflicts in the output. Each user's
changes are committed in a separate transaction, and the command reports a
summary. If a run is interrupted, rerun the command from the beginning.
Existing links identify users already processed. Synchronization changes only
users represented in the directory scan.

## Linking an Existing Shield User

During migration, start with provisioning disabled. You can keep LDAP web
sign-in disabled while preparing links from a trusted administrative shell.

### Linking by Username with Spark

Preview candidates for the `corporate` connection. The first command scans
Shield users in batches. The second checks one Shield username. Both print
matching directory identifiers and the status for each account in read-only
mode.

```console
php spark shield:ldap-link corporate
php spark shield:ldap-link corporate alex.rivera
```

The lookup uses the directory attribute configured in
`profileAttributes['username']`. If there is no username mapping, the
connection must have exactly one `loginAttributes` entry. The command uses
the service account over verified TLS, applies `loginFilter` and
`eligibilityFilter`, and checks for a unique match across all configured user
search bases. It skips reserved local accounts and rejects conflicting links.

Verify that the directory account belongs to the person who owns the Shield
account, then apply the link for that username.

```console
php spark shield:ldap-link corporate alex.rivera --apply
```

The command repeats the directory lookup before writing. It stores only the
LDAP identity link, keyed by the connection and the immutable directory
identifier, such as the normalized AD `objectGUID` or an OpenLDAP `entryUUID`.

### Linking Multiple Users

Run the read-only scan and review the proposed matches before applying them
together. Resolve username collisions or ambiguous directory matches first.

```console
php spark shield:ldap-link corporate
php spark shield:ldap-link corporate --all --apply
```

Bulk mode adds missing links. It checks for duplicate local usernames and for
multiple users matching the same LDAP object before any writes. It looks up
each account again before saving its link. It reports individual conflicts and
counts for linked, skipped, and conflicting accounts. Expected skips, such as
an already linked user or a user without an eligible match, allow the run to
continue.

An unexpected directory error stops the run. Each completed link is saved
independently. Run another preview before retrying to see the current results.

### Repairing a Stale Link

Recreating a directory account can give the same username a new immutable
identifier. Preview the affected Shield user to see the `stale_link` status
and the new directory identifier.

```console
php spark shield:ldap-link corporate alex.rivera
```

Verify that the new directory account belongs to this Shield user. Pass the
identifier shown in the preview to repair the link for the selected connection.

```console
php spark shield:ldap-link corporate alex.rivera --apply --replace 00112233-4455-6677-8899-aabbccddeeff
```

The command requires exactly one existing link for the named user on that
connection. It repeats the directory lookup and updates the link only if the
new identifier matches `--replace` and is available. A changed identifier or
an identity conflict blocks the repair.

### Linking from Application Code

For accounts with different usernames, verify the directory account in a
trusted operator workflow and link its immutable identifier to the Shield user
ID.

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

Directory group filters control who may sign in. Manage groups and
permissions with [Shield authorization](https://github.com/codeigniter4/shield/blob/develop/docs/references/authorization.md),
including assignment of any groups your application requires for new users.

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
