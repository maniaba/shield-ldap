# Directory Diagnostics

Use the `ldapDirectory` service from an administrative command or another
trusted application workflow. It exposes connectivity, service-account bind,
bounded search, and directory credential checks.

!!! important

    Apply authorization, CSRF protection, and rate limiting to any web interface
    that calls these methods. Limit operators to approved connection IDs,
    search bases, and attributes. Keep results, submitted passwords, and
    native directory error details out of application logs.

## Check a Connection

```php
use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/** @var AuthLDAP $config */
$config = config('AuthLDAP');

$connectionIds = $config->connectionIds();
$directory     = service('ldapDirectory');

try {
    $connection = $config->getConnection('corporate');
    $directory->testConnection($connection);
    $directory->testBind($connection);
} catch (LDAPException $exception) {
    log_message('warning', 'LDAP connection check failed ({reason}).', ['reason' => $exception->reason]);
}
```

`testConnection()` checks connectivity with TLS verification. For LDAPS, the
native transport uses an anonymous Root DSE query to trigger the handshake.
`testBind()` establishes a connection and verifies the service-account
credentials. Both return after success and throw `LDAPException` on failure.
The exception's `reason` property contains a diagnostic code suitable for
operator logs. See [Troubleshooting](../guides/troubleshooting.md) for how to
interpret connection and sign-in failures.

## Preview Directory Entries

The following example requests display names from a configured Active
Directory user search. `preview()` accepts one trusted base DN per call. To
compare multiple bases, make a separate call for each one. Use a trusted group
search base and group filter with the same method to inspect group entries.

```php
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPFilter;

$entries = $directory->preview(
    $connection,
    'OU=Employees,DC=example,DC=com',
    LDAPFilter::all($connection->loginFilter, $connection->eligibilityFilter),
    ['sAMAccountName', 'displayName'],
    20,
);
```

The native transport accepts a limit from 1 to 100 and up to 64 attribute
names. Pass an empty attribute list for DNs alone. Each result has a `dn`
and an `attributes` map with lowercase attribute names and lists of values.
Values such as `objectGUID` may be binary.

A full page of results can indicate that the limit was reached. Use the method
only to sample entries. Search referrals and unexpected partial results raise
an `LDAPException`.

## Check a User's Directory Credentials

Use the directory service to check a password and eligibility without creating
a Shield session or updating a Shield account. The application supplies the
trusted connection and a login identifier and password from the operator's
request.

```php
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPFilter;
use Maniaba\ShieldLDAP\Authentication\LDAP\MultiBaseLDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;

$baseDn  = $connection->userBaseDn ?? $connection->baseDn;
$matches = [];

if (is_array($baseDn) && ! $directory instanceof MultiBaseLDAPDirectoryInterface) {
    throw new LDAPException('invalid_configuration');
}

foreach ($connection->loginAttributes as $attribute) {
    $matches[] = LDAPFilter::equal($attribute, $identifier);
}

$entry = $directory->authenticate(
    $connection,
    $baseDn,
    LDAPFilter::all($connection->loginFilter, LDAPFilter::any(...$matches)),
    [],
    $password,
    $connection->eligibilityFilter,
);
```

The native implementation returns the verified entry and includes the
configured immutable ID attribute in the result. It throws `LDAPException`
if it cannot verify a single eligible user. Discard the password after the
operation and show the operator only the information needed for diagnosis.

!!! note

    `auth('ldap')->check()` resolves a Shield user and may provision the user,
    update their profile, or reconcile mapped groups. For application sign-in, use
    `auth('ldap')->attempt()` and
    complete the configured Shield login actions. See the
    [LDAP login quick start](../quick_start_guide/using_ldap_auth.md).

## Custom Connection Providers

Extend the package's `AuthLDAP` config in **app/Config/AuthLDAP.php** and
override `getConnection(string $id): LDAPConnection` and
`connectionIds(): array` to load settings from your application.
In `getConnection()`, resolve the requested ID and read the service password
from the application's secret store. Pass the password as a string to
`LDAPConnection` with the same ID that was requested. Use
`LDAPException('invalid_configuration')` for unrecognized IDs.

This allows the application to keep the password outside CodeIgniter's config
cache. Return only connection IDs or approved operational metadata to an
administrator interface.

## Replacing the Transport

CodeIgniter discovers the package's `ldapDirectory` service automatically.
To provide a different directory transport, implement
`Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface` and declare
a `ldapDirectory()` service in **app/Config/Services.php**. Follow the
[CodeIgniter Services guide](https://codeigniter.com/user_guide/concepts/services.html).

For configurations that use a list of search bases for sign-in, implement
`Maniaba\ShieldLDAP\Authentication\LDAP\MultiBaseLDAPDirectoryInterface`.
Its `authenticate()` method accepts a string or a list of base DNs and must
confirm a single matching entry across all supplied bases before verifying the
password. `LDAPDirectoryInterface` continues to support transports that use
a single string base DN. Both interfaces keep `preview()` limited to one base
per call.

An implementation used for sign-in must verify the submitted password over
a trusted encrypted connection, require one matching user, and recheck the
same immutable identity against the eligibility filter. Return the entry DN
and the requested attribute values using lowercase keys and lists of strings.
For a connection with `groupMappings`, return a `matchedGroups` list of the
Shield group keys whose LDAP membership you verified for that same user.
Return an empty list when no configured group matches.
Throw `LDAPException` with a reason code instead of passing native exceptions
or credentials to the application.

To support [group-only synchronization](../commands/index.md#synchronize-only-groups),
implement `LDAPGroupEnumerationInterface`. Return eligible entries with their
immutable IDs and a `matchedGroups` list, including entries with zero matches.
Report incomplete enumeration or membership checks with `LDAPException`.

For `shield:ldap-link`, provide
`Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserLookupInterface`. The
package's `ldapUserLookup()` service uses this capability on the configured
directory. Applications can also override that service in
**app/Config/Services.php**. [Link Existing Users](../commands/index.md#link-existing-users)

To support `shield:ldap-sync`, implement
`Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserEnumerationInterface`. Its
`scanUsers(LDAPConnection $connection, int $pageSize = 100): iterable` method
yields users matching `loginFilter` and `eligibilityFilter` from all effective
user search bases. Use the service account over verified TLS. Yield entries
with a `dn` and an `attributes` map of lowercase attribute names to lists of
strings. Include the configured immutable ID and mapped profile attributes.
Throw `LDAPException` if the scan is incomplete.
The `ldapUserEnumeration()` service uses this capability on the configured
directory and can be overridden separately. The native scan exposes
`LDAPUserScan::close()` for consumers that stop before the end of iteration.
[Synchronize Users](../commands/index.md#synchronize-users)
