# Configuration

Create **app/Config/AuthLDAP.php** by extending the package's `AuthLDAP` class.
Use the `$connections` property for directory settings and standard CodeIgniter
environment overrides for deployment-specific values. LDAP sign-in is disabled by
default. Enable it after configuring your directory and [web login](../quick_start_guide/using_ldap_auth.md).

## Prepare the Directory and PHP Runtime

1. Create a read-only service account that can search within the configured
   user base and read login attributes, immutable IDs, and attributes used by
   filters or profile mappings.
2. Configure trust for the directory's CA in the OpenLDAP client settings used by
   PHP. You can use the following settings in the client configuration file,
   commonly **/etc/ldap/ldap.conf**.

    ```text
    TLS_CACERT /etc/ssl/certs/corporate-ldap-ca.pem
    TLS_REQCERT demand
    TLS_REQSAN demand
    ```

3. Confirm that the certificates presented by all endpoints are valid for the
   configured hostnames and chain to a trusted CA. Mount the CA bundle in the web
   runtime and restart PHP workers after updating their trust settings. A service
   manager can supply the CA path through the `LDAPTLS_CACERT` process environment
   variable. See the [OpenLDAP TLS reference](https://www.openldap.org/doc/admin26/tls.html).

Use `ldaps` for listeners that negotiate TLS as soon as they accept a connection
(normally port 636). Use `starttls` for listeners that accept the LDAP StartTLS
operation before bind (normally port 389). The native transport requires TLS
validation and rejects referrals. Each process uses the same OpenLDAP client
trust policy for its configured directories.

## Active Directory

The following configuration searches two domain controllers in order. Users can
sign in with `sAMAccountName` or `userPrincipalName`. The login filter excludes
disabled accounts and `objectGUID` provides the immutable identity.

```php
<?php

declare(strict_types=1);

namespace Config;

use Maniaba\ShieldLDAP\Config\AuthLDAP as ShieldAuthLDAP;

class AuthLDAP extends ShieldAuthLDAP
{
    public string $defaultConnection = 'corporate';

    public array $connections = [
        'corporate' => [
            'hosts'               => ['dc01.example.com', 'dc02.example.com'],
            'baseDn'              => 'DC=example,DC=com',
            'bindDn'              => 'CN=shield-reader,OU=Service Accounts,DC=example,DC=com',
            'bindPassword'        => '',
            'encryption'          => 'ldaps',
            'port'                => 636,
            'userBaseDn'          => 'OU=Users,DC=example,DC=com',
            'loginFilter'         => '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            'loginAttributes'     => ['sAMAccountName', 'userPrincipalName'],
            'externalIdAttribute' => 'objectGUID',
            'profileAttributes'   => ['username' => 'sAMAccountName'],
            'provisionUsers'      => true,
        ],
    ];
}
```

Supply the password and enable LDAP through **.env**.

```ini
authldap.enabled = true
authldap.connections.corporate.bindPassword = 'replace-with-service-account-password'
```

## OpenLDAP

For an OpenLDAP server with StartTLS, use the following **app/Config/AuthLDAP.php**.
This example looks up users by `uid` and links their Shield accounts by
`entryUUID`. Allow the service account to read that operational attribute.

```php
<?php

declare(strict_types=1);

namespace Config;

use Maniaba\ShieldLDAP\Config\AuthLDAP as ShieldAuthLDAP;

class AuthLDAP extends ShieldAuthLDAP
{
    public string $defaultConnection = 'openldap';

    public array $connections = [
        'openldap' => [
            'hosts'               => ['ldap.example.org'],
            'baseDn'              => 'dc=example,dc=org',
            'bindDn'              => 'cn=shield-reader,ou=services,dc=example,dc=org',
            'bindPassword'        => '',
            'encryption'          => 'starttls',
            'port'                => 389,
            'userBaseDn'          => 'ou=people,dc=example,dc=org',
            'loginFilter'         => '(objectClass=inetOrgPerson)',
            'loginAttributes'     => ['uid'],
            'externalIdAttribute' => 'entryUUID',
            'profileAttributes'   => ['username' => 'uid'],
            'provisionUsers'      => true,
        ],
    ];
}
```

Supply the password under the connection ID `openldap`.

```ini
authldap.enabled = true
authldap.connections.openldap.bindPassword = 'replace-with-service-account-password'
```

For another LDAPv3 server, choose the login attributes, filters, and immutable
identifier according to its schema. The identifier must be unique, readable, and
stable across account renames and moves. See [Login Eligibility](../guides/login_eligibility.md)
and the [configuration reference](../references/configuration.md).

## Synchronize the Shield Email Identity

To use LDAP `mail` as the Shield email address, add this setting to your
connection in **app/Config/AuthLDAP.php**.

```php
'emailIdentityAttribute' => 'mail',
```

The service account must be able to read the attribute. Restrict directory write
access to trusted administrators because Shield can send login codes to this
address. The selected connection requires exactly one valid email address on
each sign-in. Set `$allowMagicLinkLogins` to `false` in **app/Config/Auth.php**
and keep the effective setting disabled while these identities exist. Disable
custom email-only sign-in and local password recovery for LDAP-managed accounts.

See [Email Identity Ownership](../guides/user_management.md#email-identity-ownership)
for details on provisioning and updates.

## Environment Overrides

Keep **.env** outside version control. When a deployment environment requires
underscores in variable names, use keys such as
`authldap_connections_corporate_bindPassword`. The normal CodeIgniter config
initialization applies these overrides. Declare the connection ID and each
option before setting its environment override. The same rule applies to list
entries, such as `authldap.connections.corporate.hosts.0`.

!!! warning
    Direct reads of `$connections`, configuration exports, and CodeIgniter's
    configuration cache can expose the bind password. Use an [application-owned
    connection provider](../references/diagnostics.md) if the password must stay
    outside the configuration cache.

## Multiple Directories

List replicas of one directory in a single connection's `hosts`, in preference
order. Give independent directories separate connection IDs. If users enter UPNs
from different directories, map each lower-case suffix to a connection ID.

```php
public array $loginDomains = [
    'example.com'          => 'corporate',
    'research.example.org' => 'research',
];
```

Declare `corporate` and `research` under `$connections` before using this example.
The default connection handles unqualified identifiers and unmapped suffixes.
The selected connection looks up the entire submitted identifier, including any
suffix. Keep connection IDs stable because they identify the scope of the link
between a directory account and a Shield user.

Continue to [Using LDAP Authentication](../quick_start_guide/using_ldap_auth.md)
to register the authenticator and connect it to your application's login form.
