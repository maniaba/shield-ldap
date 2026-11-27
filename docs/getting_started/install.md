# Installation

These instructions assume you have a CodeIgniter 4 application, a configured
**.env** file, and a database that the Spark CLI can access.

## Requirements

| Dependency | Supported versions |
| --- | --- |
| PHP | `^8.2` (PHP 8.2 or later in the 8.x series) |
| CodeIgniter 4 | `>=4.3.5 <4.5.0` or `^4.5.1` |
| CodeIgniter Shield | `^1.4.1` (Shield 1.4.1 or later in the 1.x series) |
| Composer | Required to install the package and its dependencies |
| PHP LDAP extension | A build linked against OpenLDAP is required for the native directory service |

Check the LDAP extension with `php --ri ldap`. If your application runs through
PHP-FPM or another web runtime, check that runtime's extension configuration as
well. An application that supplies its own [directory transport](../references/diagnostics.md)
can use the dependencies required by that transport.

## Set Up Shield

If Shield is new to your application, follow the [Shield installation guide](https://github.com/codeigniter4/shield/blob/v1.5.0/docs/getting_started/install.md)
to install it, publish its configuration, and set up its database tables.
Shield LDAP uses the existing Shield user, identity, and login tables.

## Composer Installation

### Stable Release

Install a stable release from [Packagist](https://packagist.org/packages/maniaba/shield-ldap)
once one is available. Run Composer from your application's root directory.

```console
composer require maniaba/shield-ldap
```

To keep the application on the Shield 1.4 release series, use an explicit Shield
constraint when installing the package.

```console
composer require 'codeigniter4/shield:~1.4.1' maniaba/shield-ldap
```

### Development Branch

To install the development branch from Packagist, require its version explicitly.

```console
composer require maniaba/shield-ldap:dev-develop
```

Select **Development** in the guide's version selector when using this branch.

Composer resolves the package against the version constraints in your application.
If a Shield constraint blocks installation, run `composer why codeigniter4/shield`
to see which packages impose it.

Continue to [Configuration](configuration.md) to set up directory access.
