# Shield LDAP

LDAP and Active Directory sign-in for applications using CodeIgniter Shield.
The package verifies credentials over LDAPS or StartTLS and uses Shield's
session and login actions. It supports multiple directories, explicit links
to existing Shield users, and optional provisioning by immutable directory ID.

## Requirements

- PHP 8.2 or later in the 8.x series
- CodeIgniter 4.3.5 or later in the 4.x series, excluding 4.5.0
- CodeIgniter Shield 1.4.1 or later in the 1.x series
- PHP's `ldap` extension linked against OpenLDAP for the built-in transport

## Installation

Set up Shield in your application first. [Shield installation guide](https://github.com/codeigniter4/shield/blob/develop/docs/getting_started/install.md)

Install this package from its GitHub repository.

```console
composer config repositories.shield-ldap vcs https://github.com/maniaba/shield-ldap
composer require maniaba/shield-ldap:dev-main
```

The package allows Shield versions from `^1.4.1`. To stay on the 1.4 series,
pin Shield in your application.

```console
composer require 'codeigniter4/shield:~1.4.1' 'maniaba/shield-ldap:dev-main'
```

Follow the [configuration guide](docs/ldap.md) to configure the LDAP connection,
register the `ldap` authenticator, and connect it to your application's login
form and routes.

## Development

Run the LDAP unit and feature test suite with `composer test` and the code
style and static checks with `composer ci`. Run `composer test:ldap` to test
LDAPS and StartTLS against the Docker OpenLDAP fixture.

## License

Shield LDAP is distributed under the [MIT License](LICENSE).
