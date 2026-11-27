# Shield LDAP

LDAP and Active Directory sign-in for applications using CodeIgniter Shield.
Shield LDAP verifies directory credentials over LDAPS or StartTLS, links users
by immutable directory ID, and uses Shield's session and login actions.

## Getting Started

Install Shield and set up its database tables first. Shield LDAP requires PHP
8.2 or later in the 8.x series, Shield 1.4.1 or later in the 1.x series, and a
compatible CodeIgniter 4 release. The native transport requires PHP's `ldap`
extension linked against OpenLDAP.

Install a stable release from Packagist with Composer once one is available.

```console
composer require maniaba/shield-ldap
```

To install the development branch currently available on Packagist, specify its
version explicitly.

```console
composer require maniaba/shield-ldap:dev-main
```

See the [Shield LDAP User Guide](https://maniaba.github.io/shield-ldap/latest/) for
installation, configuration, and web login. The [guide source](docs/index.md)
is available in this repository.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, documentation, and pull
request guidelines.

## License

Shield LDAP is maintained by [maniaba](https://github.com/maniaba) and distributed
under the [MIT License](LICENSE). The license file includes the copyright notices
for code adapted from CodeIgniter Shield.
