# Shield LDAP

LDAP and Active Directory sign-in for applications using CodeIgniter Shield.
Shield LDAP verifies directory credentials over LDAPS or StartTLS, links users
by immutable directory ID, and uses Shield's session and login actions.

## Getting Started

Install Shield and set up its database tables first. Shield LDAP requires PHP
8.2 or later in the 8.x series, Shield 1.4.1 or later in the 1.x series, and a
compatible CodeIgniter 4 release. The native transport requires PHP's `ldap`
extension linked against OpenLDAP.

Once the first stable release is available on Packagist, install it with Composer.

```console
composer require maniaba/shield-ldap
```

See the [Shield LDAP User Guide](https://maniaba.github.io/shield-ldap/) for
installation, configuration, and web login. The [guide source](docs/index.md)
is available in this repository.

## Contributing

Run the package tests with `composer test` and the code style and static checks
with `composer ci`. Run `composer test:ldap` for the native OpenLDAP integration
suite. See [Testing](docs/references/testing.md) for requirements and commands.

Preview the User Guide with MkDocs Material.

```console
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Run `mkdocs build --strict` before submitting documentation changes.

## License

Shield LDAP is distributed under the [MIT License](LICENSE).
