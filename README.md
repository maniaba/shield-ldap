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

The [User Guide workflow](.github/workflows/docs.yml) publishes development
documentation from `main` and a guide for each stable `vMAJOR.MINOR.PATCH` tag.
Each stable guide has its own URL, such as `/1.2.3/`, and appears in the version
selector. The guide opens on the latest stable release, or on development
documentation until the first stable release. Run the workflow on `main` to
refresh the site after a publishing failure.

## License

Shield LDAP is distributed under the [MIT License](LICENSE).
