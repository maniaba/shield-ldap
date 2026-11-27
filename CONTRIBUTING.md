# Contributing to Shield LDAP

## Getting Started

Use PHP 8.2 or later in the 8.x series, Composer, and Git. Enable SQLite3 for
the default test database.

1. Fork the repository, clone your fork, and create a branch from `main`.

    ```console
    git clone https://github.com/YOUR-USERNAME/shield-ldap.git
    cd shield-ldap
    git switch -c your-change
    ```

2. Install the development dependencies.

    ```console
    composer install
    ```

## Development Workflow

Run `composer test` for the PHPUnit suite. Run `composer test:ldap` for the
native OpenLDAP integration suite when changing the LDAP transport. See the
[testing guide](docs/references/testing.md) for integration prerequisites.

Follow the CodeIgniter coding standard. Run `composer cs` to check formatting,
or `composer cs-fix` to apply it. Run `composer analyze` for static analysis.
`composer ci` runs the style, analysis, inspection, and PHPUnit checks together.

## Documentation

Update the pages under **docs/** when changes affect installation, configuration,
or a public API. Preview the User Guide with MkDocs Material.

```console
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Run `mkdocs build --strict` before submitting documentation changes.

## Pull Requests

- Open pull requests against `main` and keep each one focused on a single change.
- Explain what changed and how you verified it.
- Include regression tests for behavior changes and update the relevant examples.

## Reporting Issues

Include the Shield LDAP, Shield, CodeIgniter, and PHP versions, the type of LDAP
directory, and steps to reproduce the issue. Remove credentials and sensitive
directory data from any configuration or logs you share.

## Publishing the User Guide

The [User Guide workflow](.github/workflows/docs.yml) publishes development
documentation from `main` and a guide for each stable `vMAJOR.MINOR.PATCH` tag.
Each stable guide has its own URL, such as `/1.2.3/`, and appears in the version
selector. The guide opens on the latest stable release, or on development
documentation until the first stable release. Run the workflow on `main` to
refresh the site after a publishing failure.
