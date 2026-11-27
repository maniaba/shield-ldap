# Contributing to Shield LDAP

## Getting Started

Use PHP 8.2 or later in the 8.x series, Composer, and Git. Enable SQLite3 for
the default test database.

1. Fork the repository, clone your fork, and create a branch from `develop`.

    ```console
    git clone https://github.com/YOUR-USERNAME/shield-ldap.git
    cd shield-ldap
    git switch -c your-change origin/develop
    ```

2. Install the development dependencies.

    ```console
    composer install
    ```

## Development Workflow

Run `composer test` for the PHPUnit suite. Run `composer test:ldap` for the
native OpenLDAP integration suite when changing the LDAP transport. See the
[testing guide](docs/references/testing.md) for integration prerequisites.

Follow the CodeIgniter coding standard and include the Shield LDAP MIT header in
every PHP file, including `.inc` files. Run `composer cs-fix` to add the header
and apply formatting. The `composer cs` check verifies both locally and in CI.
Run `composer analyze` for static analysis.
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

- Open pull requests against `develop` and keep each one focused on a single change.
- Explain what changed and how you verified it.
- Include regression tests for behavior changes and update the relevant examples.

`develop` is the default branch for development. `main` is the release branch.
GitHub Actions checks both branches.

## Reporting Issues

Include the Shield LDAP, Shield, CodeIgniter, and PHP versions, the type of LDAP
directory, and steps to reproduce the issue. Remove credentials and sensitive
directory data from any configuration or logs you share.

## Publishing the User Guide

The [User Guide workflow](.github/workflows/docs.yml) publishes development
documentation from `develop` and a guide for each stable `vMAJOR.MINOR.PATCH` tag.
Each stable guide has its own URL, such as `/1.2.3/`, and appears in the version
selector. The `/latest/` address serves the development guide until the first
stable release, then serves the latest stable guide. Tag stable releases from
`main`.

In the repository settings, open **Environments** and select **github-pages**.
Under **Deployment branches and tags**, use **Selected branches and tags** and
add an exact branch rule for `develop`.
[GitHub Actions environment settings](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments#creating-an-environment)

If the `publish` job is rejected before its steps start, check the job
annotations for the deployment branch. After correcting the branch rule,
rerun the failed job. To publish the guide from the current `develop` commit,
run the workflow again from that branch.

```console
gh workflow run docs.yml --ref develop
```

## Shield Compatibility Updates

The [Shield Compatibility Updates workflow](.github/workflows/shield-compatibility-updates.yml)
checks Packagist daily for stable Shield releases within the range declared in
**composer.json**. It proposes one release at a time in a pull request. The
compatibility workflow tests it on PHP 8.2 alongside the versions already
listed in **.github/shield-versions.json**.

To enable pull request creation, add the Actions repository secret
`SHIELD_COMPATIBILITY_TOKEN`. Use a fine-grained personal access token limited
to this repository with **Contents** and **Pull requests** read and write
permissions. A repository-scoped token lets the automated PR trigger the same
checks as a contributor's PR. [GitHub workflow triggers](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)

The workflow opens compatibility pull requests against the default branch.
Run it manually from `develop` to check immediately. To list pending
versions locally, run the detection step in dry-run mode.

```console
bash .github/scripts/update-shield-compatibility.sh --dry-run
```
