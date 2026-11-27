# Testing

Run the following commands from a Shield LDAP checkout with Composer and the
PHP extensions required by CodeIgniter. Enable SQLite3 for the default test
database.

```console
composer install
composer test
```

`composer test` runs the `main` PHPUnit suite. It covers configuration,
filters, authentication, account provisioning, and Shield's web session
lifecycle using directory doubles. It runs without a live LDAP server.
The main suite uses an in-memory SQLite database. The
[PHPUnit workflow](https://github.com/maniaba/shield-ldap/actions/workflows/phpunit.yml)
runs the suite with code coverage on PHP 8.2 through 8.5. The
[compatibility workflow](https://github.com/maniaba/shield-ldap/actions/workflows/compatibility.yml)
checks selected Shield releases.

## Code Checks

Use the same CodeIgniter coding standard and analysis tools used by Shield.

```console
composer cs
composer analyze
composer inspect
```

`composer cs` checks formatting with PHP-CS-Fixer. Use `composer cs-fix` to
apply formatting. `composer analyze` runs PHPStan, Psalm, and Rector in
check mode. `composer inspect` runs StructArmed. To run these checks with the
main test suite, use `composer ci`.

## OpenLDAP Integration Tests

Install Docker and OpenSSL and enable PHP's LDAP extension linked against
OpenLDAP in the CLI runtime. Run the same integration suite as the
[OpenLDAP workflow](https://github.com/maniaba/shield-ldap/actions/workflows/phpunit-ldap.yml).

```console
composer test:ldap
```

The runner builds the fixture under **tests/_support/LDAP/** and starts it
with temporary certificates on loopback ports. It waits for service-account
binds over LDAPS and StartTLS, runs the `ldap-integration` PHPUnit suite,
and stops the container when the run finishes. A failed smoke check, empty
suite, or skipped test fails the run.

Add live OpenLDAP tests under **tests/Authentication/LDAP/Integration/**.
PHPUnit discovers the tests there as part of the integration suite.

For Active Directory changes, also exercise the setup against a disposable
AD DS or Samba AD test domain. Confirm GUID handling after an account rename,
disabled-account filters, transitive membership, and the configured TLS
certificate policy in the directory you deploy against. See the
[configuration reference](configuration.md#login-and-eligibility-filters).
