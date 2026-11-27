# Shield LDAP User Guide

Shield LDAP adds LDAPv3 and Active Directory sign-in to applications using
CodeIgniter Shield. The authenticator verifies directory credentials over LDAPS
or StartTLS and completes sign-in through Shield's session and login actions.

Run `composer show maniaba/shield-ldap` in your application to find its installed
version. Use the version selector in the header to find the guide for that release.
Select **Development** if you installed `dev-main`.

## Getting Started

1. [Install the package](getting_started/install.md) in an application with Shield configured.
2. [Configure the directory](getting_started/configuration.md) using the Active Directory or OpenLDAP example.
3. [Enable LDAP web login](quick_start_guide/using_ldap_auth.md) in your application's routes and sign-in form.

## Guides and References

- [Login eligibility](guides/login_eligibility.md) covers login attributes, filters, and group-based sign-in restrictions.
- [User management](guides/user_management.md) covers provisioning, account linking, hybrid login, and existing sessions.
- [Spark commands](commands/index.md) covers linking existing users and synchronizing directory accounts.
- [Troubleshooting](guides/troubleshooting.md) covers TLS, directory binds, and rejected logins.
- [Configuration reference](references/configuration.md) lists settings, defaults, and limits.
- [Directory diagnostics](references/diagnostics.md) covers programmatic connection and search checks.
- [Testing](references/testing.md) explains how to run the package tests and the OpenLDAP integration suite.

For groups, permissions, and other authentication methods, see the [Shield User Guide](https://shield.codeigniter.com/).
