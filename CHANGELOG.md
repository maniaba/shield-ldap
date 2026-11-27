# Changelog

## v1.0.0

Initial stable release of Shield LDAP for CodeIgniter Shield.

### Added

- Optional LDAPv3 authentication for Active Directory and OpenLDAP using LDAPS
  or StartTLS with certificate verification by default.
- Multiple named directory connections, ordered endpoint failover, multiple
  user search bases, and routing by login domain.
- Account linking by immutable directory ID, including Active Directory
  `objectGUID` and OpenLDAP `entryUUID`. Eligible directory users can be
  provisioned on sign-in and have their mapped profile fields updated.
- Shield session support, including configured login actions such as MFA and
  remember-me for directory accounts. Hybrid sign-in can reserve named local
  accounts for access during directory outages.
- `shield:ldap-link` for previewing and linking existing users, including
  explicit repair of stale links. `shield:ldap-sync` previews and applies
  paged provisioning and profile updates.
- Configurable login and eligibility filters, directory diagnostics, and
  interfaces for application-provided directory transports.

### Requirements

- PHP `^8.2`.
- CodeIgniter 4 `>=4.3.5 <4.5.0` or `^4.5.1`.
- CodeIgniter Shield `^1.4.1`.
- The native directory transport requires PHP's `ldap` extension linked
  against OpenLDAP.
