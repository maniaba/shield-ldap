# Link Existing Users

Use `shield:ldap-link` to associate an existing Shield account with a directory
account by its immutable identifier. The command looks up the Shield username
in the directory attribute mapped by `profileAttributes['username']`. If there
is no username mapping, configure exactly one `loginAttributes` entry.

The lookup applies `loginFilter` and `eligibilityFilter` and requires a unique
match across the configured user search bases. It skips reserved local accounts.
For accounts with different usernames, use a verified link from application
code. [Linking an Existing Shield User](../guides/user_management.md#linking-an-existing-shield-user)

## Preview and Link One User

Preview the directory match for a specific Shield username. Check the matching
directory identifier and confirm that both accounts belong to the same person
before applying the link.

```console
php spark shield:ldap-link corporate alex.rivera
php spark shield:ldap-link corporate alex.rivera --apply
```

Applying a link looks up the directory account again and stores the LDAP
identity keyed by the connection and the immutable identifier, such as the
normalized AD `objectGUID` or an OpenLDAP `entryUUID`.

## Link Multiple Users

Omit the username to scan Shield users in batches. Review the proposed matches
and resolve conflicts before applying the missing links with `--all --apply`.

```console
php spark shield:ldap-link corporate
php spark shield:ldap-link corporate --all --apply
```

Bulk mode checks for duplicate local usernames and multiple Shield users
matching the same LDAP object before any writes. It looks up each candidate
again before saving a link to check that its username still resolves to the
same directory identity. The summary reports linked, skipped, and conflicting
accounts. Conflicts cause a nonzero exit status. An unexpected directory error
stops the run. Each completed link is saved independently, so run another
preview before retrying.

## Repair a Stale Link

Recreating a directory account can give the same username a new immutable
identifier. Preview the Shield user to see the `stale_link` status and the new
directory identifier. Verify that the new account belongs to the Shield user,
then pass the identifier from the preview to `--replace`.

```console
php spark shield:ldap-link corporate alex.rivera
php spark shield:ldap-link corporate alex.rivera --apply --replace 00112233-4455-6677-8899-aabbccddeeff
```

Repair requires exactly one existing link for the named user on the selected
connection. The command repeats the directory lookup and updates the link if
the identifier matches `--replace` and is available. A changed identifier or
an identity conflict blocks the repair.

## Command Help

Get the supported arguments and options in the terminal.

```console
php spark help shield:ldap-link
```
