# Spark Commands

Run these commands from a trusted shell at the root of your CodeIgniter
application, after installing Shield and running its migrations. Use a
connection ID from `AuthLDAP::$connections`. Both commands use the configured
service account over verified TLS. Run a preview before passing `--apply` to
write changes. [Configuration Reference](../references/configuration.md)

## Link Existing Users

Use `shield:ldap-link` to associate an existing Shield account with a directory
account by its immutable identifier. The command looks up the Shield username
in the directory attribute mapped by `profileAttributes['username']`. If there
is no username mapping, configure exactly one `loginAttributes` entry.

The lookup applies `loginFilter` and `eligibilityFilter` and requires a unique
match across the configured user search bases. It skips reserved local accounts.
For accounts with different usernames, use a verified link from application
code. [Linking an Existing Shield User](../guides/user_management.md#linking-an-existing-shield-user)

### Preview and Link One User

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

### Link Multiple Users

Omit the username to scan Shield users in batches. Review the proposed matches
and resolve conflicts before applying the missing links with `--all --apply`.

```console
php spark shield:ldap-link corporate
php spark shield:ldap-link corporate --all --apply
```

Bulk mode checks for duplicate local usernames and multiple Shield users
matching the same LDAP object before any writes. It looks up each candidate
again before saving a link and reports linked, skipped, and conflicting
accounts. Conflicts cause a nonzero exit status. An unexpected directory error
stops the run. Each completed link is saved independently, so run another
preview before retrying.

### Repair a Stale Link

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

## Synchronize Users

Use `shield:ldap-sync` to provision eligible directory accounts and update
mapped profiles on linked Shield users. The search uses LDAP paged results
and combines `loginFilter` and `eligibilityFilter` across the configured
`userBaseDn` values, or `baseDn` when `userBaseDn` is omitted.

```console
php spark shield:ldap-sync corporate
php spark shield:ldap-sync corporate --apply
```

| Connection option | Effect |
| --- | --- |
| `provisionUsers` | Set to `true` to create Shield accounts for eligible directory entries with no existing link. |
| `updateProfile` | Set to `true` to apply mappings to existing linked accounts. Mappings also apply when creating accounts. |
| `profileAttributes` | Maps writable Shield fields to LDAP attributes. Map `username` when provisioning users. |

Synchronization matches existing links by immutable directory identifier and
skips reserved local accounts. If an existing Shield username conflicts with
a new directory account, verify both accounts and create the link first.
[Link Existing Users](#link-existing-users)

The command requires a complete directory scan before applying changes. It
reports `would_create` and `would_update` in a preview and `created` and
`updated` when applying changes. The summary includes unchanged and skipped
accounts and conflicts. Conflicts cause a nonzero exit status.

Each user's changes are committed in a separate transaction. If a run is
interrupted, rerun the command from the beginning. Existing links identify
users already processed. Synchronization applies to entries in the scan.

## Command Help

Get the supported arguments and options in the terminal.

```console
php spark help shield:ldap-link
php spark help shield:ldap-sync
```
