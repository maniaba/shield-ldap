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
again before saving a link to check that its username still resolves to the
same directory identity. The summary reports linked, skipped, and conflicting
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
| `provisionUsers` | Set to `true` to create Shield accounts for eligible directory entries with no existing link. New users receive Shield’s configured default group. |
| `updateProfile` | Set to `true` to apply mappings to existing linked accounts. Mappings also apply when creating accounts. |
| `profileAttributes` | Maps writable Shield fields to LDAP attributes. Map `username` when provisioning users. |

Synchronization matches existing links by immutable directory identifier and
skips reserved local accounts. If an existing Shield username conflicts with
a new directory account, verify both accounts and create the link first.
[Link Existing Users](#link-existing-users)

The native transport requires the directory to honor the critical LDAP paged
results control. The command requests 100 entries per page and reports
`scan_limit_exceeded` if it needs more than 10,000 pages across the configured
bases. An incomplete scan stops before the command writes any users.

The preview shows the changes planned against the current Shield data. Apply
checks that data again before writing each user, so a later run can report
different results. The command reports `would_create` and `would_update` in a
preview and `created` and `updated` when applying changes. The summary includes
unchanged and skipped accounts and conflicts. Conflicts cause a nonzero exit
status.

Each user's changes are committed in a separate transaction. If a run is
interrupted, rerun the command from the beginning. Existing links identify
users already processed. Deleted or disabled directory accounts keep their
current local status. Review and update their Shield access through your
application’s offboarding process.

The command stages mapped profile values in memory up to PHP’s
`php://temp` threshold of 2 MiB. Larger scans can spill into PHP’s system
temporary directory. Use a restricted temporary directory on the host when
processing sensitive profile attributes.

## Synchronize Only Groups

Use `--groups-only` to reconcile [mapped LDAP groups](../getting_started/configuration.md#map-ldap-groups-to-shield-groups)
for existing Shield users linked to one connection. Run the preview, then use
`--apply` to write the changes.

```console
php spark shield:ldap-sync corporate --groups-only
php spark shield:ldap-sync corporate --groups-only --apply
```

This mode changes only LDAP group grants for eligible linked users. It
preserves manual assignments and grants still backed by another connection.
Provisioning and profile updates belong to the regular synchronization
mode. Group-only synchronization skips reserved local accounts and users
outside the eligible directory search results, including missing directory
accounts. A failed or incomplete directory scan stops the run before any
group changes are written.

The native transport uses the configured service account over verified TLS.
It checks direct membership against each mapped group DN and requests only
the immutable ID from user entries. Apply the Shield LDAP grant table
migration before running this mode. Use an explicit empty `groupMappings`
array to withdraw this connection's grants for the eligible linked users
returned by the scan.

### Run Every Five Minutes with CodeIgniter Tasks

Install CodeIgniter Tasks and publish its configuration. See the
[CodeIgniter Tasks setup guide](https://tasks.codeigniter.com/latest/configuration/)
for the runner and Settings configuration.

```console
composer require codeigniter4/tasks
php spark tasks:publish
```

Add this task to `init()` in **app/Config/Tasks.php**.

```php
$schedule->command('shield:ldap-sync corporate --groups-only --apply')
    ->everyFiveMinutes()
    ->singleInstance();
```

Set up the Tasks runner in cron to dispatch scheduled tasks every minute.
The LDAP task itself runs every five minutes.

```cron
* * * * * cd /srv/myapp && /usr/bin/php spark tasks:run >> writable/logs/tasks-cron.log 2>&1
```

### Run Directly from Cron

Add this entry to the crontab for the application's service account. Adjust
the application and PHP paths.

```cron
*/5 * * * * cd /srv/myapp && /usr/bin/php spark shield:ldap-sync corporate --groups-only --apply >> writable/logs/ldap-group-sync.log 2>&1
```

Use one scheduler per connection. When a run can take longer than the
interval, use a lock such as `flock` on systems that provide it.

## Command Help

Get the supported arguments and options in the terminal.

```console
php spark help shield:ldap-link
php spark help shield:ldap-sync
```
