# Spark Commands

Run these commands from a trusted shell at the root of your CodeIgniter
application, after installing Shield and running its migrations. Use a
connection ID from `AuthLDAP::$connections`. Both commands use the configured
service account over verified TLS. Run a preview before passing `--apply` to
write changes. [Configuration Reference](../references/configuration.md)

- <a id="link-existing-users"></a>[Link Existing Users](ldap-link.md) with `shield:ldap-link`.
- <a id="synchronize-users"></a>[Synchronize Users](ldap-sync.md) with `shield:ldap-sync`.
    - <a id="synchronize-only-groups"></a>[Synchronize only groups](ldap-sync.md#synchronize-only-groups).
    - <a id="run-every-five-minutes-with-codeigniter-tasks"></a><a id="move-sign-in-updates-to-scheduled-commands"></a>[Schedule group and profile updates](ldap-sync.md#move-sign-in-updates-to-scheduled-commands).
