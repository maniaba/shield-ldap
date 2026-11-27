# Using the LDAP Authenticator

Use this guide to add an LDAP sign-in form to an application that has completed
[Shield setup](../getting_started/install.md) and
[configured a directory connection](../getting_started/configuration.md).
For existing accounts, follow the [user management guide](../guides/user_management.md)
to link a directory identity before testing sign-in.

## Register the Authenticator

In **app/Config/Auth.php**, add `ldap` to the existing `$authenticators` array.
Keep any aliases already in use. Keep `$defaultAuthenticator` set to
`'session'` so Shield's login view, logout, and session filters use the
session established by LDAP.

```php
public array $authenticators = [
    'tokens'  => \CodeIgniter\Shield\Authentication\Authenticators\AccessTokens::class,
    'session' => \CodeIgniter\Shield\Authentication\Authenticators\Session::class,
    'hmac'    => \CodeIgniter\Shield\Authentication\Authenticators\HmacSha256::class,
    'ldap'    => \Maniaba\ShieldLDAP\Authentication\Authenticators\LDAP::class,
];
```

In the same file, set the `login` entry in the existing `$views` array to
`'\App\Views\auth\ldap_login'` and set the `allowRemembering` entry in
`$sessionConfig` to `false`. The following settings hide the registration and
magic-link links, which the example routes omit.

```php
public bool $allowRegistration = false;
public bool $allowMagicLinkLogins = false;
```

## Create the Login View

Copy **vendor/codeigniter4/shield/src/Views/login.php** to
**app/Views/auth/ldap_login.php**. Replace the email input and its label with
a text input named `username`. This accepts a short account name such as
`alice` or a user principal name such as `alice@example.com`, depending on
your directory configuration. Keep Shield's password input and CSRF field.

```php
<label for="ldapUsername"><?= lang('Auth.username') ?></label>
<input id="ldapUsername" type="text" name="username" autocomplete="username" required>
```

## Create the Login Action

Add the following method to an application controller. This example uses
**app/Controllers/Login.php**. It submits credentials to LDAP and sends users
with a pending Shield login action to the action's form before allowing
access to the application.

```php
<?php

declare(strict_types=1);

namespace App\Controllers;

use CodeIgniter\HTTP\RedirectResponse;
use Maniaba\ShieldLDAP\Authentication\Authenticators\LDAP;

final class Login extends BaseController
{
    public function loginAction(): RedirectResponse
    {
        /** @var LDAP $ldap */
        $ldap   = auth('ldap')->getAuthenticator();
        $result = $ldap->attempt($this->request->getPost(['username', 'password']));

        if (! $result->isOK()) {
            return redirect()->route('login')->with('error', $result->reason());
        }

        return $ldap->hasAction()
            ? redirect()->route('auth-action-show')->withCookies()
            : redirect()->to(config('Auth')->loginRedirect())->withCookies();
    }
}
```

!!! warning

    Keep the failure redirect limited to the error message. CodeIgniter's
    `withInput()` can copy the submitted password into session flash data.
    Set `zend.exception_ignore_args=On` in production to keep credentials
    out of application exception traces.

## Register the Routes

In **app/Config/Routes.php**, replace the `service('auth')->routes($routes)`
call added by Shield setup with the following. If your application already
passes route options, merge the exclusions into that call.

```php
service('auth')->routes($routes, ['except' => ['login', 'register', 'magic-link']]);

$routes->get('login', '\CodeIgniter\Shield\Controllers\LoginController::loginView', ['as' => 'login']);
$routes->post('login', '\App\Controllers\Login::loginAction', ['filter' => 'auth-rates']);
```

In **app/Config/Security.php**, set `$csrfProtection` to `'session'`. In
**app/Config/Filters.php**, enable `csrf` in the global before filters. Keep
the login and authentication action POST routes covered by that filter.
If you apply Shield's `session` filter globally, exclude `login` and
`auth/a/*` so users can reach the form and complete login actions.

Review the route table with `php spark routes`. On versions such as Shield
1.4.1, the default `auth/a/*` routes leave rate limiting to the application.
If those routes have no `auth-rates` filter, add the following entry to
the existing `$filters` array in **app/Config/Filters.php**. Shield registers
the filter alias.

```php
public array $filters = [
    'auth-rates' => ['before' => ['auth/a/show', 'auth/a/handle', 'auth/a/verify']],
];
```

See [Shield's controller filters](https://github.com/codeigniter4/shield/blob/develop/docs/references/controller_filters.md)
for session protection and rate limiting.

## Configure Login Actions

Shield runs the login action configured in the `login` entry of
`Config\Auth::$actions` when it applies to the user. To enable Shield's
built-in email verification, set that entry to
`\CodeIgniter\Shield\Authentication\Actions\Email2FA::class`.

`Email2FA` uses the address in the user's local Shield email identity.
Set up an independently verified address for each user and configure
mail delivery in **app/Config/Email.php** before enabling the action.
For directory users provisioned without an email identity, choose an
action that supports those accounts. Configure an applicable MFA action
for each reserved local account if you use hybrid sign-in.

See [Shield's authentication actions](https://github.com/codeigniter4/shield/blob/develop/docs/references/authentication/auth_actions.md).

## Test Sign-in

1. Make sure `authldap.enabled = true`. Enable provisioning for the test
   connection or link the test directory account to the correct Shield user.
2. Visit `/login` in a fresh browser session. Sign in with a known test account
   and complete any login action, then confirm that a route protected by the
   `session` filter is accessible.
3. Sign out and try an incorrect password. Check that the login form shows a
   generic error and that the protected route still requires sign-in.

See [Troubleshooting](../guides/troubleshooting.md) if sign-in fails.
