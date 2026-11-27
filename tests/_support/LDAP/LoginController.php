<?php

declare(strict_types=1);

/**
 * This file is part of Shield LDAP.
 *
 * Copyright (c) 2026 maniaba
 * SPDX-License-Identifier: MIT
 *
 * See the LICENSE file for the full copyright and license information.
 */

namespace Maniaba\ShieldLDAP\Tests\Support\LDAP;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\RedirectResponse;
use Maniaba\ShieldLDAP\Authentication\Authenticators\LDAP;

/**
 * Exercises the application login action described in the LDAP guide.
 */
final class LoginController extends BaseController
{
    /**
     * Signs the user in with LDAP and continues any pending Shield login action.
     */
    public function loginAction(): RedirectResponse
    {
        /** @var LDAP $ldap */
        $ldap = auth('ldap')->getAuthenticator();

        $result = $ldap->remember((bool) $this->request->getPost('remember'))
            ->attempt($this->request->getPost(['username', 'password']));

        if (! $result->isOK()) {
            return redirect()->route('login')->with('error', $result->reason());
        }

        return $ldap->hasAction()
            ? redirect()->route('auth-action-show')->withCookies()
            : redirect()->to(config('Auth')->loginRedirect())->withCookies();
    }
}
