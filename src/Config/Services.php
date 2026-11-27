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

namespace Maniaba\ShieldLDAP\Config;

use CodeIgniter\Config\BaseService;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\NativeLDAPDirectory;

class Services extends BaseService
{
    /**
     * Supplies the directory transport used for LDAP sign-in and diagnostics.
     */
    public static function ldapDirectory(bool $getShared = true): LDAPDirectoryInterface
    {
        if ($getShared) {
            return self::getSharedInstance('ldapDirectory');
        }

        return new NativeLDAPDirectory();
    }
}
