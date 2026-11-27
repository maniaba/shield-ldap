<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
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
