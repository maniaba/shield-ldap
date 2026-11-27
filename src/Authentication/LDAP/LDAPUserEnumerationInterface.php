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

namespace Maniaba\ShieldLDAP\Authentication\LDAP;

use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Optional paged discovery of directory users for synchronization.
 */
interface LDAPUserEnumerationInterface extends LDAPDirectoryInterface
{
    /**
     * Enumerate eligible users in the configured search bases over verified TLS.
     *
     * Returned attribute names are lowercase. The configured ID and profile
     * attributes are included when present.
     *
     * @return iterable<int, array{dn: string, attributes: array<string, list<string>>}>
     *
     * @throws LDAPException If a search fails or its results are incomplete.
     */
    public function scanUsers(LDAPConnection $connection, int $pageSize = 100): iterable;
}
